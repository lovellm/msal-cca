import { Request, Response, NextFunction } from "express";
import { InteractionRequiredAuthError, LogLevel, ResponseMode } from "@azure/msal-common";
import {
  IConfidentialClientApplication,
  ICacheClient,
  ConfidentialClientApplication,
  CryptoProvider,
  AuthorizationUrlRequest,
  AuthorizationCodeRequest,
  Configuration,
  SilentFlowRequest,
} from "@azure/msal-node";
import partitionManager from "./partitionManager";
import { TokenValidator } from "./TokenValidator";
import { CryptoCachePlugin } from "./CryptoCachePlugin";
import { createEncryptedCookie, findDecryptedCookie, generateNonce } from "../auth/cryptoHelpers";

const baseScopes = ["openid", "email", "profile", "offline_access"];
const signInState = "sign_in.";

const authorityMetadata = (tenantId: string) => {
  // From https://login.microsoftonline.com/${tenandId}/v2.0/.well-known/openid-configuration
  const openIdConfig = {
    token_endpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
    token_endpoint_auth_methods_supported: [
      "client_secret_post",
      "private_key_jwt",
      "client_secret_basic",
    ],
    jwks_uri: `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`,
    response_modes_supported: ["query", "fragment", "form_post"],
    subject_types_supported: ["pairwise"],
    id_token_signing_alg_values_supported: ["RS256"],
    response_types_supported: ["code", "id_token", "code id_token", "id_token token"],
    scopes_supported: ["openid", "profile", "email", "offline_access"],
    issuer: `https://login.microsoftonline.com/${tenantId}/v2.0`,
    request_uri_parameter_supported: false,
    userinfo_endpoint: "https://graph.microsoft.com/oidc/userinfo",
    authorization_endpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`,
    device_authorization_endpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/devicecode`,
    http_logout_supported: true,
    frontchannel_logout_supported: true,
    end_session_endpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/logout`,
    claims_supported: [
      "sub",
      "iss",
      "cloud_instance_name",
      "cloud_instance_host_name",
      "cloud_graph_host_name",
      "msgraph_host",
      "aud",
      "exp",
      "iat",
      "auth_time",
      "acr",
      "nonce",
      "preferred_username",
      "name",
      "tid",
      "ver",
      "at_hash",
      "c_hash",
      "email",
    ],
    kerberos_endpoint: `https://login.microsoftonline.com/${tenantId}/kerberos`,
    tenant_region_scope: "NA",
    cloud_instance_name: "microsoftonline.com",
    cloud_graph_host_name: "graph.windows.net",
    msgraph_host: "graph.microsoft.com",
    rbac_url: "https://pas.windows.net",
  };
  return JSON.stringify(openIdConfig);
};

const cloudDiscoveryMetadata = (tenantId: string) => {
  // From https://login.microsoftonline.com/common/discovery/instance?api-version=1.1&authorization_endpoint=https://login.microsoftonline.com/${tenandId}/oauth2/v2.0/authorize
  const cloudDiscoveryResponse = {
    tenant_discovery_endpoint: `https://login.microsoftonline.com/${tenantId}/v2.0/.well-known/openid-configuration`,
    "api-version": "1.1",
    metadata: [
      {
        preferred_network: "login.microsoftonline.com",
        preferred_cache: "login.windows.net",
        aliases: [
          "login.microsoftonline.com",
          "login.windows.net",
          "login.microsoft.com",
          "sts.windows.net",
        ],
      },
      {
        preferred_network: "login.partner.microsoftonline.cn",
        preferred_cache: "login.partner.microsoftonline.cn",
        aliases: ["login.partner.microsoftonline.cn", "login.chinacloudapi.cn"],
      },
      {
        preferred_network: "login.microsoftonline.de",
        preferred_cache: "login.microsoftonline.de",
        aliases: ["login.microsoftonline.de"],
      },
      {
        preferred_network: "login.microsoftonline.us",
        preferred_cache: "login.microsoftonline.us",
        aliases: ["login.microsoftonline.us", "login.usgovcloudapi.net"],
      },
      {
        preferred_network: "login-us.microsoftonline.com",
        preferred_cache: "login-us.microsoftonline.com",
        aliases: ["login-us.microsoftonline.com"],
      },
    ],
  };
  return JSON.stringify(cloudDiscoveryResponse);
};

export class AuthProvider {
  private stateCookiePrefix: string;
  cacheClient?: ICacheClient;
  private cryptoProvider: CryptoProvider;
  private tokenValidator: TokenValidator;
  oauthScopes: string[];
  scopes: string[];
  tenantId: string;
  authority: string;

  constructor(cacheClient?: ICacheClient) {
    this.stateCookiePrefix = "authstate";
    this.cacheClient = cacheClient;
    this.tenantId = process.env.TENANT_ID;
    this.authority = "https://login.microsoftonline.com/" + this.tenantId;
    this.oauthScopes = (process.env.APP_SCOPES || "").split(" ");
    this.scopes = [...baseScopes, ...this.oauthScopes];
    this.cryptoProvider = new CryptoProvider();
    this.tokenValidator = new TokenValidator(this.tenantId, this.authority);
  }

  getMsalConfig(accountId?: string): Configuration {
    let cachePlugin = undefined;
    if (this.cacheClient) {
      cachePlugin = new CryptoCachePlugin(this.cacheClient, partitionManager(accountId));
    }
    const config: Configuration = {
      auth: {
        clientId: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        authority: this.authority,
        authorityMetadata: authorityMetadata(this.tenantId),
        cloudDiscoveryMetadata: cloudDiscoveryMetadata(this.tenantId),
      },
      cache: {
        cachePlugin,
      },
      system: {
        loggerOptions: {
          loggerCallback(_, message) {
            // eslint-disable-next-line no-console
            console.log(message);
          },
          piiLoggingEnabled: false,
          logLevel: LogLevel.Warning,
        },
      },
    };
    return config;
  }

  initializeMsalClient(req: Request): IConfidentialClientApplication {
    const accountId = req.session?.account?.homeAccountId;
    return new ConfidentialClientApplication(this.getMsalConfig(accountId));
  }
  initializeMsalClientFromId(id: string): IConfidentialClientApplication {
    return new ConfidentialClientApplication(this.getMsalConfig(id));
  }

  /** Initiate sign in flow
   * @param {Request} req: express request object
   * @param {Response} res: express response object
   */
  signIn = async (req: Request, res: Response): Promise<void> => {
    // initiate the first leg of auth code grant to get token
    this.getAuthCode(req, res);
  };

  /** Middleware that handles redirect
   * @param {Request} req: express request object
   * @param {Response} res: express response object
   * @param {NextFunction} next: express next
   */
  handleRedirect = async (req: Request, res: Response, next: NextFunction): Promise<unknown> => {
    // Extract the nonce and client info from the auth response
    let nonce: string | undefined = undefined;
    const clientInfoParam = req.body.client_info as string;
    let clientInfo;
    try {
      const stateParam = decodeURIComponent(req.body.state as string);
      if (stateParam && stateParam.startsWith(signInState)) {
        const splitStateParam = stateParam.split(".");
        if (splitStateParam.length > 1) {
          nonce = splitStateParam.at(-1);
        }
      }
      if (!nonce) {
        throw new Error("no nonce in auth code response");
      }
      // Form encoding converted + to space, so need to convert back to +
      nonce = nonce.replaceAll(" ", "+");

      clientInfo = JSON.parse(this.cryptoProvider.base64Decode(clientInfoParam));
      if (!clientInfo) {
        throw new Error("no client info in auth code response");
      }
    } catch (stateParseError) {
      return res.status(401).send("unable to parse state, " + (stateParseError as Error)?.message);
    }

    // Use the nonce to find the cookie with encrypted PKCE values
    const stateCookie = findDecryptedCookie(req, this.stateCookiePrefix, "nonce", nonce);
    let pkceVerifier: string | undefined = undefined;
    if (stateCookie) {
      try {
        const stateValue = JSON.parse(stateCookie.value);
        if (stateValue.pkceCodes && stateValue.pkceCodes.verifier) {
          pkceVerifier = stateValue.pkceCodes.verifier;
        }
      } catch (e) {
        console.error("unable to find or parse state cookie");
      }
      res.clearCookie(stateCookie.name);
    }
    if (!pkceVerifier) {
      return res.status(401).send("no login cookie corresponding to the login request");
    }

    // make an msal client using the client info (user/tenant guid)
    const msalClient = this.initializeMsalClientFromId(clientInfo.uid + "." + clientInfo.utid);

    // token request with auth code and pkce verifier
    const tokenRequest = {
      authority: this.authority,
      code: req.body.code as string,
      redirectUri: process.env.REDIRECT_URL,
      scopes: this.oauthScopes,
      codeVerifier: pkceVerifier,
    } as AuthorizationCodeRequest;

    // exchange auth code for tokens and initialize session
    try {
      const tokenResponse = await msalClient.acquireTokenByCode(tokenRequest);
      const isIdTokenValid = await this.tokenValidator.validateIdToken(tokenResponse.idToken);

      if (isIdTokenValid && tokenResponse.account) {
        // assign session variables
        req.session.account = tokenResponse.account;
        req.session.isAuthenticated = true;

        return next();
      } else {
        console.error("Invalid Token After Redirect");
        return res.status(401).send("Unable to Validate Token");
      }
    } catch (error) {
      console.error(error);
      return res.status(500).send("Error Acquiring Login Token");
    }
  };

  /** Middleware that gets tokens
   * @param {Request} req: express request object
   * @param {Response} res: express response object
   * @param {boolean} forceRefresh force a token refresh instead of attempting to use current token
   */
  getToken = async (req: Request, res: Response, forceRefresh?: boolean): Promise<unknown> => {
    const sessionAccount = req?.session?.account;
    if (!sessionAccount) {
      return res.status(403).send("No Account in session");
    }

    try {
      const msalClient = this.initializeMsalClient(req);
      const silentRequest: SilentFlowRequest = {
        account: sessionAccount,
        scopes: this.scopes,
        forceRefresh: forceRefresh === true ? true : undefined,
      };

      // acquireTokenSilent does not populate cache from persistence layer on its own.
      // Calling getAllAccounts will populate from persistence layer.
      const cache = msalClient.getTokenCache();
      await cache.getAllAccounts();

      // acquire token silently to be used in resource call
      const tokenResponse = await msalClient.acquireTokenSilent(silentRequest);

      if (!tokenResponse) {
        return res.status(401).send("Unable to Acquire Token");
      }

      if (tokenResponse.accessToken.length === 0) {
        console.error("acquireTokenSilent Returned empty accessToken");
        throw new InteractionRequiredAuthError();
      }

      return res.status(200).json({
        value: tokenResponse.accessToken,
      });
    } catch (error) {
      // in case there are no cached tokens, initiate an interactive call
      if (error instanceof InteractionRequiredAuthError) {
        return res.status(401).send(error.message);
      } else {
        console.error(error);
        return res.status(500).send("Unexpected Error Getting Token");
      }
    }
  };

  /** This method is used to generate an auth code request
   * @param {Request} req: express request object
   * @param {Response} res: express response object
   */
  private getAuthCode = async (req: Request, res: Response): Promise<void> => {
    const nonce = generateNonce();
    const pkceCodes = await this.cryptoProvider.generatePkceCodes();
    const state = signInState + nonce;

    const authCodeRequest = {
      authority: this.authority,
      responseMode: ResponseMode.FORM_POST,
      redirectUri: process.env.REDIRECT_URL,
      scopes: this.scopes,
      state: state,
      nonce: nonce,
      codeChallenge: pkceCodes.challenge,
      codeChallengeMethod: "S256",
    } as AuthorizationUrlRequest;

    // save nonce and pkce values in to an encrypted cookie for later validation
    const authCookieContent = JSON.stringify({
      nonce: nonce,
      pkceCodes: pkceCodes,
    });

    // request an authorization code to exchange for tokens
    try {
      const authCookie = createEncryptedCookie(this.stateCookiePrefix, authCookieContent);
      const msalClient = this.initializeMsalClient(req);
      const responseUrl = await msalClient.getAuthCodeUrl(authCodeRequest);
      res.cookie(authCookie.name, authCookie.value, {
        expires: new Date(new Date().valueOf() + 1000 * 60 * 5),
      });
      return res.redirect(responseUrl);
    } catch (error) {
      console.error(error);
      return res.redirect("/auth/failed");
    }
  };
}
