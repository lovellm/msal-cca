import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";

interface TokenHeader {
  kid: string;
}
interface TokenPayload {
  tid: string;
  iss: string;
  aud: string;
  iat: number;
  exp: number;
}
interface DecodedToken {
  header: TokenHeader;
  payload: TokenPayload;
}

export class TokenValidator {
  private tenantId: string;
  private authority: string;

  constructor(tenantId: string, authority: string) {
    this.tenantId = tenantId;
    this.authority = authority;
  }

  /** Verifies a given token's signature using jwks-rsa
   * @param {string} authToken
   * @returns {Promise}
   */
  async verifyTokenSignature(authToken: string): Promise<TokenPayload | false> {
    if (!authToken) {
      console.error("No Token given to verifyTokenSignature");
      return false;
    }

    // we will first decode to get kid parameter in header
    let decodedToken;
    try {
      decodedToken = jwt.decode(authToken, { complete: true }) as unknown as DecodedToken;
    } catch (error) {
      console.error("Failed to Decode Auth Token", error);
      return false;
    }

    // obtains signing keys from discovery endpoint
    let keys;
    try {
      keys = await this.getSigningKeys(decodedToken.header);
    } catch (error) {
      console.error("Failed to get Signing Keys for Auth Token", error);
      return false;
    }

    // verify the signature at header section using keys
    let verifiedToken: TokenPayload;
    try {
      verifiedToken = jwt.verify(authToken, keys) as unknown as TokenPayload;
      return verifiedToken;
    } catch (error) {
      console.error("Auth Token Not Verified", error);
      return false;
    }
  }

  /** Fetches signing keys of an access token
   * from the authority discovery endpoint
   * @param {Object} header: token header
   * @param {string} authority: aad authority url
   * @returns {Promise}
   */
  private async getSigningKeys(header: TokenHeader): Promise<string> {
    const jwksUri = `${this.authority}/discovery/v2.0/keys`;
    const client = jwksClient({
      jwksUri: jwksUri,
    });

    return (await client.getSigningKey(header.kid)).getPublicKey();
  }

  /** Verifies the access token for signature
   * @param {string} idToken: raw Id token
   * @returns {Promise}
   */
  async validateIdToken(idToken: string): Promise<boolean> {
    try {
      const verifiedToken = await this.verifyTokenSignature(idToken);

      if (verifiedToken) {
        return this.validateIdTokenClaims(verifiedToken);
      } else {
        return false;
      }
    } catch (error) {
      console.error(error);
      return false;
    }
  }

  /** Validates the id token for a set of claims
   * @param {TokenPayload} tokenPayload: decoded id token claims
   * @returns {boolean}
   */
  validateIdTokenClaims(tokenPayload: TokenPayload, aud?: string | false): boolean {
    const now = Math.round(new Date().getTime() / 1000); // in UNIX format
    const checkIssuer = tokenPayload.iss.includes(this.tenantId) ? true : false;
    const checkTimestamp = tokenPayload.iat <= now && tokenPayload.exp >= now ? true : false;

    // default aud check to true in case it should be skipped
    let audCheck = true;
    // explicit false to skip the check altogether
    if (aud !== false) {
      // this check depends upon the type of token and the scopes requested in the token.
      // if requesting an ms graph api scope (such as User.Read), the token will not match the authentication client.
      // if an id token, it should match the client id used in the authentication request.
      // if an access token, aud could be the id of a different app requested in the scope.
      audCheck = tokenPayload.aud === (aud || process.env.CLIENT_ID);
    }

    return checkIssuer && checkTimestamp && audCheck;
  }
}
