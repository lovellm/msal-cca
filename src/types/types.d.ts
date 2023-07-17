import { AccountInfo } from "@azure/msal-common"; // dependency of msal-node
export {};

declare module "express-session" {
  interface SessionData {
    account?: AccountInfo;
    isAuthenticated?: boolean;
  }
}

declare global {
  declare namespace NodeJS {
    interface ProcessEnv {
      APP_NAME: string;
      SESSION_SECRET: string;
      REDIS_HOST?: string;
      REDIS_USER?: string;
      REDIS_KEY?: string;
      REDIS_PORT?: string;
      TENANT_ID: string;
      CLIENT_ID: string;
      CLIENT_SECRET: string;
      APP_SCOPES: string;
      REDIRECT_URL: string;
      AUTH_COOKIE_KEY: string;
    }
  }
}
