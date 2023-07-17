import { Express } from "express";
import expressSession from "express-session";
import checkAuth from "./checkAuth";
import auth from "./auth";
import storeRedis from "./storeRedis";
import redisCacheClient from "../msal/redisCacheClient";
import localCacheClient from "../msal/localCacheClient";
import { AuthProvider } from "../msal/AuthProvider";
import { RedisStore } from "connect-redis";
import { ICacheClient } from "@azure/msal-node";

const cookieAge = 1000 * 60 * 60 * 4;

/** Set up session management and authentication for the Express app.
 * @param {Object} app Instance of Express App
 */
export default async function setupSession(app: Express) {
  /* If the redis keys do not exist in process.env, storeRedis will be undefined
   * and expressSession will default to the memory store
   */
  let sessionStore: RedisStore | undefined = undefined;
  let cacheClient: ICacheClient | undefined = undefined;
  if (process.env.REDIS_HOST) {
    const redisStore = await storeRedis();
    if (redisStore) {
      sessionStore = redisStore.redisStore;
      // eslint-disable-next-line no-console
      console.log("Using Redis Store");
      cacheClient = redisCacheClient(redisStore.redisClient);
    }
  }

  if (!sessionStore) {
    // eslint-disable-next-line no-console
    console.log("Using Default Memory Store");
    cacheClient = localCacheClient();
  }

  const sessionMiddleware = expressSession({
    store: sessionStore,
    secret: process.env.SESSION_SECRET,
    name: process.env.APP_NAME,
    resave: false,
    rolling: true,
    saveUninitialized: false,
    cookie: {
      maxAge: cookieAge,
    },
  });

  app.use(sessionMiddleware);

  const authProvider = new AuthProvider(cacheClient);

  // Check Authentication on Each Request
  app.use(checkAuth);

  // Register the auth routes
  auth(app, authProvider);

  return authProvider;
}
