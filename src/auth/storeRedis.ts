import expressSession from "express-session";
import { createClient, RedisClientType } from "redis";
import connectRedis from "connect-redis";
const RedisStore = connectRedis(expressSession);

export default async function storeRedis() {
  try {
    const redisPrefix = (process.env.APP_NAME || "") + "s";
    const redisHost = process.env.REDIS_HOST;
    const redisUser = process.env.REDIS_USER;
    const redisKey = process.env.REDIS_KEY;
    let redisPort = process.env.REDIS_PORT ? Number.parseInt(process.env.REDIS_PORT) : undefined;
    if (Number.isNaN(redisPort)) {
      redisPort = undefined;
    }

    if (!redisHost || !redisKey) {
      return undefined;
    } else {
      const redisClient = createClient({
        socket: {
          host: redisHost,
          port: redisPort,
          tls: true,
        },
        username: redisUser,
        password: redisKey,
        legacyMode: true,
      });

      redisClient.on("connect", () => {
        // eslint-disable-next-line no-console
        console.log("Redis Connected");
      });

      redisClient.on("error", (redisErr) => {
        if (redisErr.message === "Socket closed unexpectedly") {
          console.warn("Redis Socket Closed...");
        } else {
          console.error("Redis Client Error", redisErr.message);
        }
      });

      await redisClient.connect();

      const redisStore = new RedisStore({
        client: redisClient,
        prefix: redisPrefix,
      });

      return {
        redisStore: redisStore,
        redisClient: redisClient as RedisClientType,
      };
    }
  } catch (e) {
    console.error("Error Created Redis Store", e);
  }

  return undefined;
}
