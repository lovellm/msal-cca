import { ICacheClient } from "@azure/msal-node";
import { RedisClientType } from "redis";

const exp = 1000 * 60 * 60 * 12;

// Create an ICacheClient around a Redis Client to use with MSAL.
export default function (client: RedisClientType) {
  return {
    get: async (key: string) => {
      const data = await client.v4.get(key);
      return data;
    },
    set: async (key: string, value: string) => {
      const data = await client.v4.set(key, value, { PX: exp });
      return data;
    },
  } as ICacheClient;
}
