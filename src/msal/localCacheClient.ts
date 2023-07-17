import { ICacheClient } from "@azure/msal-node";

// Create an ICacheClient around a simple object to use with MSAL.
export default function () {
  const cache: Record<string, unknown> = {};

  return {
    get: async (key: string) => {
      if (key in cache) {
        return cache[key];
      }
    },
    set: async (key: string, value: string) => {
      cache[key] = value;
      return value;
    },
    cache: () => cache,
  } as ICacheClient;
}
