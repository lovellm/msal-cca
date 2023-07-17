import crypto from "crypto";
import { AccountEntity, ICachePlugin, TokenCacheContext } from "@azure/msal-common";
import { ICacheClient, IPartitionManager, TokenCache } from "@azure/msal-node";
import { encryptContent, decryptContent, createBuffer } from "../auth/cryptoHelpers";

interface CryptoCacheRecord {
  iv: string;
  msg: string;
}

/** MSAL cache plugin that will encrypt the cache store.
 * based on:
 * https://github.com/AzureAD/microsoft-authentication-library-for-js/blob/dev/lib/msal-node/src/cache/distributed/DistributedCachePlugin.ts
 */
export class CryptoCachePlugin implements ICachePlugin {
  private client: ICacheClient;
  private partitionManager: IPartitionManager;
  private key: string;

  constructor(client: ICacheClient, partitionManager: IPartitionManager) {
    this.client = client;
    this.partitionManager = partitionManager;
    this.key = process.env.AUTH_COOKIE_KEY;
  }

  public async beforeCacheAccess(cacheContext: TokenCacheContext): Promise<void> {
    const partitionKey = await this.partitionManager.getKey();
    const recordString = await this.client.get(partitionKey);

    // default to empty string if no record or something went wrong
    let cacheContent = "";
    if (recordString) {
      try {
        // parse to an object
        const record = JSON.parse(recordString) as CryptoCacheRecord;

        // turn the iv in to a buffer
        const ivBuffer = createBuffer(record.iv, "base64");

        // decrypt the content to load in to token cache
        cacheContent = decryptContent(record.msg, this.key, ivBuffer);
      } catch (e) {
        // ignore, if above went wrong, no usable cache
      }
    }
    cacheContext.tokenCache.deserialize(cacheContent);
  }

  public async afterCacheAccess(cacheContext: TokenCacheContext): Promise<void> {
    // only take action if the cache has changed, otherwise no reasons to save
    if (cacheContext.cacheHasChanged) {
      // msal default does this to get the partion key, so keeping their logic as is
      const kvStore = (cacheContext.tokenCache as TokenCache).getKVStore();
      const accountEntities = Object.values(kvStore).filter((value) =>
        AccountEntity.isAccountEntity(value as object),
      );
      if (accountEntities.length > 0) {
        const accountEntity = accountEntities[0] as AccountEntity;
        const partitionKey = await this.partitionManager.extractKey(accountEntity);

        // serialize the token cache to prepare it to save
        const cacheContent = cacheContext.tokenCache.serialize();

        // make a new random iv
        const ivBuffer = crypto.randomBytes(12);

        // encrypt the cache and make the record to persist
        const msg = encryptContent(cacheContent, this.key, ivBuffer);
        const record: CryptoCacheRecord = {
          iv: ivBuffer.toString("base64"),
          msg: msg,
        };

        await this.client.set(partitionKey, JSON.stringify(record));
      }
    }
  }
}
