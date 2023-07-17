import { IPartitionManager } from "@azure/msal-node";
import { AccountEntity } from "@azure/msal-common"; // dependency of msal-node

export default function partitionManager(accountId?: string) {
  const keyPrefix = (process.env.APP_NAME || "") + "a";
  return {
    getKey: async (): Promise<string> => {
      return keyPrefix + accountId;
    },
    extractKey: async (accountEntity: AccountEntity): Promise<string> => {
      if ("homeAccountId" in accountEntity) {
        return keyPrefix + accountEntity.homeAccountId;
      }
      throw new Error("homeAccountId is not defined");
    },
  } as IPartitionManager;
}
