import crypto from "crypto";
import { Request } from "express";

/** Create Buffer from data.
 * Simplified from passport-azure-ad's jwe.js
 */
export const createBuffer = (data: string | Buffer | number, encoding: BufferEncoding) => {
  if (!Buffer.isBuffer(data) && typeof data !== "string" && typeof data !== "number")
    throw new Error("in createBuffer, data must be a buffer, string or number");

  if (typeof data === "string") return Buffer.from(data, encoding);
  else if (typeof data === "number") return Buffer.alloc(data);
  else return Buffer.from(data);
};

/** Encrypt data
 * Derived from passport-azure-ad's cookieContentHandler.js
 * @param content The value to encrypt
 * @param key Encryption key
 * @param iv Encryption iv
 * @returns HEX encoded encrypted content and auth tag, seperated by a period.
 */
export function encryptContent(content: string, key: string | Buffer, iv: string | Buffer): string {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  let encrypted = cipher.update(content, "utf8", "hex");
  encrypted += cipher.final("hex");
  const authTag = cipher.getAuthTag().toString("hex");

  return encrypted + "." + authTag;
}
/** Decrypt data
 * Derived from passport-azure-ad's cookieContentHandler.js
 * @param encrypted The result from encryptContent
 * @param key Encryption key
 * @param iv Encryption iv
 * @returns The decrypted content
 */
export function decryptContent(
  encrypted: string,
  key: string | Buffer,
  iv: string | Buffer,
): string {
  const parts = encrypted.split(".");
  if (parts.length !== 2) throw new Error("invalid encrypted content provided to decryptContent");

  const authTag = createBuffer(parts[1], "hex");

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(parts[0], "hex", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}

/** Generates a random nonce
 * @param bytes Number of random bytes, default 12
 * @returns Base 64 encoded string of random bytes
 */
export function generateNonce(bytes?: number) {
  return crypto.randomBytes(bytes && bytes > 0 ? bytes : 12).toString("base64");
}

/** Create content for an encrypted cookie
 * @param name Cookie base name. Will have an iv appended to it.
 * @param value Value to encrypt
 * @returns Object with final name and encrypted value to make the cookie
 */
export function createEncryptedCookie(name: string, value: string) {
  let cookieName = name;
  const key = process.env.AUTH_COOKIE_KEY;
  const ivBuffer = crypto.randomBytes(12);
  cookieName += "." + ivBuffer.toString("base64");
  const encryptedValue = encryptContent(value, key, ivBuffer);
  return {
    name: cookieName,
    value: encryptedValue,
  };
}

/** Finds and decrypts a cookie
 * @param req Request containing cookies
 * @param baseName Starting name of the cookie. Will check all cookies starting with this until a match
 * @param find1 If not given, will decrypt and return first cookie matching baseName.
 * If given but find2 not given, will only return if decrypted value matches this.
 * @param find2 If given, assumed value is stringified json,
 * will check that for a property find1 with value find2, as strings
 */
export function findDecryptedCookie(
  req: Request,
  baseName: string,
  find1?: string,
  find2?: string,
): undefined | { name: string; value: string } {
  const cookies = req.cookies as unknown as Record<string, string>;
  let foundValue: string | undefined = undefined;
  let foundName: string | undefined = undefined;
  let found = false;
  const key = process.env.AUTH_COOKIE_KEY;
  Object.keys(cookies).forEach((cookieName) => {
    if (!found && cookieName && cookieName.startsWith(baseName)) {
      try {
        const cookieValue = cookies[cookieName];
        const nameParts = cookieName.split(".");
        let iv = "";
        let ivBuffer;
        if (nameParts.length > 1) {
          iv = nameParts[nameParts.length - 1];
          ivBuffer = createBuffer(iv, "base64");
        }
        if (!ivBuffer) {
          return;
        }
        const decryptedValue = decryptContent(cookieValue, key, ivBuffer);
        if (!find1) {
          // No find option, return first decryptable cookie
          found = true;
          foundValue = decryptedValue;
          foundName = cookieName;
        } else if (!find2) {
          // Has find1 but not find2, return cookie if decrypted value matches find1
          if (find1 === decryptedValue) {
            found = true;
            foundValue = decryptedValue;
            foundName = cookieName;
          }
        } else {
          // Has find1 and find2, return cookie if JSON encoded value[find] = find2
          // Don't actually need to parse json since stringify is predictable how it will appear.
          const toFind = `"${find1}":"${find2}"`;
          if (decryptedValue.indexOf(toFind) !== -1) {
            found = true;
            foundValue = decryptedValue;
            foundName = cookieName;
          }
        }
      } catch (e) {
        // If can't decrypt, pretend it does not exist
      }
    }
  });

  if (foundName && foundValue) {
    return { name: foundName, value: foundValue };
  }
  return undefined;
}
