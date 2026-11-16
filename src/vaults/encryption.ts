import type { Env } from "../types";
import {
  base64url,
  unbase64,
  encoder,
  HttpError,
} from "../security/primitives";
import { isKeyId, parseKeyring } from "./keyring";
export interface Envelope {
  v: 1 | 2;
  kid: string;
  iv: string;
  data: string;
}
export interface VaultBinding {
  accountId: string;
  connectionId: string;
  revision: number;
}
function aad(kid: string, tenant: string, binding?: VaultBinding): Uint8Array {
  return encoder.encode(
    binding
      ? `agentsecret:v2:${kid}:${binding.accountId}:${binding.connectionId}:${binding.revision}`
      : `agentsecret:v1:${kid}:${tenant}`,
  );
}
/**
 * The one definition of a well-formed keyring, shared with the staging path in
 * `./keyring`, so encryption and rotation cannot disagree about what a
 * keyring is. Key material length is validated per key when it is used, since
 * a keyring may hold an ID that only has to decrypt.
 */
function keys(env: Env): Record<string, string> {
  return parseKeyring(env).keys;
}
async function key(
  env: Env,
  id: string,
  usage: Array<"encrypt" | "decrypt">,
): Promise<CryptoKey> {
  const encoded = keys(env)[id];
  if (typeof encoded !== "string")
    throw new HttpError(503, "vault_key_unavailable");
  const bytes = unbase64(encoded);
  if (bytes.length !== 32) throw new HttpError(503, "invalid_vault_key");
  return crypto.subtle.importKey(
    "raw",
    new Uint8Array(bytes).buffer,
    "AES-GCM",
    false,
    usage,
  );
}
export async function encryptConfig(
  value: unknown,
  tenant: string,
  env: Env,
  binding?: VaultBinding,
): Promise<Envelope> {
  const kid = env.VAULT_ACTIVE_KEY;
  if (!isKeyId(kid) || !keys(env)[kid])
    throw new HttpError(503, "vault_keyring_unconfigured");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: new Uint8Array(iv).buffer,
      additionalData: new Uint8Array(aad(kid, tenant, binding)).buffer,
    },
    await key(env, kid, ["encrypt"]),
    encoder.encode(JSON.stringify(value)),
  );
  return {
    v: binding ? 2 : 1,
    kid,
    iv: base64url(iv),
    data: base64url(new Uint8Array(data)),
  };
}
export async function decryptConfig(
  envelope: Envelope,
  tenant: string,
  env: Env,
  binding?: VaultBinding,
): Promise<unknown> {
  if (!envelope || envelope.v !== (binding ? 2 : 1) || !envelope.kid)
    throw new HttpError(503, "vault_reconnection_required");
  try {
    const data = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(unbase64(envelope.iv)).buffer,
        additionalData: new Uint8Array(aad(envelope.kid, tenant, binding))
          .buffer,
      },
      await key(env, envelope.kid, ["decrypt"]),
      new Uint8Array(unbase64(envelope.data)).buffer,
    );
    return JSON.parse(
      new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(data),
    );
  } catch {
    throw new HttpError(503, "vault_decryption_failed");
  }
}
