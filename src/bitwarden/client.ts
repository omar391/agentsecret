import type { VaultConfig } from "../types";
type BitwardenConfig = Extract<VaultConfig, { type: "bitwarden" }>;
import { encoder, unbase64, HttpError, readText } from "../security/primitives";
import { pinnedFetch } from "../security/pinned-fetch";

/** Send provider credentials only to an HTTPS destination bound to checked DNS answers. */
export async function providerFetch(
  url: string,
  init: RequestInit,
): Promise<Response> {
  try {
    return await pinnedFetch(
      url,
      { ...init, redirect: "manual" },
      { allowNonStandardPort: true },
    );
  } catch {
    throw new HttpError(502, "vault_provider_unavailable");
  }
}
export async function hmac(
  key: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(key).buffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(
    await crypto.subtle.sign("HMAC", imported, new Uint8Array(data).buffer),
  );
}
function concat(...arrays: Uint8Array[]) {
  const result = new Uint8Array(arrays.reduce((sum, a) => sum + a.length, 0));
  let at = 0;
  for (const a of arrays) {
    result.set(a, at);
    at += a.length;
  }
  return result;
}
/** Bitwarden SDK derive_shareable_key(seed, "accesstoken", Some("sm-access-token")). */
export async function accessTokenKey(seed: Uint8Array): Promise<Uint8Array> {
  if (seed.length !== 16) throw new HttpError(400, "invalid_bitwarden_seed");
  const prk = await hmac(encoder.encode("bitwarden-accesstoken"), seed);
  const info = encoder.encode("sm-access-token");
  const first = await hmac(prk, concat(info, new Uint8Array([1])));
  return concat(
    first,
    await hmac(prk, concat(first, info, new Uint8Array([2]))),
  );
}
/** Only authenticated AES256-CBC/HMAC-SHA256 EncString type 2 is accepted. */
export async function decryptBitwarden(
  value: string,
  key: Uint8Array,
): Promise<string> {
  try {
    if (key.length !== 64 || !value.startsWith("2.")) throw new Error();
    const parts = value.slice(2).split("|");
    if (parts.length !== 3) throw new Error();
    const [iv, ciphertext, mac] = parts.map(unbase64);
    if (
      iv.length !== 16 ||
      mac.length !== 32 ||
      !ciphertext.length ||
      ciphertext.length % 16
    )
      throw new Error();
    const authenticationKey = await crypto.subtle.importKey(
      "raw",
      new Uint8Array(key.slice(32)).buffer,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );
    if (
      !(await crypto.subtle.verify(
        "HMAC",
        authenticationKey,
        new Uint8Array(mac).buffer,
        new Uint8Array(concat(iv, ciphertext)).buffer,
      ))
    )
      throw new Error();
    const encryptionKey = await crypto.subtle.importKey(
      "raw",
      new Uint8Array(key.slice(0, 32)).buffer,
      "AES-CBC",
      false,
      ["decrypt"],
    );
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(
      await crypto.subtle.decrypt(
        { name: "AES-CBC", iv: new Uint8Array(iv).buffer },
        encryptionKey,
        new Uint8Array(ciphertext).buffer,
      ),
    );
  } catch {
    throw new HttpError(502, "bitwarden_decryption_failed");
  }
}
export async function providerJson(
  url: string,
  init: RequestInit,
): Promise<Record<string, any>> {
  let response: Response;
  try {
    response = await providerFetch(url, init);
  } catch {
    throw new HttpError(502, "vault_provider_unavailable");
  }
  if (!response.ok) {
    await response.body?.cancel();
    throw new HttpError(502, "vault_provider_rejected_request");
  }
  try {
    const value = JSON.parse(await readText(response, 1024 * 1024));
    if (!value || typeof value !== "object") throw new Error();
    return value;
  } catch {
    throw new HttpError(502, "invalid_vault_response");
  }
}
export async function resolveBitwarden(
  config: BitwardenConfig,
  secretId: string,
): Promise<string> {
  const match =
    /^0\.([0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})\.([^.:]+):([^:]+)$/i.exec(
      config.accessToken,
    );
  if (
    !match ||
    !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(secretId)
  )
    throw new HttpError(400, "invalid_bitwarden_configuration");
  const tokenKey = await accessTokenKey(unbase64(match[3]));
  const auth = await providerJson(
    (config.identityUrl || "https://identity.bitwarden.com") + "/connect/token",
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: match[1],
        client_secret: match[2],
        scope: "api.secrets",
      }),
    },
  );
  if (
    typeof auth.access_token !== "string" ||
    typeof auth.encrypted_payload !== "string"
  )
    throw new HttpError(502, "invalid_bitwarden_response");
  let payload: { encryptionKey: string };
  let organization: string;
  try {
    payload = JSON.parse(
      await decryptBitwarden(auth.encrypted_payload, tokenKey),
    );
    const token = JSON.parse(
      new TextDecoder().decode(unbase64(auth.access_token.split(".")[1])),
    );
    organization = token.organization;
    if (typeof organization !== "string") throw new Error();
  } catch {
    throw new HttpError(502, "invalid_bitwarden_encrypted_payload");
  }
  const organizationKey = unbase64(payload.encryptionKey);
  const secret = await providerJson(
    (config.apiUrl || "https://api.bitwarden.com") + "/secrets/" + secretId,
    {
      headers: {
        Authorization: "Bearer " + auth.access_token,
        Accept: "application/json",
      },
    },
  );
  if (
    secret.id !== secretId ||
    secret.organizationId !== organization ||
    typeof secret.value !== "string"
  )
    throw new HttpError(502, "invalid_bitwarden_response");
  return decryptBitwarden(secret.value, organizationKey);
}
