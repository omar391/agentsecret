import { HttpError, base64url, unbase64 } from "../security/primitives";

/**
 * The Worker vault keyring: a JSON map from a non-secret key ID to a 32-byte
 * AES-256-GCM key, plus the single ID that names the key new envelopes use.
 *
 * These values live in the protected Cloudflare secrets `VAULT_KEYS` and
 * `VAULT_ACTIVE_KEY`. They are staged, never edited in place, so every
 * mutation of this keyring is a complete replacement rather than an update.
 */

export const KEY_ID_PATTERN = /^[a-zA-Z0-9_-]{1,40}$/;

export interface Keyring {
  /** Key ID to base64url-encoded 32-byte key material. */
  keys: Record<string, string>;
  /** The ID new envelopes are written under. */
  activeKey: string;
}

/** One staged keyring version, with the version it replaces kept beside it. */
export interface StagedKeyVersion {
  /** The staged replacement: the complete key union with the new key active. */
  keyring: Keyring;
  /** The version that was current when this one was staged. */
  previous: Keyring;
  /** The appended key ID. */
  newKeyId: string;
}

export function isKeyId(value: unknown): value is string {
  return typeof value === "string" && KEY_ID_PATTERN.test(value);
}

/** Canonical base64url spelling of one stored key value. */
export function canonicalKey(encoded: unknown): string {
  if (typeof encoded !== "string" || !encoded)
    throw new HttpError(503, "invalid_vault_key");
  const bytes = unbase64(encoded);
  if (bytes.length !== 32) throw new HttpError(503, "invalid_vault_key");
  return base64url(bytes);
}

/**
 * Read and validate the keyring a live Worker env carries.
 *
 * Structure and the key-ID shape are validated here; key material length is
 * validated when a key is actually used, because a keyring may hold an ID that
 * only has to decrypt. This is the single definition of a well-formed keyring
 * that encryption and staging share, so the two cannot disagree about what a
 * keyring is.
 */
/**
 * Accept either the Worker env form (a JSON string) or an already-parsed key
 * map, so a staged version can be re-read directly as well as re-declared.
 */
export type KeyringSource =
  { VAULT_KEYS?: string; VAULT_ACTIVE_KEY?: string } | Keyring;

function rawKeys(source: KeyringSource): unknown {
  const candidate =
    (source as Keyring).keys ?? (source as { VAULT_KEYS?: string }).VAULT_KEYS;
  if (typeof candidate === "string") {
    try {
      return JSON.parse(candidate || "");
    } catch {
      return undefined;
    }
  }
  return candidate;
}

export function parseKeyring(source: KeyringSource): Keyring {
  const value = rawKeys(source);
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new HttpError(503, "vault_keyring_unconfigured");
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length === 0)
    throw new HttpError(503, "vault_keyring_unconfigured");
  const keys: Record<string, string> = {};
  for (const [id, encoded] of entries) {
    if (!isKeyId(id) || typeof encoded !== "string" || !encoded)
      throw new HttpError(503, "vault_keyring_unconfigured");
    keys[id] = encoded;
  }
  const activeKey =
    (source as Keyring).activeKey ??
    (source as { VAULT_ACTIVE_KEY?: string }).VAULT_ACTIVE_KEY;
  if (!isKeyId(activeKey) || !keys[activeKey])
    throw new HttpError(503, "vault_keyring_unconfigured");
  return { keys, activeKey };
}

/**
 * Stage one new keyring version: append a fresh key and make it active.
 *
 * Every existing key ID and value is preserved unchanged, so a staged version
 * can decrypt every envelope the previous version could. Reusing an existing
 * key ID is refused, because an ID is the envelope's permanent label and
 * re-binding it would silently change what stored ciphertext means.
 */
export function stageNextVersion(
  current: Keyring,
  addition: { id: string; key: string },
): StagedKeyVersion {
  const id = addition?.id;
  if (!isKeyId(id)) throw new HttpError(503, "vault_keyring_unconfigured");
  if (Object.prototype.hasOwnProperty.call(current.keys, id))
    throw new HttpError(409, "vault_key_id_reused");
  const encoded = canonicalKey(addition?.key);
  return {
    keyring: {
      keys: { ...current.keys, [id]: encoded },
      activeKey: id,
    },
    previous: current,
    newKeyId: id,
  };
}

/**
 * Restore a previous active key without dropping any staged key.
 *
 * Once an envelope has been written under a key ID that key must stay
 * decryptable, so a rollback keyring is the union of the staged keyring and the
 * restored active key, never a strict return to the earlier map. Restoring an
 * ID the keyring does not contain is refused rather than silently widening it.
 */
export function rollbackKeyring(
  staged: Keyring,
  restoredActiveKey: string,
): Keyring {
  if (!isKeyId(restoredActiveKey) || !staged.keys[restoredActiveKey])
    throw new HttpError(503, "vault_key_unavailable");
  return { keys: { ...staged.keys }, activeKey: restoredActiveKey };
}

/**
 * The complete secret payload one staged Worker version carries.
 *
 * Both values are produced from one keyring object so the staged bulk upload
 * can never present half a version: a key map that omits an ID the active key
 * names would strand every envelope written under it. This is the exact shape
 * a protected stdin producer feeds to the versioned secret workflow.
 */
export function stagedSecretBundle(version: Keyring): {
  VAULT_KEYS: string;
  VAULT_ACTIVE_KEY: string;
} {
  const normalized: Record<string, string> = {};
  for (const id of Object.keys(version.keys).sort())
    normalized[id] = canonicalKey(version.keys[id]);
  return {
    VAULT_KEYS: JSON.stringify(normalized),
    VAULT_ACTIVE_KEY: version.activeKey,
  };
}

/** Non-secret inventory: every key ID, plus which one is active. */
export function describeKeyring(version: Keyring): {
  keyCount: number;
  keyIds: string[];
  activeKeyId: string;
} {
  return {
    keyCount: Object.keys(version.keys).length,
    keyIds: Object.keys(version.keys).sort(),
    activeKeyId: version.activeKey,
  };
}

/**
 * One-way verification metadata for a key ID, so a rotation step can confirm
 * the active key without disclosing the key ID itself or any key material.
 */
export async function keyringFingerprint(
  version: Keyring,
): Promise<{ keyCount: number; activeKeyFingerprint: string }> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode("agentsecret:active-key:" + version.activeKey),
  );
  return {
    keyCount: Object.keys(version.keys).length,
    activeKeyFingerprint: base64url(new Uint8Array(digest)),
  };
}
