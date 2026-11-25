export class HttpError extends Error {
  constructor(
    public status: number,
    public code: string,
    message = code,
  ) {
    super(message);
  }
}
export const encoder = new TextEncoder();
export function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
export function unbase64(value: string): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/_=-]+$/.test(value))
    throw new HttpError(400, "invalid_encoding");
  try {
    return Uint8Array.from(
      atob(value.replace(/-/g, "+").replace(/_/g, "/")),
      (c) => c.charCodeAt(0),
    );
  } catch {
    throw new HttpError(400, "invalid_encoding");
  }
}
export async function hash(value: string): Promise<string> {
  return base64url(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", encoder.encode(value)),
    ),
  );
}

/** Reject JavaScript strings containing lone UTF-16 surrogates before hashing or JSON transport. */
export function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}
export function random(bytes = 32): string {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}
export const now = () => Math.floor(Date.now() / 1000);
export function tenantId(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{1,80}$/.test(value))
    throw new HttpError(400, "invalid_tenant");
  return value;
}
export function reference(prefix: string, tenant: string): string {
  return `${prefix}.${base64url(encoder.encode(tenantId(tenant)))}.${random()}`;
}
export interface ConnectReference {
  itemId: string;
  fieldId: string;
}

const CONNECT_ID = /^[0-9a-z]{26}$/;
const CONNECT_REFERENCE_UNSAFE =
  /[\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/;

/** Reject characters that are never valid in a provider reference. */
export function hasUnsafeConnectReferenceCharacter(value: string): boolean {
  return (
    !isWellFormedUnicode(value) ||
    value.includes("\ufffd") ||
    /[\u0000-\u001f\u007f-\u009f]/.test(value) ||
    CONNECT_REFERENCE_UNSAFE.test(value)
  );
}

/** Also reject percent-encoded unsafe characters before a reference is used. */
export function hasUnsafeConnectReferenceText(value: string): boolean {
  if (hasUnsafeConnectReferenceCharacter(value)) return true;
  try {
    return hasUnsafeConnectReferenceCharacter(decodeURIComponent(value));
  } catch {
    return false;
  }
}

/** Check whether a consumer field path is a well-formed JSON Pointer path. */
function isWellFormedJsonPointer(fieldPath: string): boolean {
  if (!fieldPath.startsWith("/")) return false;
  return fieldPath
    .split("/")
    .slice(1)
    .every((part) => !/~(?![01])/.test(part));
}

/** Normalize a consumer field path to a Connect field ID. */
function connectFieldIdFromPath(fieldPath: string): string | null {
  if (fieldPath.includes("%")) return null;
  if (!isWellFormedJsonPointer(fieldPath)) return null;
  const parts = fieldPath.split("/");
  if (
    parts.length !== 4 ||
    parts[0] !== "" ||
    parts[1] !== "fields" ||
    parts[3] !== "value"
  )
    return null;
  const candidate = parts[2];
  if (!candidate) return null;
  if (/~(?![01])/.test(candidate)) return null;
  const fieldId = candidate.replace(/~1/g, "/").replace(/~0/g, "~");
  return fieldId &&
    fieldId.length <= 256 &&
    !hasUnsafeConnectReferenceCharacter(fieldId)
    ? fieldId
    : null;
}

/** Build a canonical Connect reference from generic object/field inputs. */
export function connectReferenceFromGeneric(
  objectId: string,
  fieldPath: string | null | undefined,
): string | null {
  if (!CONNECT_ID.test(objectId)) return null;
  if (fieldPath === null || fieldPath === undefined || fieldPath === "")
    return null;
  if (fieldPath.length > 1024) return null;
  const fieldId = connectFieldIdFromPath(fieldPath);
  return fieldId ? `${objectId}#${encodeURIComponent(fieldId)}` : null;
}

/**
 * Parse a provider-independent 1Password Connect field reference without
 * importing vault/provider code. Returns null for malformed references so
 * callers can apply their own error contract.
 */
export function parseConnectReference(
  reference: string,
): ConnectReference | null {
  if (hasUnsafeConnectReferenceCharacter(reference)) return null;
  const parts = reference.split("#");
  if (parts.length !== 2) return null;
  const [itemId, encodedFieldId] = parts;
  if (!CONNECT_ID.test(itemId)) return null;
  let fieldId: string;
  try {
    fieldId = decodeURIComponent(encodedFieldId);
  } catch {
    return null;
  }
  if (
    !fieldId ||
    fieldId.length > 256 ||
    hasUnsafeConnectReferenceCharacter(fieldId)
  )
    return null;
  return { itemId, fieldId };
}

export function referenceTenant(value: unknown, prefix: string): string {
  if (typeof value !== "string" || value.length > 256)
    throw new HttpError(401, "invalid_token");
  const parts = value.split(".");
  if (
    parts.length !== 3 ||
    parts[0] !== prefix ||
    !/^[\w-]{43}$/.test(parts[2])
  )
    throw new HttpError(401, "invalid_token");
  try {
    const tenant = tenantId(
      new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(
        unbase64(parts[1]),
      ),
    );
    if (base64url(encoder.encode(tenant)) !== parts[1]) throw new Error();
    return tenant;
  } catch {
    throw new HttpError(401, "invalid_token");
  }
}
export function equal(a: string, b: string): boolean {
  const x = encoder.encode(a),
    y = encoder.encode(b);
  let result = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++)
    result |= (x[i] || 0) ^ (y[i] || 0);
  return result === 0;
}
export async function readBytes(
  response: Response | Request,
  max = 1024 * 1024,
): Promise<Uint8Array> {
  const advertised = Number(response.headers.get("content-length"));
  if (Number.isFinite(advertised) && advertised > max)
    throw new HttpError(413, "payload_too_large");
  if (!response.body) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > max) {
        await reader.cancel();
        throw new HttpError(413, "payload_too_large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const joined = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.length;
  }
  return joined;
}
export async function readText(
  response: Response | Request,
  max = 1024 * 1024,
  fatalUtf8 = false,
): Promise<string> {
  const bytes = await readBytes(response, max);
  return new TextDecoder("utf-8", {
    fatal: fatalUtf8,
    ignoreBOM: false,
  }).decode(bytes);
}
export async function body(request: Request): Promise<Record<string, unknown>> {
  const text = await readText(request, 64 * 1024);
  try {
    if (
      request.headers
        .get("content-type")
        ?.includes("application/x-www-form-urlencoded")
    )
      return Object.fromEntries(new URLSearchParams(text));
    const result = JSON.parse(text || "{}");
    if (!result || Array.isArray(result) || typeof result !== "object")
      throw new Error();
    return result;
  } catch {
    throw new HttpError(400, "invalid_request");
  }
}
export function json(value: unknown, status = 200): Response {
  return Response.json(value, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
export function html(value: string): Response {
  return new Response(value, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy":
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
export function escape(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (ch) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        ch
      ]!,
  );
}
