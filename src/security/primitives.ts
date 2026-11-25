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
// Minimal shell for server-rendered pages (/device, OAuth consent, device
// review). Styles stay inline because these pages' CSP allows no external
// stylesheet, script, font or image. Visual tokens mirror web/DESIGN.md.
const PAGE_STYLE = `:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:#fafbfc;color:#0f172a;font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}main{max-width:640px;margin:0 auto;padding:48px 16px}.panel{background:#fff;border:1px solid #e2e8f0;border-radius:12px;box-shadow:0 1px 3px rgba(15,23,42,.06);padding:28px}.brand{display:flex;align-items:center;gap:8px;font-weight:700;margin-bottom:20px}.mark{display:inline-flex;width:26px;height:26px;border-radius:7px;background:#0f172a}h1{font-size:22px;letter-spacing:-.015em;line-height:1.25;margin:0 0 12px}p{margin:0 0 12px;color:#475569}ul{margin:16px 0;padding:0;list-style:none;border:1px solid #e2e8f0;border-radius:10px;overflow:hidden}li{padding:12px 14px;border-bottom:1px solid #e2e8f0;color:#475569;overflow-wrap:anywhere}li:last-child{border-bottom:0}li strong{color:#0f172a}form{display:flex;flex-direction:column;gap:14px;margin-top:8px}label{display:flex;flex-direction:column;gap:6px;font-weight:600;font-size:13px}input:not([type=hidden]){width:100%;min-height:40px;padding:8px 12px;border:1px solid #cbd5e1;border-radius:8px;font:inherit;font-family:"SF Mono",Menlo,Consolas,monospace;font-size:13px}input:focus{outline:none;border-color:#059669;box-shadow:0 0 0 3px rgba(5,150,105,.35)}button,a.button{align-self:flex-start;display:inline-flex;align-items:center;min-height:40px;padding:0 18px;border:0;border-radius:8px;background:#0f172a;color:#fff;font:inherit;font-weight:600;text-decoration:none;cursor:pointer}button:hover,a.button:hover{background:#1e293b}a{color:#0f172a}`;
function page(body: string): string {
  if (/^\s*<!doctype/i.test(body)) return body;
  const heading = /<h1>([\s\S]*?)<\/h1>/.exec(body)?.[1] ?? "AgentSecret";
  const title = heading.replace(/<[^>]*>/g, "");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>${title} · AgentSecret</title><style>${PAGE_STYLE}</style></head><body><main><div class="panel"><div class="brand"><span class="mark" aria-hidden="true"></span>AgentSecret</div>${body}</div></main></body></html>`;
}
export function html(value: string): Response {
  return new Response(page(value), {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy":
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
      "Referrer-Policy": "same-origin",
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
