/**
 * Customer browser sessions.
 *
 * One module owns the whole lifetime of a customer session so that the rules cannot drift apart
 * between the sign-in callback, the request guard and the rotation point:
 *
 * - **Opaque, server-issued.** The value is `as2.<base64url account id>.<32 random bytes>`, minted
 *   by `random()` (32 bytes = 256 bits from the platform CSPRNG). Only its SHA-256 digest is
 *   persisted in the account's authority Durable Object, so a database read cannot yield a usable
 *   session value.
 * - **Account-bound.** The account id is inside the value *and* inside the stored record; the
 *   record is the account's own Durable Object, one per account. A caller cannot choose a tenant:
 *   there is no request field anywhere that selects one for a customer session.
 * - **Bounded lifetime.** `exp` is set once at sign-in and rotation never moves it, so rotation
 *   refreshes the credential without extending the absolute window.
 * - **Rotated on privilege change and at a defined refresh point.** `rotateSession` runs on an
 *   identity link (a privilege change), `refreshSession` runs on any authenticated customer
 *   request once the rotation interval has elapsed. Both replace the stored digest atomically, so
 *   the old value stops working the moment the new one is written.
 * - **Revocable across independent edges.** The session lives in the authority, which every Worker
 *   instance reaches through its own Durable Object binding; nothing is cached in Worker memory or
 *   KV, so a revocation or rotation performed on one edge is seen by every other edge on its next
 *   request.
 * - **CSRF/origin.** The cookie is `HttpOnly`, `Secure`, `SameSite=Lax` and accepted on a
 *   state-changing request only from a same-origin caller (enforced in `authenticate`, which every
 *   customer route passes through). `Lax` and not `Strict` is deliberate: a provider callback is a
 *   cross-site top-level navigation, and `Strict` would drop the flow's own transaction cookie.
 *   The session cookie itself is never read by the callback, so `Lax` costs nothing there, and
 *   `Lax` is not attached to cross-site subrequests nor to cross-site POSTs, which is what makes
 *   an unproven cross-origin write impossible.
 */
import { authority } from "../state/authority-kernel";
import {
  HttpError,
  hash,
  now,
  random,
  reference,
} from "../security/primitives";
import type { Env, Principal, Session } from "../types";

/** The one cookie name a customer browser session travels in. */
export const SESSION_COOKIE = "agentsecret_session";

/** Absolute lifetime of a customer session, from sign-in. Rotation never extends it. */
export const SESSION_TTL_SECONDS = 8 * 3600;

/** The scopes a customer session carries. It is a control session, never an agent session. */
export const CUSTOMER_SCOPES = [
  "admin",
  "secrets:read",
  "secrets:proxy",
] as const;

/** Lowest rotation interval the deployment may ask for; 1s exists so a test can observe a rotation. */
const MIN_ROTATION_SECONDS = 1;
/** Default rotation interval: a session credential is at most this stale. */
const DEFAULT_ROTATION_SECONDS = 1800;
/** Upper bound on the configured interval, so no configuration disables rotation. */
const MAX_ROTATION_SECONDS = 3600;
/** Do not rotate inside the last minute of the absolute lifetime: it would only churn the store. */
const ROTATION_TAIL_SECONDS = 60;

/**
 * The rotation interval, clamped. It is deployment configuration, not request input: a client
 * cannot ask for a longer-lived credential, and the minimum stays above zero so "never rotate" is
 * not an expressible configuration.
 */
export function rotationSeconds(env: Env): number {
  const configured = Number(env.SESSION_ROTATION_SECONDS);
  if (!Number.isFinite(configured)) return DEFAULT_ROTATION_SECONDS;
  return Math.min(
    MAX_ROTATION_SECONDS,
    Math.max(MIN_ROTATION_SECONDS, Math.floor(configured)),
  );
}

/**
 * The customer session cookie. `SameSite=Lax`: see the module comment. `Max-Age` is always the
 * remaining absolute lifetime, never a fresh 8 hours, so a rotation cannot silently extend a
 * session's life.
 */
export function sessionCookie(value: string, maxAge: number): string {
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${Math.max(0, Math.floor(maxAge))}`;
}

/** Clear the session cookie. Used by logout and by account deletion. */
export function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

/**
 * Mint a fresh customer session for `accountId` and persist only its digest. Returns the value for
 * the `Set-Cookie` header; it is never returned in a body, a URL or a log line.
 */
export async function signInSession(
  env: Env,
  origin: string,
  accountId: string,
): Promise<string> {
  const value = reference("as2", accountId);
  const issuedAt = now();
  const session: Session = {
    tenant: accountId,
    purpose: "control",
    audience: origin,
    scopes: [...CUSTOMER_SCOPES],
    exp: issuedAt + SESSION_TTL_SECONDS,
    epoch: 0,
    createdAt: issuedAt,
    refreshedAt: issuedAt,
  };
  await authority(env, accountId, {
    op: "control_login",
    hash: await hash(value),
    session,
  });
  return value;
}

/**
 * Replace the stored digest of a live customer session with a fresh value, keeping the record's
 * tenant, scopes, audience and absolute expiry exactly as they are. The authority performs both
 * writes in one transaction and derives the replacement record from the *stored* session, so a
 * caller supplies only the new digest: nothing in the request can widen or prolong the session.
 *
 * Returns `null` (and writes nothing) when the session is not eligible: a bootstrap/agent
 * principal, an already-expired session, or one inside the final minute of its life.
 */
async function rotate(
  env: Env,
  principal: Principal,
  force: boolean,
): Promise<string | null> {
  if (principal.bootstrap || principal.purpose !== "control") return null;
  if (!principal.scopes.includes("admin")) return null;
  const at = now();
  if (!force && principal.exp - at <= ROTATION_TAIL_SECONDS) return null;
  if (!force) {
    // A session minted before this module existed has no `createdAt`; it is left alone rather than
    // rotated at an arbitrary point, because there is no honest answer to "how old is it".
    if (!principal.createdAt) return null;
    const lastRotation = principal.refreshedAt ?? principal.createdAt;
    if (at - lastRotation < rotationSeconds(env)) return null;
  }
  const value = reference("as2", principal.tenant);
  await authority(env, principal.tenant, {
    op: "rotate_session",
    principal,
    hash: await hash(value),
  });
  return value;
}

/**
 * The defined refresh point: called after every authenticated customer request. Rotation is due
 * once the configured interval has elapsed since the previous rotation (or since sign-in).
 */
export async function refreshSession(
  env: Env,
  principal: Principal,
): Promise<string | null> {
  return rotate(env, principal, false);
}

/**
 * Rotate on a privilege change: linking another identity to the account changes what the session
 * can reach, so the credential is replaced immediately rather than at the next refresh point.
 */
export async function rotateOnPrivilegeChange(
  env: Env,
  principal: Principal,
): Promise<string | null> {
  return rotate(env, principal, true);
}

/**
 * The parsed value of a session cookie, or `null` when the header carries no such cookie.
 * Deliberately does not validate the value: a malformed value must fail authentication, not be
 * silently dropped in favour of another credential form.
 */
export function sessionCookieValue(request: Request): string | null {
  const header = request.headers.get("Cookie");
  if (!header) return null;
  for (const item of header.split(";")) {
    const trimmed = item.trim();
    if (trimmed.startsWith(SESSION_COOKIE + "="))
      return trimmed.slice(SESSION_COOKIE.length + 1);
  }
  return null;
}

/** Fail closed when a caller asks to rotate something that is not a stored customer session. */
export function requireCustomerSession(principal: Principal): void {
  if (principal.bootstrap || principal.purpose !== "control")
    throw new HttpError(401, "customer_session_required");
}
