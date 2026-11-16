import type { Env, Principal, Session } from "../types";
import { control } from "../security/auth";
import { authority } from "../state/authority-kernel";
import type { RegistryDatabase } from "../registry/database";
import { HttpError, hash, now, random } from "../security/primitives";
import {
  requireCustomerSession,
  rotateOnPrivilegeChange,
  SESSION_COOKIE,
  SESSION_TTL_SECONDS,
  sessionCookie,
  signInSession,
} from "./sessions";
import {
  linkCustomerIdentity,
  registerOrLoginCustomer,
  validateAccountOwnership,
} from "../registry";
import type { IdentityInput } from "../registry/types";
import {
  authorizationUrl,
  exchangeCode,
  providerConfig,
  resolveIdentity,
  type ProviderIdentity,
  type SocialProvider,
  type SocialProviderConfig,
} from "./providers";
import {
  claimTransaction,
  createTransaction,
  findTransaction,
  TRANSACTION_TTL_SECONDS,
} from "./transactions";

const TRANSACTION_COOKIE_PREFIX = "agentsecret_oauth_";
/** Fixed, parameter-free destination: nothing the provider returned is reflected into a URL. */
const POST_LOGIN_LOCATION = "/?view=dashboard";

export type SocialPhase = "start" | "callback";

/** Exact route table for the four customer-facing routes; anything else under `/auth/` is inert. */
export function socialRoute(
  path: string,
): { provider: SocialProvider; phase: SocialPhase } | null {
  const match = /^\/auth\/(github|google)(\/callback)?$/.exec(path);
  if (!match) return null;
  return {
    provider: match[1] as SocialProvider,
    phase: match[2] ? "callback" : "start",
  };
}

function cookieValue(request: Request, name: string): string | null {
  const header = request.headers.get("Cookie");
  if (!header) return null;
  for (const item of header.split(";")) {
    const trimmed = item.trim();
    if (!trimmed.startsWith(name + "=")) continue;
    const value = trimmed.slice(name.length + 1);
    return value.length > 0 ? value : null;
  }
  return null;
}

function requireDb(env: Env): RegistryDatabase {
  if (!env.DB) throw new HttpError(503, "database_unavailable");
  return env.DB;
}

/**
 * Cookie policy for the two cookies this flow sets. Both are `SameSite=Lax`, which is the value the
 * browser sends on the cross-site top-level GET navigation the provider redirects this browser
 * back with — the return leg of the flow, and the reason a `Strict` session cookie broke it: the
 * callback arrived without a session, so a started link could only fail (`401 unauthorized`) after
 * its transaction had already been claimed.
 *
 * `Lax` is the minimum that repairs that return leg, and the choice was deliberate:
 *   - `Strict` is withheld on the provider's cross-site navigation, so the link callback cannot see
 *     which session asked for it.
 *   - `None` would attach the session to every cross-site request any page makes, which is far more
 *     than the flow needs.
 * `Lax` attaches it to top-level navigations only; cross-site subresource requests, cross-site
 * `POST`s and cross-site `DELETE`s still never carry it.
 *
 * Nothing state-changing becomes reachable by a cross-site top-level GET through `Lax`: every
 * authenticated mutation in this server is a non-GET route (`/api/auth/logout`,
 * `/api/user/onboarding`, `/api/user/vaults*`, `/api/user/policies`,
 * `/api/user/account`, `/api/user/revoke`, `/oauth/revoke`, `/api/device/approve`, `/proxy`,
 * `/mcp`), and a
 * cookie-authenticated non-GET request additionally requires a same-origin `Origin` header
 * (`authenticate` → `sameOrigin(request, true)`), which a cross-site initiator cannot forge. The
 * only GET that writes anything is this flow's own start route, and its one authenticated form
 * (`?link=1`) refuses a cross-site navigation outright (see `socialStart`).
 *
 * Both cookies are HttpOnly and Secure; the transaction cookie is scoped to its own provider's
 * path, so the two providers' bindings cannot be swapped for one another by the browser. The
 * session cookie itself is defined once, in `sessions.ts`.
 */
function transactionCookie(
  provider: SocialProvider,
  value: string,
  maxAge: number,
): string {
  return `${TRANSACTION_COOKIE_PREFIX}${provider}=${value}; Path=/auth/${provider}; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function redirect(
  location: string,
  cookies: string[] = [],
  status = 303,
): Response {
  const response = new Response(null, {
    status,
    headers: { Location: location, "Cache-Control": "no-store" },
  });
  for (const cookie of cookies) response.headers.append("Set-Cookie", cookie);
  return response;
}

/**
 * Identity input for the registry. The provider subject is the identity key. The provider email is
 * metadata: provider email is retained on the identity with its verification bit; account email
 * is populated only for provider-verified addresses. The GitHub
 * login name is display metadata too, never a key.
 */
function identityInput(identity: ProviderIdentity): IdentityInput {
  const providerEmail = identity.email;
  const profile: Record<string, unknown> = {
    name: identity.name,
    avatarUrl: identity.avatarUrl,
  };
  if (identity.login) profile.login = identity.login;
  return {
    provider: identity.provider,
    providerSubject: identity.subject,
    email: providerEmail,
    emailVerified: Boolean(identity.emailVerified),
    profile,
  };
}

export async function socialStart(
  request: Request,
  env: Env,
  url: URL,
  provider: SocialProvider,
): Promise<Response> {
  const origin = env.PUBLIC_ORIGIN || url.origin;
  // Configured first: an unconfigured provider fails closed before touching any storage.
  const config = providerConfig(env, provider, origin);
  const db = requireDb(env);

  // A link is only ever started from an authenticated customer session, and the account it will
  // link into is recorded with that session's own digest as one value, so the row and its binding
  // cannot be written apart. The account is the authority; the session digest is the proof that
  // whoever completes the link is the session that asked for it. Everything else is a sign-in.
  let link: { accountId: string; sessionHash: string } | null = null;
  if (url.searchParams.get("link") === "1") {
    // The session cookie is `Lax`, so a browser attaches it to a cross-site top-level GET. That
    // makes this the one authenticated GET that writes, so a link may only be started by the
    // customer's own navigation: `Sec-Fetch-Site` is set by the browser and cannot be forged by a
    // page. A client that is not a browser navigation sends no such header — it still has to hold
    // the session cookie to get past `control` below.
    if (request.headers.get("Sec-Fetch-Site") === "cross-site")
      throw new HttpError(403, "cross_site_navigation");
    const principal = await control(request, env);
    // Only a real customer session may start a link: an operator/agent credential that shares the
    // control purpose is refused here, before any transaction row is written.
    requireCustomerSession(principal);
    await validateAccountOwnership(env, principal.tenant);
    // `principal.hash` is the SHA-256 of the session cookie value: the stored credential hash,
    // never the value itself, and the same digest the callback computes from the cookie it sees.
    link = { accountId: principal.tenant, sessionHash: principal.hash };
  }

  const state = random(32);
  const browserBinding = random(32);
  // The verifier is minted for every provider: both flows accept an S256 challenge (see the PKCE
  // note on `SocialProviderConfig`), so there is no provider-specific branch here to get wrong.
  const codeVerifier = random(32);
  const nonce = provider === "google" ? random(32) : null;
  const codeChallenge = await hash(codeVerifier);

  await createTransaction(db, {
    provider,
    stateHash: await hash(state),
    cookieHash: await hash(browserBinding),
    redirectUri: config.redirectUri,
    codeVerifier,
    nonce,
    link,
    expiresAt: now() + TRANSACTION_TTL_SECONDS,
  });

  return redirect(
    authorizationUrl(config, { state, codeChallenge, nonce }),
    [transactionCookie(provider, browserBinding, TRANSACTION_TTL_SECONDS)],
    302,
  );
}

export async function socialCallback(
  request: Request,
  env: Env,
  url: URL,
  provider: SocialProvider,
): Promise<Response> {
  const origin = env.PUBLIC_ORIGIN || url.origin;
  const config = providerConfig(env, provider, origin);
  const db = requireDb(env);

  // A provider-reported failure (for example the customer cancelled) is recorded as a refusal; the
  // provider's own error text is never reflected back.
  if (url.searchParams.has("error")) throw new HttpError(400, "provider_error");

  // The token exchange always uses the redirect URI registered for this route and stored with the
  // transaction. A callback that supplies any other redirect URI is refused before any transaction
  // is consumed and before the provider is contacted.
  const claimedRedirect = url.searchParams.get("redirect_uri");
  if (claimedRedirect !== null && claimedRedirect !== config.redirectUri)
    throw new HttpError(400, "unexpected_redirect_uri");

  const state = url.searchParams.get("state");
  const binding = cookieValue(request, TRANSACTION_COOKIE_PREFIX + provider);
  if (!state || state.length > 256 || !binding || binding.length > 256)
    throw new HttpError(400, "invalid_state");

  const stateHash = await hash(state);
  const cookieHash = await hash(binding);

  // Which account, if any, this authorization request was started for. Read-only: it decides
  // nothing about consumption. It only tells this callback whether the initiating session has to
  // be re-validated before the row is spent, and lets a refusal below report what it refused.
  const pending = await findTransaction(db, {
    provider,
    stateHash,
    cookieHash,
  });

  const sessionValue = cookieValue(request, SESSION_COOKIE);
  const sessionHash = sessionValue ? await hash(sessionValue) : null;

  if (pending?.linkAccountId) {
    // Linking proves the new identity with this authorization-code flow, and completing it needs
    // the authenticated session that started it: same session, still live, same account. The
    // atomic claim below re-proves that same binding from the row, so these gates can only add a
    // refusal — they are never what decides whether the row is spent, and a refusal here leaves
    // the transaction untouched for the session that does hold it. (`control` is here rather than
    // after the claim precisely so a revoked session cannot spend a row it can no longer use.)
    if (!sessionValue) throw new HttpError(401, "unauthorized");
    const principal = await control(request, env);
    if (principal.tenant !== pending.linkAccountId)
      throw new HttpError(401, "session_mismatch");
    await validateAccountOwnership(env, pending.linkAccountId);
  }

  const transaction = await claimTransaction(db, {
    provider,
    stateHash,
    cookieHash,
    sessionHash,
  });
  if (!transaction) {
    // The predicate matched no row, so nothing was consumed. Re-read to report the reason: a live
    // row for this state and this browser is a session refusal, anything else is a bad state.
    const live = await findTransaction(db, { provider, stateHash, cookieHash });
    if (live?.linkAccountId) throw new HttpError(401, "session_mismatch");
    throw new HttpError(400, "invalid_state");
  }

  const code = url.searchParams.get("code");
  if (!code || code.length > 2048) throw new HttpError(400, "invalid_request");

  const tokens = await exchangeCode(config, {
    code,
    redirectUri: transaction.redirectUri,
    codeVerifier: transaction.codeVerifier,
  });
  const identity = await resolveIdentity(config, tokens, transaction.nonce);
  const input = identityInput(identity);

  if (transaction.linkAccountId) {
    // Never merged by email: the registry only records the provider subject against this account
    // and refuses a subject that already belongs to a different one.
    await linkCustomerIdentity(env, transaction.linkAccountId, input);
    // Linking changes what the session can reach, so the credential is rotated immediately. The
    // replacement is derived from the stored session by the authority; the caller only supplies its
    // digest. The browser keeps the same absolute expiry, so this is rotation, not renewal.
    // `sessionHash` is this request's own digest of the cookie value, and `claimTransaction` only
    // spent the row because it matched the stored binding, so it is the initiating session.
    if (!sessionHash) throw new HttpError(401, "unauthorized");
    const session = await authority<Session | null>(
      env,
      transaction.linkAccountId,
      { op: "get_session", hash: sessionHash },
    );
    if (!session) throw new HttpError(401, "invalid_token");
    const rotated = await rotateOnPrivilegeChange(env, {
      ...session,
      hash: sessionHash,
    } as Principal);
    const cookies = [transactionCookie(provider, "", 0)];
    if (rotated)
      cookies.push(sessionCookie(rotated, Math.max(1, session.exp - now())));
    return redirect(POST_LOGIN_LOCATION, cookies);
  }

  const result = await registerOrLoginCustomer(env, {
    identity: input,
    profile: { name: identity.name, avatarUrl: identity.avatarUrl },
  });
  const session = await signInSession(env, origin, result.account.id);
  return redirect(POST_LOGIN_LOCATION, [
    sessionCookie(session, SESSION_TTL_SECONDS),
    transactionCookie(provider, "", 0),
  ]);
}
