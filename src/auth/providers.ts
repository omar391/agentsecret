import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from "jose";
import type { Env } from "../types";
import { HttpError, readText } from "../security/primitives";

/**
 * Customer-facing social sign-in providers. These are deliberately separate from the broker's own
 * `/oauth/*` authorization server for agents: nothing here mints or validates an AgentSecret
 * access token, and no provider token is ever handed to a caller.
 */
export type SocialProvider = "github" | "google";

const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token";
const GITHUB_API_URL = "https://api.github.com";

const GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
/** Google documents both spellings as valid issuers for the same identity platform. */
const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"];

export interface SocialProviderConfig {
  provider: SocialProvider;
  clientId: string;
  clientSecret: string;
  authorizeUrl: string;
  tokenUrl: string;
  scopes: string;
  redirectUri: string;
}

/**
 * PKCE, stated once and enforced for every provider rather than silently omitted per provider.
 *
 * Both authorization-code flows this module speaks accept `code_challenge` /
 * `code_challenge_method=S256`, so this flow always sends a challenge on the authorization request
 * and the matching `code_verifier` on the token request — for GitHub and Google alike. The verifier
 * is generated per transaction, stored server-side only (`oauth_transactions.code_verifier`) and
 * sent to nobody but the provider's token endpoint.
 *
 * An earlier revision of this file claimed the opposite for GitHub: that its OAuth App flow
 * "documents no `code_challenge` parameter, so PKCE cannot be used there", and disabled it on that
 * basis. That was stale. GitHub documents S256 for the OAuth app code flow
 * (https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps), and with
 * the challenge switched off a GitHub code minted for authorization request A could be redeemed
 * against transaction B. The wrong belief is recorded here rather than deleted because the
 * mitigation was never "GitHub cannot do PKCE": it is PKCE itself, and stating why it is present
 * is what keeps someone from removing it as unnecessary the next time this file is edited. The
 * single-use, browser-bound `state`, the exact registered `redirect_uri` replayed in the exchange,
 * and the client secret remain as additional bindings; none of them replaces the verifier.
 */
export const PKCE_CHALLENGE_METHOD = "S256";

/**
 * Provider applications are registered outside this deployment, so configuration comes from the
 * environment and the routes fail closed with the existing `501 feature_not_configured` shape when
 * a provider is not configured. A half-configured provider (id without secret, or the reverse) is
 * treated as not configured rather than guessed at.
 */
export function providerConfig(
  env: Env,
  provider: SocialProvider,
  origin: string,
): SocialProviderConfig {
  const [idName, secretName] =
    provider === "github"
      ? ["GITHUB_OAUTH_CLIENT_ID", "GITHUB_OAUTH_CLIENT_SECRET"]
      : ["GOOGLE_OIDC_CLIENT_ID", "GOOGLE_OIDC_CLIENT_SECRET"];
  const clientId = env[idName];
  const clientSecret = env[secretName];
  if (
    typeof clientId !== "string" ||
    typeof clientSecret !== "string" ||
    !clientId.trim() ||
    !clientSecret.trim() ||
    clientId.length > 512 ||
    clientSecret.length > 512
  )
    throw new HttpError(501, "feature_not_configured");
  return {
    provider,
    clientId,
    clientSecret,
    authorizeUrl:
      provider === "github" ? GITHUB_AUTHORIZE_URL : GOOGLE_AUTHORIZE_URL,
    tokenUrl: provider === "github" ? GITHUB_TOKEN_URL : GOOGLE_TOKEN_URL,
    scopes:
      provider === "github" ? "read:user user:email" : "openid email profile",
    redirectUri: `${origin}/auth/${provider}/callback`,
  };
}

export function authorizationUrl(
  config: SocialProviderConfig,
  params: {
    state: string;
    codeChallenge: string;
    nonce: string | null;
  },
): string {
  const url = new URL(config.authorizeUrl);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", config.redirectUri);
  url.searchParams.set("scope", config.scopes);
  url.searchParams.set("state", params.state);
  url.searchParams.set("code_challenge", params.codeChallenge);
  url.searchParams.set("code_challenge_method", PKCE_CHALLENGE_METHOD);
  if (params.nonce) url.searchParams.set("nonce", params.nonce);
  return url.toString();
}

/** A provider response that is not what the flow expects is a refused proof, never a guess. */
async function providerJson(
  url: string,
  init: RequestInit,
): Promise<Record<string, unknown>> {
  let response: Response;
  try {
    response = await fetch(url, {
      ...init,
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new HttpError(502, "provider_unavailable");
  }
  if (response.status >= 500) {
    await response.body?.cancel();
    throw new HttpError(502, "provider_unavailable");
  }
  if (!response.ok) {
    await response.body?.cancel();
    throw new HttpError(401, "invalid_identity_proof");
  }
  let text: string;
  try {
    text = await readText(response, 64 * 1024);
  } catch {
    throw new HttpError(401, "invalid_identity_proof");
  }
  try {
    const value = JSON.parse(text);
    if (!value || typeof value !== "object" || Array.isArray(value))
      throw new Error();
    return value as Record<string, unknown>;
  } catch {
    throw new HttpError(401, "invalid_identity_proof");
  }
}

export interface ExchangedTokens {
  accessToken: string;
  idToken: string | null;
}

/**
 * Redeem the authorization code with the provider. `redirectUri` is the value stored with the
 * transaction, never anything the callback query supplied. The response body carries provider
 * tokens and is never logged, returned or republished: only the two fields below leave this
 * function.
 */
export async function exchangeCode(
  config: SocialProviderConfig,
  input: { code: string; redirectUri: string; codeVerifier: string | null },
): Promise<ExchangedTokens> {
  const form = new URLSearchParams({
    grant_type: "authorization_code",
    code: input.code,
    redirect_uri: input.redirectUri,
    client_id: config.clientId,
    client_secret: config.clientSecret,
  });
  // Every authorization request this flow issues carries an S256 challenge, so a transaction with
  // no verifier is not one of ours and is refused before the provider is contacted.
  if (!input.codeVerifier)
    throw new HttpError(400, "invalid_transaction_state");
  form.set("code_verifier", input.codeVerifier);
  const body = await providerJson(config.tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: form.toString(),
  });
  const accessToken = body.access_token;
  const idToken = body.id_token;
  if (
    typeof accessToken !== "string" ||
    !accessToken ||
    accessToken.length > 8192
  )
    throw new HttpError(401, "invalid_identity_proof");
  if (
    idToken !== undefined &&
    (typeof idToken !== "string" || idToken.length > 16384)
  )
    throw new HttpError(401, "invalid_identity_proof");
  return { accessToken, idToken: idToken ?? null };
}

export interface ProviderIdentity {
  provider: SocialProvider;
  /** Stable provider subject. Never the email, never the login name. */
  subject: string;
  /** Provider email, when the provider supplies one. Metadata only. */
  email: string | null;
  emailVerified: boolean;
  name: string;
  avatarUrl: string;
  login: string | null;
}

function displayName(value: unknown, fallback: string): string {
  if (typeof value !== "string") return fallback;
  const trimmed = value.trim();
  return trimmed.length > 0 && trimmed.length <= 256 ? trimmed : fallback;
}

function avatarUrl(value: unknown): string {
  if (typeof value !== "string" || value.length > 2048) return "";
  try {
    const url = new URL(value);
    return url.protocol === "https:" ? url.toString() : "";
  } catch {
    return "";
  }
}

/**
 * GitHub identity comes from the authenticated API using the exchanged access token. The stable
 * subject is the numeric account id: the login name is mutable and reassignable, and the email is
 * neither stable nor verified, so neither may identify an account.
 */
export async function githubIdentity(
  config: SocialProviderConfig,
  accessToken: string,
): Promise<ProviderIdentity> {
  const user = await providerJson(`${GITHUB_API_URL}/user`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "agentsecret",
    },
  });
  const id = user.id;
  if (typeof id !== "number" || !Number.isSafeInteger(id) || id <= 0)
    throw new HttpError(401, "invalid_identity_proof");
  const login =
    typeof user.login === "string" && user.login.length <= 256
      ? user.login
      : null;

  // The verified primary email is optional profile metadata. Any failure here is tolerated: a
  // missing or unverified provider email must never block an otherwise valid identity.
  let email: string | null = null;
  let emailVerified = false;
  try {
    const addresses = await githubEmails(accessToken);
    const verified = addresses.find((entry) => entry.primary && entry.verified);
    if (verified) {
      email = verified.email;
      emailVerified = true;
    } else {
      email = addresses.find((entry) => entry.email)?.email ?? null;
    }
  } catch {
    email = null;
    emailVerified = false;
  }

  return {
    provider: "github",
    subject: String(id),
    email,
    emailVerified,
    name: displayName(user.name, login ?? "GitHub customer"),
    avatarUrl: avatarUrl(user.avatar_url),
    login,
  };
}

async function githubEmails(
  accessToken: string,
): Promise<{ email: string; primary: boolean; verified: boolean }[]> {
  let response: Response;
  try {
    response = await fetch(`${GITHUB_API_URL}/user/emails`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "agentsecret",
      },
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new HttpError(502, "provider_unavailable");
  }
  if (response.status >= 500) {
    await response.body?.cancel();
    throw new HttpError(502, "provider_unavailable");
  }
  if (!response.ok) {
    await response.body?.cancel();
    throw new HttpError(401, "invalid_identity_proof");
  }
  let value: unknown;
  try {
    value = JSON.parse(await readText(response, 64 * 1024));
  } catch {
    throw new HttpError(401, "invalid_identity_proof");
  }
  if (!Array.isArray(value)) throw new HttpError(401, "invalid_identity_proof");
  return value.flatMap((entry) => {
    if (!entry || typeof entry !== "object") return [];
    const record = entry as Record<string, unknown>;
    if (typeof record.email !== "string" || !record.email) return [];
    return [
      {
        email: record.email.slice(0, 320),
        primary: record.primary === true,
        verified: record.verified === true,
      },
    ];
  });
}

/**
 * Google's OIDC id_token is the identity proof: signature against Google's published keys,
 * issuer, audience (this client), expiry and the nonce this transaction minted. No profile field
 * is read from the callback query, and the access token is not used to fetch a profile, so a
 * substituted userinfo response cannot change who is signed in.
 */
export async function googleIdentity(
  config: SocialProviderConfig,
  idToken: string,
  nonce: string | null,
): Promise<ProviderIdentity> {
  if (!nonce) throw new HttpError(401, "invalid_identity_proof");
  const jwks = await providerJson(GOOGLE_JWKS_URL, {
    headers: { Accept: "application/json" },
  });
  let payload: Record<string, unknown>;
  try {
    const verified = await jwtVerify(
      idToken,
      createLocalJWKSet(jwks as unknown as JSONWebKeySet),
      {
        algorithms: ["RS256"],
        issuer: GOOGLE_ISSUERS,
        audience: config.clientId,
        requiredClaims: ["sub", "iat", "exp", "aud", "iss"],
        clockTolerance: 0,
      },
    );
    payload = verified.payload as Record<string, unknown>;
  } catch {
    throw new HttpError(401, "invalid_identity_proof");
  }
  // OIDC requires `azp` to name this client when the token is issued for more than one audience.
  if (
    Array.isArray(payload.aud) &&
    payload.aud.length > 1 &&
    payload.azp !== config.clientId
  )
    throw new HttpError(401, "invalid_identity_proof");
  if (payload.nonce !== nonce)
    throw new HttpError(401, "invalid_identity_proof");
  const subject = payload.sub;
  if (typeof subject !== "string" || !subject || subject.length > 255)
    throw new HttpError(401, "invalid_identity_proof");

  const email =
    typeof payload.email === "string" && payload.email.length <= 320
      ? payload.email
      : null;
  return {
    provider: "google",
    subject,
    email,
    // Google sends a boolean; anything else (including the string "true") is not treated as a
    // verification claim we would rely on.
    emailVerified: payload.email_verified === true,
    name: displayName(payload.name, email ?? "Google customer"),
    avatarUrl: avatarUrl(payload.picture),
    login: null,
  };
}

export async function resolveIdentity(
  config: SocialProviderConfig,
  tokens: ExchangedTokens,
  nonce: string | null,
): Promise<ProviderIdentity> {
  if (config.provider === "google") {
    if (!tokens.idToken) throw new HttpError(401, "invalid_identity_proof");
    return googleIdentity(config, tokens.idToken, nonce);
  }
  return githubIdentity(config, tokens.accessToken);
}
