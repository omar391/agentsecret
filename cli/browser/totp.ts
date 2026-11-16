import { createHmac, timingSafeEqual } from "node:crypto";

export interface TotpOptions {
  digits?: number;
  periodSeconds?: number;
  algorithm?: "sha1" | "sha256" | "sha512";
}

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Decode an RFC 4648 base32 secret without padding. Never accepts whitespace. */
export function decodeBase32(secret: string): Buffer {
  if (typeof secret !== "string" || secret.length === 0)
    throw new Error("totp_secret_invalid");
  const normalized = secret.toUpperCase();
  let bits = 0;
  let value = 0;
  const output: number[] = [];
  for (const character of normalized) {
    const index = BASE32_ALPHABET.indexOf(character);
    if (index < 0) throw new Error("totp_secret_invalid");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((value >>> bits) & 0xff);
    }
  }
  if (output.length === 0) throw new Error("totp_secret_invalid");
  return Buffer.from(output);
}

function hotp(
  key: Buffer,
  counter: bigint,
  digits: number,
  algorithm: TotpOptions["algorithm"],
): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(counter);
  const digest = createHmac(algorithm ?? "sha1", key)
    .update(message)
    .digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % 10 ** digits).padStart(digits, "0");
}

/**
 * Generate one RFC 6238 code for the exact clock sample. The result is never
 * cached; callers must compute it at the authorized use and discard it.
 */
export function generateTotp(
  secret: string,
  atMilliseconds: number,
  options: TotpOptions = {},
): string {
  const digits = options.digits ?? 6;
  const period = options.periodSeconds ?? 30;
  if (!Number.isInteger(digits) || digits < 6 || digits > 8)
    throw new Error("totp_digits_invalid");
  if (!Number.isInteger(period) || period < 1 || period > 300)
    throw new Error("totp_period_invalid");
  if (!Number.isFinite(atMilliseconds) || atMilliseconds < 0)
    throw new Error("totp_time_invalid");
  const key = decodeBase32(secret);
  const counter = BigInt(Math.floor(atMilliseconds / 1000 / period));
  return hotp(key, counter, digits, options.algorithm);
}

/** Compare a supplied code without leaking timing information. */
export function totpMatches(expected: string, supplied: string): boolean {
  const left = Buffer.from(expected, "utf8");
  const right = Buffer.from(supplied, "utf8");
  return left.length === right.length && timingSafeEqual(left, right);
}
