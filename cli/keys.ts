import { importJWK } from "jose";

export async function createSigningPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  ) as Promise<CryptoKeyPair>;
}

export async function restoreSigningPair(
  privateJwk: JsonWebKey,
): Promise<CryptoKeyPair> {
  const publicJwk: JsonWebKey = { ...privateJwk };
  delete publicJwk.d;
  publicJwk.key_ops = ["verify"];
  const [privateKey, publicKey] = await Promise.all([
    importJWK(privateJwk, "ES256"),
    importJWK(publicJwk, "ES256"),
  ]);
  return {
    privateKey: privateKey as CryptoKey,
    publicKey: publicKey as CryptoKey,
  };
}

export async function signingPairForLogin(
  server: string,
  existingServer: string | undefined,
  readExistingKey: () => JsonWebKey,
): Promise<CryptoKeyPair> {
  if (existingServer === server) return restoreSigningPair(readExistingKey());
  return createSigningPair();
}
