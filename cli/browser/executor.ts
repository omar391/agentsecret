import { exportJWK } from "jose";
import { createSigningPair, restoreSigningPair } from "../keys";
import { signProof } from "../../protocol/dpop";
import {
  executorIdForJwk,
  executorThumbprint as sharedExecutorThumbprint,
} from "../../protocol/executor-id";

export interface ExecutorIdentityRecord {
  version: 1;
  executorId: string;
  createdAt: number;
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
}

export interface PublicExecutorIdentity {
  version: 1;
  executorId: string;
  createdAt: number;
  publicJwk: JsonWebKey;
}

/**
 * Create a browser-executor identity that is separate from agent sessions. The
 * private key is returned only for immediate protected storage; registration
 * and every public value exclude it.
 */
export async function createExecutorIdentity(
  atMilliseconds = Date.now(),
): Promise<ExecutorIdentityRecord> {
  if (!Number.isFinite(atMilliseconds) || atMilliseconds < 0)
    throw new Error("executor_time_invalid");
  const pair = await createSigningPair();
  const [publicJwk, privateJwk] = await Promise.all([
    exportJWK(pair.publicKey),
    exportJWK(pair.privateKey),
  ]);
  return {
    version: 1,
    executorId: await executorIdForJwk(publicJwk),
    createdAt: atMilliseconds,
    publicJwk,
    privateJwk,
  };
}

export async function executorSigningPair(
  record: ExecutorIdentityRecord,
): Promise<CryptoKeyPair> {
  if (record.version !== 1) throw new Error("executor_record_invalid");
  if (typeof record.privateJwk?.d !== "string")
    throw new Error("executor_record_invalid");
  const pair = await restoreSigningPair(record.privateJwk);
  const publicJwk = await exportJWK(pair.publicKey);
  if ((await executorIdForJwk(publicJwk)) !== record.executorId)
    throw new Error("executor_record_invalid");
  return pair;
}

/** Sign one DPoP-bound executor request. */
export async function executorProof(
  record: ExecutorIdentityRecord,
  method: string,
  uri: string,
  accessToken?: string,
  requestHash?: string,
): Promise<string> {
  const pair = await executorSigningPair(record);
  return signProof(pair, method, uri, accessToken, requestHash);
}

/** Registration payload for the Worker; the private key is deliberately absent. */
export function publicExecutorIdentity(
  record: ExecutorIdentityRecord,
): PublicExecutorIdentity {
  return {
    version: 1,
    executorId: record.executorId,
    createdAt: record.createdAt,
    publicJwk: record.publicJwk,
  };
}

export async function executorThumbprint(
  publicJwk: JsonWebKey,
): Promise<string> {
  return sharedExecutorThumbprint(publicJwk);
}
