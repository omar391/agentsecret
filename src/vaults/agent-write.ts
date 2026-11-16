import type { Env, Principal } from "../types";
import { authority } from "../state/authority-kernel";
import { hash, HttpError, isWellFormedUnicode } from "../security/primitives";
import { decryptConfig } from "./encryption";
import { referenceContainsValue, validateVault } from "./manager";
import { writeSecret } from "./operations";
import { parseConnectReference } from "./onepassword";

export type AgentSecretWriteIntent = "create" | "update" | "delete";

/** Shared agent/MCP write authorization, durable admission, mutation, and receipt path. */
export async function performAgentSecretWrite(
  principal: Principal,
  input: Record<string, unknown>,
  intent: AgentSecretWriteIntent,
  env: Env,
): Promise<{
  status: "created" | "updated" | "deleted";
  reference: string;
  verified: true;
  replayed: boolean;
}> {
  const expectedKeys =
    intent === "create"
      ? "alias,operationId,title,value"
      : intent === "delete"
        ? "alias,operationId,reference"
        : "alias,operationId,reference,value";
  if (Object.keys(input).sort().join(",") !== expectedKeys)
    throw new HttpError(400, "invalid_secret_save_request");
  if (principal.purpose !== "agent")
    throw new HttpError(403, "agent_session_required");
  const alias = input.alias;
  const operationId = input.operationId;
  const target = intent === "create" ? input.title : input.reference;
  const value = intent === "delete" ? undefined : input.value;
  if (
    typeof alias !== "string" ||
    !/^[A-Z][A-Z0-9_]{0,63}$/.test(alias) ||
    typeof operationId !== "string" ||
    !/^[A-Za-z0-9_-]{20,128}$/.test(operationId) ||
    typeof target !== "string" ||
    !target.trim() ||
    !isWellFormedUnicode(target) ||
    target.length > (intent === "create" ? 128 : 1024) ||
    /[\u0000-\u001f\u007f]/.test(target) ||
    (intent !== "delete" &&
      (typeof value !== "string" ||
        !isWellFormedUnicode(value) ||
        !value.length ||
        value.length > 8192))
  )
    throw new HttpError(400, "invalid_secret_save_request");
  if (intent !== "create") parseConnectReference(target);
  const authorized = await authority<any>(env, principal.tenant, {
    op: "authorize_secret_write",
    principal,
    alias,
    intent,
  });
  const { policy, connection } = authorized;
  if (intent !== "create" && target !== policy.secretId)
    throw new HttpError(403, "secret_write_reference_forbidden");
  if (connection.provider !== "onepassword-connect")
    throw new HttpError(409, "provider_write_unsupported");
  const config = validateVault(
    await decryptConfig(connection.envelope, principal.tenant, env, {
      accountId: principal.tenant,
      connectionId: connection.id,
      revision: connection.revision,
    }),
  );
  if (config.type !== "onepassword-connect")
    throw new HttpError(409, "provider_write_unsupported");
  if (intent === "update" && referenceContainsValue(target, value as string))
    throw new HttpError(409, "secret_reference_not_safe");
  const payloadDigest =
    value === undefined ? undefined : await hash(value as string);
  const reservation = await authority<any>(env, principal.tenant, {
    op: "reserve_secret_save",
    principal,
    alias,
    operationId,
    connectionId: connection.id,
    revision: connection.revision,
    title: target,
    intent,
    payloadDigest,
  });
  const status =
    intent === "delete"
      ? "deleted"
      : intent === "update"
        ? "updated"
        : "created";
  if (reservation.status === "saved") {
    if (reservation.legacyBinding)
      throw new HttpError(409, "secret_save_operation_conflict");
    const reference = reservation.reference || "";
    if (
      !reservation.verified ||
      (intent === "delete" && reference !== target) ||
      (value !== undefined &&
        referenceContainsValue(reference, value as string))
    )
      throw new HttpError(409, "save_outcome_unknown");
    return { status, reference, verified: true, replayed: true };
  }
  if (reservation.status !== "reserved")
    throw new HttpError(
      409,
      reservation.status === "unknown"
        ? "save_outcome_unknown"
        : "save_in_progress",
    );
  try {
    const receipt = await writeSecret(
      config,
      intent,
      target,
      value as string | undefined,
    );
    const completed = await authority<any>(env, principal.tenant, {
      op: "complete_secret_save",
      principal,
      operationId,
      status: "saved",
      reference: receipt.reference,
      verified: receipt.verified,
    });
    return {
      status,
      reference: completed.reference,
      verified: true,
      replayed: false,
    };
  } catch {
    try {
      await authority(env, principal.tenant, {
        op: "complete_secret_save",
        principal,
        operationId,
        status: "unknown",
      });
    } catch {
      /* Preserve the reservation when an unknown result cannot be recorded. */
    }
    throw new HttpError(503, "save_outcome_unknown");
  }
}
