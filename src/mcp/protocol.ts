import type {
  BackgroundContext,
  Env,
  JSONRPCRequest,
  SecretPolicy,
  VaultConfig,
} from "../types";
import { SECRET_BODY_PLACEHOLDER } from "../constants";
import { authenticate } from "../security/auth";
import { validateRequestPolicy } from "../security/policy";
import {
  hash,
  HttpError,
  hasUnsafeConnectReferenceCharacter,
  isWellFormedUnicode,
  json,
  random,
} from "../security/primitives";
import { authority } from "../state/authority-kernel";
import { execute, normalize } from "../broker";
import { tools } from "./tools";
import { decryptConfig, type Envelope } from "../vaults/encryption";
import { validateVault } from "../vaults/manager";
import {
  findSecretByLoginSelector,
  findSecretByReference,
  findSecretByTitle,
} from "../vaults/operations";
import { performAgentSecretWrite } from "../vaults/agent-write";
import { parseConnectReference } from "../vaults/onepassword";
import {
  providerCapabilities,
  type ProviderMode,
} from "../vaults/capabilities";
import {
  normalizeNamedSecretLocatorBinding,
  normalizeNamedSecretLocatorInputBinding,
  normalizeLoginLookupLocatorBinding,
  normalizeLoginLookupLocatorInputBinding,
  normalizeSecretRefBinding,
  normalizeSecretRefInputBinding,
  normalizeEnvVarLocatorBinding,
  normalizeEnvVarLocatorInputBinding,
  COMPANION_ONLY_STORES,
  LOCATOR_UNSUPPORTED_STORES,
} from "../../protocol/consumer-bindings";

const PROVIDER_MODE_BY_CONNECTION_TYPE: Record<
  VaultConfig["type"],
  ProviderMode
> = {
  bitwarden: "bitwarden-secrets-manager",
  "bitwarden-password-manager": "bitwarden-password-manager",
  "onepassword-connect": "onepassword-connect",
  "onepassword-service-account": "onepassword-service-account",
  lastpass: "lastpass",
};

const connectionProviderForStore = {
  // The current `bitwarden` connection type is BWS. Bitwarden Password Manager
  // has no distinct connection type yet and must never fall through to BWS.
  "bitwarden-cli": null,
  "bitwarden-secrets-manager": "bitwarden",
  "onepassword-connect": "onepassword-connect",
  "onepassword-service-account": null,
  lastpass: null,
} as const;

function recordValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function hasOnlyArgumentKeys(
  value: unknown,
  allowed: readonly string[],
): boolean {
  const record = recordValue(value);
  return !!record && Object.keys(record).every((key) => allowed.includes(key));
}

export async function mcp(
  request: Request,
  env: Env,
  ctx: BackgroundContext,
  text: string,
): Promise<Response> {
  let message: JSONRPCRequest;
  try {
    message = JSON.parse(text);
  } catch {
    return json(
      {
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: "Parse error" },
      },
      400,
    );
  }
  if (
    !message ||
    Array.isArray(message) ||
    message.jsonrpc !== "2.0" ||
    typeof message.method !== "string" ||
    (message.id !== undefined &&
      message.id !== null &&
      typeof message.id !== "string" &&
      typeof message.id !== "number") ||
    (message.params !== undefined &&
      (!message.params ||
        typeof message.params !== "object" ||
        Array.isArray(message.params)))
  )
    return json(
      {
        jsonrpc: "2.0",
        id: null,
        error: { code: -32600, message: "Invalid request" },
      },
      400,
    );
  const params = message.params || {};
  const proxy =
    message.method === "tools/call" && params.name === "proxy_http_request";
  const bodyBoundDelete =
    message.method === "tools/call" && params.name === "secrets_delete";
  const digest = await hash(text);
  const { principal, proof } = await authenticate(
    request,
    env,
    !proxy,
    proxy || bodyBoundDelete ? digest : undefined,
  );
  if (message.id === undefined) return new Response(null, { status: 202 });
  let result: unknown;
  switch (message.method) {
    case "initialize":
      result = {
        protocolVersion: "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name: "agentsecret", version: "3.0.0" },
        instructions:
          "Use aliases for authorized broker operations. Strict mode does not export credentials to local commands.",
      };
      break;
    case "ping":
      result = {};
      break;
    case "tools/list":
      result = { tools };
      break;
    case "tools/call": {
      try {
        const args = params.arguments === undefined ? {} : params.arguments;
        if (!recordValue(args))
          throw new HttpError(400, "invalid_tool_arguments");
        let value: unknown;
        if (params.name === "list_available_secrets") {
          if (!hasOnlyArgumentKeys(args, []))
            throw new HttpError(400, "invalid_tool_arguments");
          const policies = await authority<
            Array<{
              alias: string;
              description: string;
              allowedDomains: string[];
              allowedMethods: string[];
              injectionType: SecretPolicy["injectionType"];
              headerName?: string;
              queryParamName?: string;
              connectionId?: string;
              connectionRevision?: number;
              secretWrite?: {
                create?: boolean;
                update?: boolean;
                delete?: boolean;
              };
            }>
          >(env, principal.tenant, {
            op: "policies",
            principal,
          });
          const connections = await authority<
            Array<{
              alias: string;
              id: string;
              provider: VaultConfig["type"];
              revision: number;
            }>
          >(env, principal.tenant, {
            op: "agent_connections",
            principal,
          });
          const connectionsByAlias = new Map(
            connections.map((connection) => [connection.alias, connection]),
          );
          const canSeeOwnerWriteGrants =
            principal.scopes.includes("secrets:write") ||
            principal.scopes.includes("admin");
          value = {
            available_secrets: policies.map((policy) => {
              const connection = policy.connectionId
                ? connectionsByAlias.get(policy.alias)
                : undefined;
              const boundConnection =
                connection?.id === policy.connectionId ? connection : undefined;
              const providerMode = boundConnection
                ? PROVIDER_MODE_BY_CONNECTION_TYPE[boundConnection.provider]
                : undefined;
              const connectionIsCurrent =
                !!providerMode &&
                boundConnection?.revision === policy.connectionRevision;
              const capabilities = connectionIsCurrent
                ? providerCapabilities(providerMode)
                : undefined;
              const companionBinding =
                connectionIsCurrent &&
                capabilities?.status === "requires-companion" &&
                boundConnection
                  ? {
                      connection_id: boundConnection.id,
                      connection_revision: boundConnection.revision,
                    }
                  : undefined;
              return {
                alias: policy.alias,
                description: policy.description,
                allowedDomains: policy.allowedDomains,
                allowedMethods: policy.allowedMethods,
                credential_sink:
                  policy.injectionType === "header"
                    ? { type: "header", name: policy.headerName }
                    : policy.injectionType === "query_param"
                      ? {
                          type: "query_param",
                          name: policy.queryParamName,
                        }
                      : policy.injectionType === "body_placeholder"
                        ? {
                            type: "body_placeholder",
                            marker: SECRET_BODY_PLACEHOLDER,
                          }
                        : { type: policy.injectionType },
                connection_status: connectionIsCurrent
                  ? "ready"
                  : policy.connectionId
                    ? "unavailable"
                    : "unbound",
                ...(connectionIsCurrent && providerMode && capabilities
                  ? {
                      provider_mode: providerMode,
                      provider_capabilities: {
                        status: capabilities.status,
                        read: capabilities.read,
                        create: capabilities.create,
                        update: capabilities.update,
                        conditional_update: capabilities.conditionalUpdate,
                        verify_after_write: capabilities.verifyAfterWrite,
                        delete: capabilities.delete,
                        reason: capabilities.reason,
                      },
                      ...(companionBinding
                        ? { companion_binding: companionBinding }
                        : {}),
                    }
                  : {}),
                ...(canSeeOwnerWriteGrants && policy.secretWrite
                  ? {
                      owner_write_grant: {
                        create: policy.secretWrite.create === true,
                        update: policy.secretWrite.update === true,
                        delete: policy.secretWrite.delete === true,
                      },
                    }
                  : {}),
              };
            }),
          };
        } else if (params.name === "secrets_find") {
          const findArgs = args as {
            secret_alias?: unknown;
            store?: unknown;
            reference?: unknown;
            binding?: unknown;
            input_ref?: unknown;
            input_locator?: unknown;
            selector?: unknown;
          };
          const alias = findArgs.secret_alias;
          const requestedSelector = findArgs.selector;
          const directBinding =
            findArgs.binding === undefined
              ? undefined
              : normalizeSecretRefBinding(findArgs.binding);
          const inputBindingValue = recordValue(
            findArgs.binding,
          )?.secret_ref_input;
          const inputName =
            typeof inputBindingValue === "string"
              ? inputBindingValue
              : recordValue(inputBindingValue)?.name;
          const normalizedInputName =
            typeof inputName === "string" ? inputName.trim() : undefined;
          const inputBinding =
            findArgs.binding === undefined
              ? undefined
              : normalizeSecretRefInputBinding(
                  findArgs.binding,
                  typeof normalizedInputName === "string" &&
                    findArgs.input_ref !== undefined
                    ? { [normalizedInputName]: findArgs.input_ref }
                    : undefined,
                );
          const binding = directBinding ?? inputBinding;
          const namedSecretBinding =
            findArgs.binding === undefined
              ? undefined
              : normalizeNamedSecretLocatorBinding(findArgs.binding);
          const inputLocatorBindingValue = recordValue(
            findArgs.binding,
          )?.secret_locator_input;
          const inputLocatorName =
            typeof inputLocatorBindingValue === "string"
              ? inputLocatorBindingValue.trim()
              : typeof recordValue(inputLocatorBindingValue)?.name === "string"
                ? (recordValue(inputLocatorBindingValue)?.name as string).trim()
                : undefined;
          const namedSecretInputBinding =
            findArgs.binding === undefined
              ? undefined
              : normalizeNamedSecretLocatorInputBinding(
                  findArgs.binding,
                  typeof inputLocatorName === "string" &&
                    findArgs.input_locator !== undefined
                    ? { [inputLocatorName]: findArgs.input_locator }
                    : undefined,
                );
          const directLoginLookupBinding =
            findArgs.binding === undefined
              ? undefined
              : normalizeLoginLookupLocatorBinding(findArgs.binding);
          const effectiveLoginLookupBinding =
            directLoginLookupBinding ??
            normalizeLoginLookupLocatorInputBinding(
              findArgs.binding,
              typeof inputLocatorName === "string" &&
                findArgs.input_locator !== undefined
                ? { [inputLocatorName]: findArgs.input_locator }
                : undefined,
            );
          const effectiveNamedSecretBinding =
            namedSecretBinding ?? namedSecretInputBinding;
          const directEnvVarBinding =
            findArgs.binding === undefined
              ? undefined
              : normalizeEnvVarLocatorBinding(findArgs.binding);
          const envVarInputBinding =
            findArgs.binding === undefined
              ? undefined
              : normalizeEnvVarLocatorInputBinding(
                  findArgs.binding,
                  typeof inputLocatorName === "string" &&
                    findArgs.input_locator !== undefined
                    ? { [inputLocatorName]: findArgs.input_locator }
                    : undefined,
                );
          const effectiveEnvVarBinding =
            directEnvVarBinding ?? envVarInputBinding;
          let selector =
            effectiveNamedSecretBinding && requestedSelector === undefined
              ? { title: effectiveNamedSecretBinding.name }
              : requestedSelector;
          const bindingStore =
            binding?.store ??
            effectiveNamedSecretBinding?.store ??
            effectiveLoginLookupBinding?.store;
          const validSelector = (() => {
            if (
              !selector ||
              typeof selector !== "object" ||
              Array.isArray(selector)
            )
              return false;
            const value = selector as Record<string, unknown>;
            if (
              typeof value.title !== "string" ||
              !value.title.trim() ||
              value.title.length > 128 ||
              /[\u0000-\u001f\u007f]/.test(value.title) ||
              hasUnsafeConnectReferenceCharacter(value.title)
            )
              return false;
            if (value.kind === undefined) {
              return (
                Object.keys(value).every((key) =>
                  ["title", "fieldId"].includes(key),
                ) &&
                (value.fieldId === undefined ||
                  (typeof value.fieldId === "string" &&
                    !!value.fieldId.trim() &&
                    value.fieldId.length <= 256 &&
                    !/[\u0000-\u001f\u007f]/.test(value.fieldId)))
              );
            }
            return (
              value.kind === "login_lookup" &&
              Object.keys(value).every((key) =>
                [
                  "kind",
                  "title",
                  "username",
                  "uris",
                  "fieldId",
                  "fieldPath",
                ].includes(key),
              ) &&
              typeof value.username === "string" &&
              !!value.username.trim() &&
              value.username.length <= 512 &&
              !/[\u0000-\u001f\u007f]/.test(value.username) &&
              !hasUnsafeConnectReferenceCharacter(value.username) &&
              Array.isArray(value.uris) &&
              value.uris.length > 0 &&
              value.uris.length <= 16 &&
              value.uris.every(
                (uri) =>
                  typeof uri === "string" &&
                  !!uri.trim() &&
                  uri.length <= 2048 &&
                  !/[\u0000-\u001f\u007f]/.test(uri) &&
                  !hasUnsafeConnectReferenceCharacter(uri as string),
              ) &&
              new Set(value.uris).size === value.uris.length &&
              typeof value.fieldId === "string" &&
              !!value.fieldId.trim() &&
              value.fieldId.length <= 256 &&
              !/[\u0000-\u001f\u007f]/.test(value.fieldId) &&
              (value.fieldPath === undefined ||
                (typeof value.fieldPath === "string" &&
                  !!value.fieldPath.trim() &&
                  value.fieldPath.length <= 256 &&
                  !/[\u0000-\u001f\u007f]/.test(value.fieldPath)))
            );
          })();
          if (
            typeof alias !== "string" ||
            !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(alias) ||
            !Object.keys(args as object).every((key) =>
              [
                "secret_alias",
                "store",
                "reference",
                "binding",
                "input_ref",
                "input_locator",
                "selector",
              ].includes(key),
            ) ||
            (findArgs.store !== undefined &&
              (typeof findArgs.store !== "string" ||
                !Object.hasOwn(connectionProviderForStore, findArgs.store))) ||
            (findArgs.reference !== undefined && selector !== undefined) ||
            (findArgs.binding !== undefined &&
              ((binding == null &&
                effectiveNamedSecretBinding == null &&
                effectiveLoginLookupBinding == null &&
                effectiveEnvVarBinding == null) ||
                findArgs.reference !== undefined ||
                (requestedSelector !== undefined &&
                  ((effectiveNamedSecretBinding !== null &&
                    effectiveNamedSecretBinding !== undefined) ||
                    (effectiveLoginLookupBinding !== null &&
                      effectiveLoginLookupBinding !== undefined))) ||
                (findArgs.input_ref !== undefined &&
                  directBinding !== null &&
                  directBinding !== undefined) ||
                (findArgs.input_locator !== undefined &&
                  ((namedSecretBinding !== null &&
                    namedSecretBinding !== undefined) ||
                    (directLoginLookupBinding !== null &&
                      directLoginLookupBinding !== undefined))) ||
                (findArgs.store !== undefined &&
                  findArgs.store !== bindingStore))) ||
            (findArgs.input_ref !== undefined &&
              (findArgs.binding === undefined || inputBinding == null)) ||
            (findArgs.input_locator !== undefined &&
              (findArgs.binding === undefined ||
                (namedSecretInputBinding == null &&
                  effectiveLoginLookupBinding == null &&
                  envVarInputBinding == null))) ||
            (findArgs.input_ref !== undefined &&
              findArgs.input_locator !== undefined) ||
            (findArgs.reference !== undefined &&
              (typeof findArgs.reference !== "string" ||
                !findArgs.reference.trim() ||
                findArgs.reference !== findArgs.reference.trim() ||
                findArgs.reference.length > 1024 ||
                /[\u0000-\u001f\u007f]/.test(findArgs.reference))) ||
            (binding?.store === "onepassword-connect" &&
              binding.reference === undefined) ||
            (selector !== undefined && !validSelector)
          )
            throw new HttpError(400, "invalid_secret_find_request");
          if (effectiveEnvVarBinding)
            throw new HttpError(409, "local_only_env_var");
          if (binding && COMPANION_ONLY_STORES.has(binding.store))
            throw new HttpError(409, "secret_store_unavailable");
          if (
            (effectiveNamedSecretBinding &&
              COMPANION_ONLY_STORES.has(effectiveNamedSecretBinding.store)) ||
            (effectiveLoginLookupBinding &&
              COMPANION_ONLY_STORES.has(effectiveLoginLookupBinding.store))
          )
            throw new HttpError(409, "secret_store_unavailable");
          if (
            (effectiveNamedSecretBinding &&
              ((LOCATOR_UNSUPPORTED_STORES.has(
                effectiveNamedSecretBinding.store,
              ) &&
                !COMPANION_ONLY_STORES.has(
                  effectiveNamedSecretBinding.store,
                )) ||
                (effectiveNamedSecretBinding.fieldPath !== null &&
                  effectiveNamedSecretBinding.fieldPath !== ""))) ||
            (effectiveLoginLookupBinding &&
              ((LOCATOR_UNSUPPORTED_STORES.has(
                effectiveLoginLookupBinding.store,
              ) &&
                !COMPANION_ONLY_STORES.has(
                  effectiveLoginLookupBinding.store,
                )) ||
                (effectiveLoginLookupBinding.fieldPath !== null &&
                  effectiveLoginLookupBinding.fieldPath !== "")))
          )
            throw new HttpError(409, "secret_binding_unsupported");
          const authorized = await authority<{
            policy: {
              secretId?: string;
              findSelector?: import("../types").SecretFindSelector;
            };
            vault: Envelope | null;
            connection?: {
              id: string;
              revision: number;
              provider: string;
              envelope: Envelope;
            } | null;
          }>(env, principal.tenant, {
            op: "inspect_secret",
            principal,
            alias: alias.toUpperCase(),
          });
          if (!authorized.policy.secretId)
            throw new HttpError(400, "explicit_secret_reference_required");
          if (
            findArgs.reference !== undefined &&
            findArgs.reference !== authorized.policy.secretId
          )
            throw new HttpError(403, "secret_reference_forbidden");
          if (effectiveLoginLookupBinding) {
            const policySelector = authorized.policy.findSelector;
            const sameUris =
              policySelector &&
              "kind" in policySelector &&
              policySelector.kind === "login_lookup" &&
              effectiveLoginLookupBinding.uris.length ===
                policySelector.uris.length &&
              new Set(effectiveLoginLookupBinding.uris).size ===
                effectiveLoginLookupBinding.uris.length &&
              effectiveLoginLookupBinding.uris.every((uri) =>
                policySelector.uris.includes(uri),
              );
            if (
              !policySelector ||
              !("kind" in policySelector) ||
              policySelector.kind !== "login_lookup" ||
              policySelector.username !==
                effectiveLoginLookupBinding.username ||
              !sameUris
            )
              throw new HttpError(403, "secret_selector_forbidden");
            selector = policySelector;
          }
          if (
            binding &&
            binding.store === "bitwarden-secrets-manager" &&
            (binding.fieldPath === null || binding.fieldPath === "") &&
            binding.objectId !== authorized.policy.secretId
          )
            throw new HttpError(403, "secret_reference_forbidden");
          if (
            binding &&
            binding.store === "onepassword-connect" &&
            binding.reference !== authorized.policy.secretId
          )
            throw new HttpError(403, "secret_reference_forbidden");
          if (binding?.store === "bitwarden-secrets-manager") {
            if (binding.fieldPath !== null && binding.fieldPath !== "")
              throw new HttpError(409, "secret_binding_unsupported");
          }
          if (selector !== undefined) {
            const policySelector = authorized.policy.findSelector;
            const supplied = selector as Record<string, unknown>;
            const selectorMatches =
              policySelector &&
              ("kind" in policySelector &&
              policySelector.kind === "login_lookup"
                ? supplied.kind === "login_lookup" &&
                  supplied.title === policySelector.title &&
                  supplied.username === policySelector.username &&
                  supplied.fieldId === policySelector.fieldId &&
                  supplied.fieldPath === policySelector.fieldPath &&
                  Array.isArray(supplied.uris) &&
                  supplied.uris.length === policySelector.uris.length &&
                  new Set(supplied.uris).size === supplied.uris.length &&
                  supplied.uris.every((uri) =>
                    policySelector.uris.includes(uri),
                  )
                : supplied.kind === undefined &&
                  supplied.title === policySelector.title &&
                  (supplied.fieldId === undefined ||
                    supplied.fieldId === policySelector.fieldId));
            if (!selectorMatches)
              throw new HttpError(403, "secret_selector_forbidden");
          }
          const connection = authorized.connection || undefined;
          const envelope = connection?.envelope || authorized.vault;
          if (!envelope) throw new HttpError(503, "vault_not_connected");
          const config = validateVault(
            await decryptConfig(
              envelope,
              principal.tenant,
              env,
              connection
                ? {
                    accountId: principal.tenant,
                    connectionId: connection.id,
                    revision: connection.revision,
                  }
                : undefined,
            ),
          );
          if (connection && config.type !== connection.provider)
            throw new HttpError(409, "vault_connection_changed");
          const requestedStore = bindingStore ?? findArgs.store;
          if (requestedStore !== undefined) {
            const expectedConnectionProvider =
              connectionProviderForStore[
                requestedStore as keyof typeof connectionProviderForStore
              ];
            if (expectedConnectionProvider === null)
              throw new HttpError(409, "secret_store_unavailable");
            if (binding?.store === "onepassword-connect") {
              if (
                !connection ||
                connection.provider !== expectedConnectionProvider
              )
                throw new HttpError(403, "secret_store_mismatch");
            } else if (
              !connection ||
              connection.provider !== expectedConnectionProvider
            )
              throw new HttpError(403, "secret_store_mismatch");
          }
          if (
            binding &&
            binding.store !== "bitwarden-secrets-manager" &&
            binding.store !== "onepassword-connect" &&
            !COMPANION_ONLY_STORES.has(binding.store)
          ) {
            throw new HttpError(409, "secret_binding_unsupported");
          }
          await authority(env, principal.tenant, {
            op: "rate",
            key:
              "mcp-secret-find:" + principal.tenant + ":" + alias.toUpperCase(),
            limit: 20,
          });
          if (authorized.policy.findSelector) {
            const selected =
              "kind" in authorized.policy.findSelector &&
              authorized.policy.findSelector.kind === "login_lookup"
                ? await findSecretByLoginSelector(
                    config,
                    authorized.policy.findSelector,
                  )
                : await findSecretByTitle(
                    config,
                    authorized.policy.findSelector.title,
                    authorized.policy.findSelector.fieldId,
                  );
            if (selected.reference !== authorized.policy.secretId)
              throw new HttpError(409, "secret_selector_changed");
            value = selected;
          } else {
            value = await findSecretByReference(
              config,
              authorized.policy.secretId,
            );
          }
        } else if (params.name === "secrets_delete") {
          const deleteArgs = args as {
            secret_alias?: unknown;
            operation_id?: unknown;
            reference?: unknown;
          };
          if (
            Object.keys(args as object)
              .sort()
              .join(",") !== "operation_id,reference,secret_alias" ||
            typeof deleteArgs.secret_alias !== "string" ||
            !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(deleteArgs.secret_alias) ||
            typeof deleteArgs.operation_id !== "string" ||
            !/^[A-Za-z0-9_-]{20,128}$/.test(deleteArgs.operation_id) ||
            typeof deleteArgs.reference !== "string" ||
            deleteArgs.reference !== deleteArgs.reference.trim() ||
            !deleteArgs.reference.trim() ||
            deleteArgs.reference.length > 1024 ||
            !isWellFormedUnicode(deleteArgs.reference) ||
            hasUnsafeConnectReferenceCharacter(deleteArgs.reference) ||
            /[\u0000-\u001f\u007f]/.test(deleteArgs.reference)
          )
            throw new HttpError(400, "invalid_secret_save_request");
          let connectReference = false;
          try {
            connectReference =
              parseConnectReference(deleteArgs.reference) !== null;
          } catch {}
          if (
            !connectReference &&
            !/^[A-Za-z0-9_-]{1,128}#\/fields\/[A-Za-z0-9_-]{1,128}$/.test(
              deleteArgs.reference,
            )
          )
            throw new HttpError(400, "invalid_connect_reference");
          const alias = deleteArgs.secret_alias.toUpperCase();
          await authority(env, principal.tenant, {
            op: "rate",
            key: "mcp-secret-delete:" + principal.tenant + ":" + alias,
            limit: 20,
          });
          const authorized = await authority<{
            connection: { provider: string };
          }>(env, principal.tenant, {
            op: "authorize_secret_write",
            principal,
            alias,
            intent: "delete",
          });
          if (
            authorized.connection.provider === "onepassword-service-account"
          ) {
            const prepared = await authority<{
              status: string;
              requestId: string;
              reference?: string;
              verified?: true;
            }>(env, principal.tenant, {
              op: "prepare_private_input",
              principal,
              requestId: random(32),
              operationId: deleteArgs.operation_id,
              alias,
              intent: "delete",
              target: deleteArgs.reference,
            });
            value =
              prepared.status === "saved"
                ? {
                    status: "deleted",
                    reference: prepared.reference,
                    verified: prepared.verified === true,
                    replayed: true,
                  }
                : prepared.status === "unknown"
                  ? {
                      status: "outcome_unknown",
                      requestId: prepared.requestId,
                    }
                  : prepared.status === "rejected"
                    ? { status: "rejected" }
                    : prepared.status === "expired"
                      ? { status: "expired" }
                      : {
                          status: "owner_input_required",
                          requestId: prepared.requestId,
                        };
          } else {
            value = await performAgentSecretWrite(
              principal,
              {
                alias,
                operationId: deleteArgs.operation_id,
                reference: deleteArgs.reference,
              },
              "delete",
              env,
            );
          }
        } else if (params.name === "secrets_save") {
          const saveArgs = args as {
            secret_alias?: unknown;
            operation_id?: unknown;
            intent?: unknown;
            title?: unknown;
            reference?: unknown;
          };
          const intent = saveArgs.intent;
          const target =
            intent === "create" ? saveArgs.title : saveArgs.reference;
          const expectedKeys =
            intent === "create"
              ? "intent,operation_id,secret_alias,title"
              : "intent,operation_id,reference,secret_alias";
          if (
            Object.keys(args as object)
              .sort()
              .join(",") !== expectedKeys ||
            typeof saveArgs.secret_alias !== "string" ||
            !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(saveArgs.secret_alias) ||
            typeof saveArgs.operation_id !== "string" ||
            !/^[A-Za-z0-9_-]{20,128}$/.test(saveArgs.operation_id) ||
            !["create", "update", "ensure"].includes(String(intent)) ||
            typeof target !== "string" ||
            target !== target.trim() ||
            !target.trim() ||
            !isWellFormedUnicode(target) ||
            hasUnsafeConnectReferenceCharacter(target) ||
            target.length > (intent === "create" ? 128 : 1024) ||
            /[\u0000-\u001f\u007f]/.test(target)
          )
            throw new HttpError(400, "invalid_secret_save_request");
          const alias = saveArgs.secret_alias.toUpperCase();
          if (intent !== "create") {
            let connectReference = false;
            try {
              connectReference = parseConnectReference(target) !== null;
            } catch {}
            if (
              !connectReference &&
              !/^[A-Za-z0-9_-]{1,128}#\/fields\/[A-Za-z0-9_-]{1,128}$/.test(
                target,
              )
            )
              throw new HttpError(400, "invalid_connect_reference");
          }
          await authority(env, principal.tenant, {
            op: "rate",
            key: "mcp-private-input:" + principal.tenant + ":" + alias,
            limit: 20,
          });
          const prepared = await authority<{
            status: string;
            requestId: string;
            reference?: string;
            verified?: true;
            resultStatus?: "unchanged" | "updated";
          }>(env, principal.tenant, {
            op: "prepare_private_input",
            principal,
            requestId: random(32),
            operationId: saveArgs.operation_id,
            alias,
            intent,
            target,
          });
          value =
            prepared.status === "saved"
              ? {
                  status:
                    intent === "ensure"
                      ? prepared.resultStatus
                      : intent === "update"
                        ? "updated"
                        : "created",
                  requestId: prepared.requestId,
                  reference: prepared.reference,
                  verified: prepared.verified === true,
                  replayed: true,
                }
              : prepared.status === "unknown"
                ? {
                    status: "outcome_unknown",
                    requestId: prepared.requestId,
                  }
                : prepared.status === "rejected"
                  ? { status: "rejected" }
                  : prepared.status === "expired"
                    ? { status: "expired" }
                    : {
                        status: "owner_input_required",
                        requestId: prepared.requestId,
                      };
        } else if (params.name === "proxy_http_request") {
          if (
            !hasOnlyArgumentKeys(args, [
              "secret_alias",
              "url",
              "method",
              "headers",
              "body",
            ])
          )
            throw new HttpError(400, "invalid_tool_arguments");
          value = await execute(args, principal, proof, digest, env, ctx);
        } else if (params.name === "prepare_local_execution") {
          if (!hasOnlyArgumentKeys(args, ["secret_alias", "url"]))
            throw new HttpError(400, "invalid_tool_arguments");
          const normalized = normalize({ ...(args as object), method: "GET" });
          const policies = await authority<SecretPolicy[]>(
            env,
            principal.tenant,
            { op: "policies", principal },
          );
          const policy = policies.find(
            (candidate) => candidate.alias === normalized.secret_alias,
          );
          if (!policy) throw new HttpError(403, "alias_forbidden");
          if (!validateRequestPolicy(policy, normalized.url, "GET").isValid)
            throw new HttpError(403, "policy_denied");
          value = {
            execution: "local",
            program: "agentsecret",
            argv: [
              "request",
              "--alias",
              normalized.secret_alias,
              "--url",
              normalized.url,
            ],
            requires:
              "An authenticated local companion. Execute argv with your own local tool; the cloud does not execute it.",
          };
        } else
          return json({
            jsonrpc: "2.0",
            id: message.id,
            error: { code: -32601, message: "Unknown tool" },
          });
        result = { content: [{ type: "text", text: JSON.stringify(value) }] };
      } catch (error) {
        result = {
          isError: true,
          content: [
            {
              type: "text",
              text:
                error instanceof HttpError ? error.code : "operation_failed",
            },
          ],
        };
      }
      break;
    }
    default:
      return json({
        jsonrpc: "2.0",
        id: message.id,
        error: { code: -32601, message: "Method not found" },
      });
  }
  return json({ jsonrpc: "2.0", id: message.id, result });
}
