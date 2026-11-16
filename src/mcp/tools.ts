const secretRefValueSchema = {
  type: "object",
  properties: {
    type: { type: "string", enum: ["secret_ref", "secret-ref"] },
    store: {
      type: "string",
      enum: [
        "bitwarden-cli",
        "bitwarden-secrets-manager",
        "onepassword-connect",
        "onepassword-service-account",
        "lastpass",
      ],
    },
    object_id: { type: "string", minLength: 1, maxLength: 1024 },
    objectId: { type: "string", minLength: 1, maxLength: 1024 },
    field_path: { type: ["string", "null"], maxLength: 1024 },
    fieldPath: { type: ["string", "null"], maxLength: 1024 },
  },
  anyOf: [{ required: ["object_id"] }, { required: ["objectId"] }],
  additionalProperties: false,
};

export const tools = [
  {
    name: "list_available_secrets",
    description:
      "List permitted aliases, destination/method policies, owner-selected credential sinks, and current provider capability metadata for policy-bound connections. Body-placeholder aliases include the exact marker to place in a supported request body. Owner write grants are disclosed only to write-scoped callers; provider capabilities do not grant permission. Values are never returned.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "secrets_find",
    description:
      "Check an explicitly authorized secret alias and return availability and safe metadata only. References must be exact and unpadded. Structured refs must match the alias's owner-bound reference. For 1Password Connect, an object ID plus the exact /fields/<field-id>/value JSON Pointer maps to its canonical reference only when it matches the bound policy. Named-secret and login_lookup locators are accepted only for 1Password Connect and must match the owner-pinned title or login identity. Companion-gated stores (bitwarden-cli, onepassword-service-account, lastpass) fail as secret_store_unavailable before lookup, for both structured secret refs and locators. BWS name/login locators fail as secret_binding_unsupported before lookup. env_var locators are recognized only to reject them as local_only_env_var; they are never resolved by the cloud. For structured refs, the broker derives the canonical reference and compares it with the owner's policy. For named_secret and login_lookup locators, it uses the owner's pinned selector and never accepts a caller-selected field ID. For input bindings, pass only the selected typed value as input_ref or input_locator, never the full workflow input map. BWS structured refs support only exact UUIDs with no field path. Secret values are never returned.",
    inputSchema: {
      type: "object",
      required: ["secret_alias"],
      properties: {
        secret_alias: { type: "string" },
        store: {
          type: "string",
          enum: [
            "bitwarden-cli",
            "bitwarden-secrets-manager",
            "onepassword-connect",
            "onepassword-service-account",
            "lastpass",
          ],
        },
        reference: { type: "string", maxLength: 1024 },
        binding: {
          oneOf: [
            {
              type: "object",
              required: ["secret_ref"],
              properties: { secret_ref: secretRefValueSchema },
              additionalProperties: false,
            },
            {
              type: "object",
              required: ["secret_ref_input"],
              properties: {
                secret_ref_input: {
                  description:
                    "Name of the workflow input containing the typed secret reference.",
                  oneOf: [
                    { type: "string", minLength: 1, maxLength: 128 },
                    {
                      type: "object",
                      required: ["name"],
                      properties: {
                        name: { type: "string", minLength: 1, maxLength: 128 },
                        field_path: { type: "string", maxLength: 1024 },
                      },
                      additionalProperties: false,
                    },
                    {
                      type: "object",
                      required: ["kind", "name"],
                      properties: {
                        kind: { const: "env_var" },
                        name: { type: "string", minLength: 1, maxLength: 128 },
                      },
                      additionalProperties: false,
                    },
                  ],
                },
              },
              additionalProperties: false,
            },
            {
              type: "object",
              required: ["secret_locator"],
              properties: {
                secret_locator: {
                  oneOf: [
                    {
                      type: "object",
                      required: ["kind", "name"],
                      properties: {
                        kind: { const: "named_secret" },
                        store: { type: "string" },
                        name: {
                          type: "string",
                          minLength: 1,
                          maxLength: 128,
                        },
                        field_path: {
                          type: ["string", "null"],
                          maxLength: 1024,
                        },
                        fieldPath: {
                          type: ["string", "null"],
                          maxLength: 1024,
                        },
                      },
                      additionalProperties: false,
                    },
                    {
                      type: "object",
                      required: ["kind", "username", "uris"],
                      properties: {
                        kind: { const: "login_lookup" },
                        store: { type: "string" },
                        username: {
                          type: "string",
                          minLength: 1,
                          maxLength: 512,
                        },
                        uris: {
                          type: "array",
                          minItems: 1,
                          maxItems: 16,
                          items: {
                            type: "string",
                            minLength: 1,
                            maxLength: 2048,
                          },
                        },
                        field_path: {
                          type: ["string", "null"],
                          maxLength: 1024,
                        },
                        fieldPath: {
                          type: ["string", "null"],
                          maxLength: 1024,
                        },
                      },
                      additionalProperties: false,
                    },
                  ],
                },
              },
              additionalProperties: false,
            },
            {
              type: "object",
              required: ["secret_locator_input"],
              properties: {
                secret_locator_input: {
                  oneOf: [
                    { type: "string", minLength: 1, maxLength: 128 },
                    {
                      type: "object",
                      required: ["name"],
                      properties: {
                        name: { type: "string", minLength: 1, maxLength: 128 },
                      },
                      additionalProperties: false,
                    },
                  ],
                },
              },
              additionalProperties: false,
            },
          ],
        },
        input_ref: {
          ...secretRefValueSchema,
          description:
            "The typed secret reference for the named secret_ref_input. Pass only this ref, not other workflow inputs.",
          required: ["type"],
        },
        input_locator: {
          oneOf: [
            {
              type: "object",
              required: ["kind", "name"],
              properties: {
                kind: { const: "env_var" },
                name: { type: "string", minLength: 1, maxLength: 128 },
              },
              additionalProperties: false,
            },
            {
              type: "object",
              required: ["kind", "name"],
              properties: {
                kind: { const: "named_secret" },
                store: { type: "string" },
                name: { type: "string", minLength: 1, maxLength: 128 },
                field_path: { type: ["string", "null"], maxLength: 1024 },
                fieldPath: { type: ["string", "null"], maxLength: 1024 },
              },
              additionalProperties: false,
            },
            {
              type: "object",
              required: ["kind", "username", "uris"],
              properties: {
                kind: { const: "login_lookup" },
                store: { type: "string" },
                username: { type: "string", minLength: 1, maxLength: 512 },
                uris: {
                  type: "array",
                  minItems: 1,
                  maxItems: 16,
                  items: { type: "string", minLength: 1, maxLength: 2048 },
                },
                field_path: { type: ["string", "null"], maxLength: 1024 },
                fieldPath: { type: ["string", "null"], maxLength: 1024 },
              },
              additionalProperties: false,
            },
          ],
        },
        selector: {
          oneOf: [
            {
              type: "object",
              required: ["title"],
              properties: {
                title: { type: "string", minLength: 1, maxLength: 128 },
                fieldId: { type: "string", minLength: 1, maxLength: 256 },
              },
              additionalProperties: false,
            },
            {
              type: "object",
              required: ["kind", "title", "username", "uris", "fieldId"],
              properties: {
                kind: { const: "login_lookup" },
                title: { type: "string", minLength: 1, maxLength: 128 },
                username: { type: "string", minLength: 1, maxLength: 512 },
                uris: {
                  type: "array",
                  minItems: 1,
                  maxItems: 16,
                  items: { type: "string", minLength: 1, maxLength: 2048 },
                },
                fieldId: { type: "string", minLength: 1, maxLength: 256 },
                fieldPath: { type: "string", minLength: 1, maxLength: 256 },
              },
              additionalProperties: false,
            },
          ],
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "secrets_save",
    description:
      "Request an owner-fulfilled secret create, exact-reference update, or ensure. Never provide a value. Connect requests are completed in the authenticated dashboard; 1Password service-account requests are completed by the enrolled local companion against the same requestId. Ensure compares privately and updates only when the value differs. Targets must be exact and unpadded; update/ensure references are validated before rate charging. Use the returned requestId with the same operation_id and target to poll; reusing an operation_id with a different target is refused without dispatching. Returns only a request status and safe reference receipt.",
    inputSchema: {
      type: "object",
      required: ["secret_alias", "operation_id", "intent"],
      properties: {
        secret_alias: { type: "string" },
        operation_id: {
          type: "string",
          pattern: "^[A-Za-z0-9_-]{20,128}$",
          minLength: 20,
          maxLength: 128,
        },
        intent: { type: "string", enum: ["create", "update", "ensure"] },
        title: { type: "string", maxLength: 128 },
        reference: { type: "string", maxLength: 1024 },
      },
      additionalProperties: false,
    },
  },
  {
    name: "secrets_delete",
    description:
      "Delete one exact provider field authorized by the alias owner's delete grant. Connect deletion runs through the cloud broker; a 1Password service-account request returns a requestId for completion by the enrolled local companion after executor-bound admission. Supply only the alias, a valid operation ID, and an unpadded owner-bound exact reference; invalid IDs/references and extra fields are rejected before rate charging. Returns a safe verified receipt or an owner-action status.",
    inputSchema: {
      type: "object",
      required: ["secret_alias", "operation_id", "reference"],
      properties: {
        secret_alias: { type: "string" },
        operation_id: {
          type: "string",
          pattern: "^[A-Za-z0-9_-]{20,128}$",
          minLength: 20,
          maxLength: 128,
        },
        reference: { type: "string", minLength: 1, maxLength: 1024 },
      },
      additionalProperties: false,
    },
  },
  {
    name: "proxy_http_request",
    description:
      "Perform a policy-authorized HTTPS request. The broker applies the owner-selected credential sink and returns the permitted result. For a body-placeholder alias, include exactly one {{AGENTSECRET_SECRET}} marker as a whole JSON string/value slot or in text/plain; the broker substitutes only after authorization. Supply an absolute public HTTPS URL.",
    inputSchema: {
      type: "object",
      required: ["secret_alias", "url"],
      properties: {
        secret_alias: { type: "string" },
        url: { type: "string" },
        method: { type: "string" },
        headers: { type: "object", additionalProperties: { type: "string" } },
        body: {},
      },
      additionalProperties: false,
    },
  },
  {
    name: "prepare_local_execution",
    description:
      "Describe how to use the local broker request CLI. This cloud tool returns instructions; the agent uses its own local execution tool to run them. It does not export credentials or execute a local command.",
    inputSchema: {
      type: "object",
      required: ["secret_alias", "url"],
      properties: { secret_alias: { type: "string" }, url: { type: "string" } },
      additionalProperties: false,
    },
  },
];
