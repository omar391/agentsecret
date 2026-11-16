import { test } from "node:test";
import assert from "node:assert/strict";
import { unit } from "./unit-helpers.mjs";

test("BWS write intents fail closed before any provider request", async (t) => {
  let outbound = 0;
  t.mock.method(globalThis, "fetch", async () => {
    outbound++;
    throw new Error("unsupported provider write must not dispatch");
  });

  const config = {
    type: "bitwarden",
    accessToken: "synthetic-bitwarden-secrets-manager-token",
  };

  for (const intent of ["create", "update", "delete"]) {
    await assert.rejects(
      unit.writeSecret(
        config,
        intent,
        "synthetic-reference",
        intent === "delete" ? undefined : "synthetic-value",
      ),
      (error) =>
        error instanceof Error &&
        error.status === 409 &&
        error.code === "provider_write_unsupported",
    );
  }

  assert.equal(outbound, 0);
});

test("BWS name lookup fails closed before listing value-bearing secrets", async (t) => {
  let outbound = 0;
  t.mock.method(globalThis, "fetch", async () => {
    outbound++;
    throw new Error("BWS name lookup must not list secret values");
  });

  await assert.rejects(
    unit.findSecretByTitle(
      {
        type: "bitwarden",
        accessToken: "synthetic-bitwarden-secrets-manager-token",
      },
      "synthetic owner-pinned name",
    ),
    (error) =>
      error instanceof Error &&
      error.status === 409 &&
      error.code === "provider_selector_unsupported",
  );

  assert.equal(outbound, 0);
});

test("companion-gated providers fail closed for shared find and write", async (t) => {
  let outbound = 0;
  t.mock.method(globalThis, "fetch", async () => {
    outbound++;
    throw new Error("companion-gated provider must not dispatch");
  });

  const configs = [
    {
      type: "bitwarden-password-manager",
      profileId: "synthetic-bwpm-profile",
    },
    {
      type: "onepassword-service-account",
      vaultId: "synthetic-vault",
    },
    {
      type: "lastpass",
      profileId: "synthetic-lastpass-profile",
    },
  ];

  for (const config of configs) {
    await assert.rejects(
      unit.findSecretByReference(config, "synthetic-item#password"),
      (error) =>
        error instanceof Error &&
        error.status === 503 &&
        error.code === "secret_store_unavailable",
    );
    for (const intent of ["create", "update", "delete"]) {
      await assert.rejects(
        unit.writeSecret(
          config,
          intent,
          "synthetic-item#password",
          intent === "delete" ? undefined : "synthetic-value",
        ),
        (error) =>
          error instanceof Error &&
          error.status === 409 &&
          error.code === "provider_write_unsupported",
      );
    }
  }

  assert.equal(outbound, 0);
});
