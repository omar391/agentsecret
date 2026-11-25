import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { build } from "esbuild";
import { mkdir } from "node:fs/promises";
const require = createRequire(new URL("../web/package.json", import.meta.url));
const React = require("react");
const { create, act } = require("react-test-renderer");
const output = new URL("../tmp/tests/web-app.mjs", import.meta.url).pathname;
await mkdir(new URL("../tmp/tests/", import.meta.url), { recursive: true });
await build({
  entryPoints: [new URL("../web/src/App.tsx", import.meta.url).pathname],
  bundle: true,
  format: "esm",
  platform: "node",
  outfile: output,
  plugins: [
    {
      name: "shared-react",
      setup(build) {
        build.onResolve(
          { filter: /^(react(?:\/.*)?|lucide-react)$/ },
          (args) => ({ path: require.resolve(args.path), external: true }),
        );
      },
    },
  ],
});
const { default: App } = await import(output);

test("simulator submits its displayed custom alias, follows tenant policies and exposes broker/transport errors", async (t) => {
  const originalWindow = globalThis.window;
  const originalFetch = globalThis.fetch;
  let currentTenant = "default";
  let policies = [
    {
      alias: "API_TOKEN",
      allowedDomains: ["api.github.com"],
      allowedMethods: ["GET"],
      description: "synthetic policy",
    },
  ];
  let nextError = { status: 403, error: "policy_denied" };
  let calls = 0;
  globalThis.window = {
    location: {
      search: "?view=dashboard&tab=simulator",
      origin: "https://broker.example.test",
    },
  };
  globalThis.fetch = async (url, options = {}) => {
    if (url === "/api/auth/me")
      return Response.json({
        authenticated: true,
        user: {
          id: currentTenant,
          name: "Synthetic Operator",
          provider: "operator",
          plan: "self-hosted",
          quotaUsed: 0,
          quotaLimit: 100,
          availableTenants: ["default", "other-tenant"],
        },
      });
    if (url === "/api/user/policies") return Response.json({ policies });
    if (url === "/api/operator/tenant") {
      currentTenant = JSON.parse(options.body).tenant;
      return Response.json({ success: true });
    }
    if (url === "/proxy") {
      calls++;
      assert.equal(JSON.parse(options.body).secret_alias, policies[0].alias);
      if (nextError === null) throw new Error("synthetic transport failure");
      return Response.json(
        { error: nextError.error },
        { status: nextError.status },
      );
    }
    throw new Error("Unexpected UI fixture request: " + url);
  };
  let renderer;
  t.after(() => {
    if (renderer) act(() => renderer.unmount());
    globalThis.window = originalWindow;
    globalThis.fetch = originalFetch;
  });
  await act(async () => {
    renderer = create(React.createElement(App));
  });
  const alias = () =>
    renderer.root.findByProps({ "aria-label": "Secret Alias" });
  const execute = () =>
    renderer.root
      .findAllByType("button")
      .find((button) => button.children.includes("Execute Blind Proxy"));
  const simulatorAlert = (match) =>
    renderer.root
      .findAllByProps({ role: "alert" })
      .find((node) => node.children.join("").includes(match));
  assert.equal(alias().props.value, "API_TOKEN");
  assert.equal(execute().props.disabled, false);
  for (const failure of [
    { status: 403, error: "policy_denied" },
    { status: 401, error: "invalid_token" },
    { status: 502, error: "vault_provider_unavailable" },
  ]) {
    nextError = failure;
    await act(async () => {
      await execute().props.onClick();
    });
    assert.equal(
      simulatorAlert(failure.error).children.join(""),
      failure.error,
    );
    assert.ok(
      JSON.stringify(renderer.toJSON()).includes("HTTP " + failure.status),
    );
  }
  nextError = null;
  await act(async () => {
    await execute().props.onClick();
  });
  assert.match(
    simulatorAlert("Broker request failed").children.join(""),
    /Broker request failed/,
  );
  assert.ok(JSON.stringify(renderer.toJSON()).includes("Transport error"));
  // There is no tenant selector left: the account is whatever the session says it is, so the only
  // thing the simulator can do is re-read the policies the server reports for that account.
  assert.equal(
    renderer.root
      .findAllByType("select")
      .filter((node) => node.props.value === currentTenant).length,
    0,
  );
  const remount = async () => {
    await act(async () => renderer.unmount());
    await act(async () => {
      renderer = create(React.createElement(App));
    });
  };
  policies = [{ ...policies[0], alias: "OTHER_API" }];
  await remount();
  assert.equal(alias().props.value, "OTHER_API");
  await act(async () => {
    await execute().props.onClick();
  });
  assert.equal(calls, 5);
  policies = [];
  await remount();
  assert.equal(alias().props.value, "");
  assert.equal(execute().props.disabled, true);
  await act(async () => {
    await execute().props.onClick();
  });
  assert.equal(calls, 5);
});

test("public funnel omits simulated security proof and stale billing return UI", async (t) => {
  const originalWindow = globalThis.window;
  const originalFetch = globalThis.fetch;
  globalThis.window = {
    location: {
      search: "?view=dashboard&checkout_success=true&plan=pro",
      origin: "http://localhost:8787",
    },
  };
  globalThis.fetch = async () =>
    Response.json({ authenticated: false }, { status: 401 });
  let renderer;
  t.after(() => {
    if (renderer) act(() => renderer.unmount());
    globalThis.window = originalWindow;
    globalThis.fetch = originalFetch;
  });
  await act(async () => {
    renderer = create(React.createElement(App));
  });
  let text = JSON.stringify(renderer.toJSON());
  assert.ok(text.includes("Not signed in"));
  assert.ok(text.includes("http://localhost:8787"));
  assert.ok(!text.includes("Operator session"));
  assert.ok(!text.includes("Production Edge"));
  assert.ok(!text.includes("AstronLab Prod"));
  assert.ok(!text.includes("Billing & Quota"));
  assert.ok(!text.includes("Returned from checkout"));
  const home = renderer.root
    .findAllByType("button")
    .find((button) => button.children.includes("← Back to Public Site"));
  await act(async () => {
    home.props.onClick();
  });
  text = JSON.stringify(renderer.toJSON());
  assert.ok(!text.includes("Zero-Exposure Cryptographic Invariant"));
  assert.ok(!text.includes("Interactive Attack Proof"));
  assert.ok(!text.includes("timer-driven illustration"));
  assert.ok(!text.includes("not a live attack test or a security proof"));
  assert.ok(!text.includes("Execute Attack Simulation"));
  assert.ok(!text.includes("attack-demo"));
  assert.ok(text.includes("How AgentSecret Works"));
});

test("legacy and unknown dashboard tabs fall back to Overview with the server allowance", async (t) => {
  const originalWindow = globalThis.window;
  const originalFetch = globalThis.fetch;
  globalThis.window = {
    location: {
      search: "?view=dashboard&tab=billing",
      origin: "https://broker.example.test",
    },
  };
  globalThis.fetch = async (url) => {
    if (url === "/api/auth/me")
      return Response.json({
        authenticated: true,
        user: {
          id: "synthetic-account",
          name: "Synthetic User",
          provider: "github",
          plan: "free",
          quotaUsed: 37,
          quotaLimit: 250,
        },
      });
    if (url === "/api/user/policies") return Response.json({ policies: [] });
    throw new Error("Unexpected UI fixture request: " + url);
  };
  let renderer;
  t.after(() => {
    if (renderer) act(() => renderer.unmount());
    globalThis.window = originalWindow;
    globalThis.fetch = originalFetch;
  });
  const renderForTab = async (tab) => {
    globalThis.window.location.search = `?view=dashboard&tab=${tab}`;
    if (renderer) await act(async () => renderer.unmount());
    await act(async () => {
      renderer = create(React.createElement(App));
    });
    const text = JSON.stringify(renderer.toJSON());
    assert.ok(text.includes("Monthly Quota"));
    const renderedText = (node) =>
      typeof node === "string"
        ? node
        : Array.isArray(node)
          ? node.map(renderedText).join("")
          : node?.children
            ? renderedText(node.children)
            : "";
    assert.ok(renderedText(renderer.toJSON()).includes("37 / 250"));
    assert.ok(!text.includes("Billing & Quota"));
    // The CLI defaults to the "default" tenant, so a customer's command must
    // name the signed-in account or device approval cannot find the grant.
    assert.equal(
      renderer.root.findByProps({ "aria-label": "Companion login command" })
        .props.value,
      "agentsecret login --server https://broker.example.test --tenant synthetic-account",
    );
  };
  await renderForTab("billing");
  await renderForTab("unknown");
});

test("vault connections display capability status returned by the server", async (t) => {
  const originalWindow = globalThis.window;
  const originalFetch = globalThis.fetch;
  globalThis.window = {
    location: {
      search: "?view=dashboard&tab=vaults",
      origin: "https://broker.example.test",
    },
  };
  globalThis.fetch = async (url) => {
    if (url === "/api/auth/me")
      return Response.json({
        authenticated: true,
        user: {
          id: "synthetic-account",
          name: "Synthetic User",
          provider: "github",
          plan: "free",
          quotaUsed: 0,
          quotaLimit: 10000,
        },
      });
    if (url === "/api/user/policies") return Response.json({ policies: [] });
    if (url === "/api/user/vault-connections")
      return Response.json({
        providerCapabilities: {
          "bitwarden-secrets-manager": {
            status: "implemented",
            read: true,
            create: false,
            update: false,
            conditionalUpdate: false,
            verifyAfterWrite: false,
            delete: false,
            reason: "The current adapter implements authenticated read only.",
          },
          "bitwarden-password-manager": {
            status: "requires-companion",
            read: false,
            create: false,
            update: false,
            conditionalUpdate: false,
            verifyAfterWrite: false,
            delete: false,
            reason:
              "The documented local bw CLI supports item get/create/edit with encoded JSON through stdin. Value-bearing output and whole-item replace require a trusted, account-bound companion with in-memory handling; no adapter is implemented.",
          },
          "onepassword-service-account": {
            status: "requires-companion",
            read: false,
            create: false,
            update: false,
            conditionalUpdate: false,
            verifyAfterWrite: false,
            delete: false,
            reason:
              "The documented 1Password CLI supports scoped item CRUD using JSON templates on stdin. The protected companion adapter is not implemented; custom-field deletion is name-based, built-in fields cannot be deleted, JSON edits may overwrite passkeys, and conditional updates are not supported. This is not a Connect token.",
          },
          lastpass: {
            status: "requires-companion",
            read: true,
            create: false,
            update: false,
            conditionalUpdate: false,
            verifyAfterWrite: false,
            delete: false,
            reason:
              "A dedicated account-bound local companion reads exact LastPass CLI item fields after cloud authorization and keeps the full item JSON in process memory. Writes, attachments, and unsupported fields remain disabled; live acceptance is still required.",
          },
        },
        connections: [
          {
            id: "synthetic-connection",
            alias: "personal",
            provider: "onepassword-connect",
            revision: 1,
            capabilities: {
              read: true,
              create: true,
              update: true,
              conditionalUpdate: false,
              verifyAfterWrite: true,
              delete: false,
            },
          },
        ],
      });
    return new Response("not found", { status: 404 });
  };
  let renderer;
  t.after(() => {
    if (renderer) act(() => renderer.unmount());
    globalThis.window = originalWindow;
    globalThis.fetch = originalFetch;
  });
  await act(async () => {
    renderer = create(React.createElement(App));
  });
  const text = JSON.stringify(renderer.toJSON());
  const availability = renderer.root.findByProps({
    "aria-label": "Provider availability",
  });
  const renderedText = (node) =>
    typeof node === "string" || typeof node === "number"
      ? String(node)
      : node.children.map(renderedText).join("");
  const rows = availability
    .findAllByType("li")
    .map((row) => row.children.map(renderedText).join(""));
  assert.match(text, /read; write available/);
  assert.ok(
    rows.some(
      (row) =>
        row.includes("Bitwarden Secrets Manager") &&
        row.includes("Read available · save unavailable"),
    ),
  );
  assert.ok(
    rows.some(
      (row) =>
        row.includes("Bitwarden Password Manager") &&
        row.includes("Companion required") &&
        row.includes("no adapter is implemented"),
    ),
  );
  assert.ok(!rows.some((row) => row.includes("1Password Connect")));
  assert.ok(
    rows.some(
      (row) =>
        row.includes("1Password service account") &&
        row.includes("Companion required"),
    ),
  );
  assert.ok(
    rows.some(
      (row) => row.includes("LastPass") && row.includes("Companion required"),
    ),
  );
});

test("policy form exposes a separate exact-reference delete grant", async (t) => {
  const originalWindow = globalThis.window;
  const originalFetch = globalThis.fetch;
  let savedPolicy;
  let policyPostCount = 0;
  globalThis.window = {
    location: {
      search: "?view=dashboard&tab=policies",
      origin: "https://broker.example.test",
    },
  };
  globalThis.fetch = async (url, options = {}) => {
    if (url === "/api/auth/me")
      return Response.json({
        authenticated: true,
        user: {
          id: "synthetic-account",
          name: "Synthetic User",
          provider: "github",
          plan: "free",
          quotaUsed: 0,
          quotaLimit: 10000,
        },
      });
    if (url === "/api/user/policies" && options.method === "POST") {
      policyPostCount++;
      savedPolicy = JSON.parse(options.body);
      return Response.json({ success: true });
    }
    if (url === "/api/user/policies") return Response.json({ policies: [] });
    if (url === "/api/user/vault-connections")
      return Response.json({
        providerCapabilities: {},
        connections: [
          {
            id: "onepassword-delete-policy",
            alias: "personal",
            provider: "onepassword-connect",
            revision: 1,
            capabilities: {
              read: true,
              create: true,
              update: true,
              conditionalUpdate: false,
              verifyAfterWrite: true,
              delete: true,
            },
          },
        ],
      });
    throw new Error("Unexpected policy UI fixture request: " + url);
  };
  let renderer;
  t.after(() => {
    if (renderer) act(() => renderer.unmount());
    globalThis.window = originalWindow;
    globalThis.fetch = originalFetch;
  });
  await act(async () => {
    renderer = create(React.createElement(App));
  });
  const labelText = (node) =>
    node.children
      .map((child) =>
        typeof child === "string"
          ? child
          : child?.children
            ? labelText(child)
            : "",
      )
      .join("");
  const deleteGrantLabel = renderer.root
    .findAllByType("label")
    .find((label) =>
      labelText(label).includes("Allow deleting this policy’s exact reference"),
    );
  assert.ok(deleteGrantLabel);
  const loginLookupLabel = renderer.root
    .findAllByType("label")
    .find((label) =>
      labelText(label).includes("Allow lookup by this exact login locator"),
    );
  assert.ok(loginLookupLabel);
  await act(async () => {
    deleteGrantLabel
      .findByType("input")
      .props.onChange({ target: { checked: true } });
    loginLookupLabel
      .findByType("input")
      .props.onChange({ target: { checked: true } });
  });
  await act(async () => {
    renderer.root
      .findAllByType("input")
      .find((input) => input.props.placeholder === "Provider reference")
      .props.onChange({
        target: { value: "0123456789abcdef0123456789#field-id" },
      });
    renderer.root
      .findAllByType("input")
      .find((input) => input.props.placeholder === "MY_SERVICE_KEY")
      .props.onChange({ target: { value: "DELETE_ONLY" } });
    const labelInput = (match) =>
      renderer.root
        .findAllByType("label")
        .find((label) => labelText(label).startsWith(match))
        .findByType("input");
    labelInput("Exact Connect item title").props.onChange({
      target: { value: " Owner pinned work login " },
    });
    labelInput("Exact username").props.onChange({
      target: { value: " synthetic.user@example.test " },
    });
    renderer.root
      .findAllByType("label")
      .find((label) => labelText(label).startsWith("Exact item URLs"))
      .findByType("textarea")
      .props.onChange({ target: { value: "https://login.github.com" } });
    labelInput("Exact password field label").props.onChange({
      target: { value: " password " },
    });
    renderer.root
      .findAllByType("select")
      .find((select) => select.props["aria-label"] === "Credential placement")
      .props.onChange({ target: { value: "body_placeholder" } });
  });
  const policyForm = renderer.root
    .findAllByType("form")
    .find((form) =>
      form
        .findAllByType("button")
        .some((button) => button.children.includes("+ Register Policy")),
    );
  assert.ok(policyForm);
  await act(async () => {
    await policyForm.props.onSubmit({ preventDefault() {} });
  });
  assert.equal(savedPolicy.alias, "DELETE_ONLY");
  assert.equal(savedPolicy.injectionType, "body_placeholder");
  assert.deepEqual(savedPolicy.secretWrite, {
    create: false,
    update: false,
    delete: true,
  });
  assert.deepEqual(savedPolicy.findSelector, {
    kind: "login_lookup",
    title: " Owner pinned work login ",
    username: " synthetic.user@example.test ",
    uris: ["https://login.github.com"],
    fieldId: "field-id",
    fieldPath: " password ",
  });
  assert.equal(Object.hasOwn(savedPolicy, "value"), false);
  await act(async () => {
    renderer.root
      .findAllByType("label")
      .find((label) =>
        labelText(label).includes("Allow lookup by this exact login locator"),
      )
      .findByType("input")
      .props.onChange({ target: { checked: true } });
  });
  await act(async () => {
    renderer.root
      .findAllByType("input")
      .find((input) => input.props.placeholder === "Provider reference")
      .props.onChange({
        target: { value: "0123456789abcdef0123456789#field-id" },
      });
    renderer.root
      .findAllByType("input")
      .find((input) => input.props.placeholder === "MY_SERVICE_KEY")
      .props.onChange({ target: { value: "BAD_URI" } });
    renderer.root
      .findAllByType("label")
      .find((label) => labelText(label).startsWith("Exact Connect item title"))
      .findByType("input")
      .props.onChange({ target: { value: "Title" } });
    renderer.root
      .findAllByType("label")
      .find((label) => labelText(label).startsWith("Exact username"))
      .findByType("input")
      .props.onChange({ target: { value: "user" } });
    renderer.root
      .findAllByType("label")
      .find((label) => labelText(label).startsWith("Exact item URLs"))
      .findByType("textarea")
      .props.onChange({ target: { value: " https://login.github.com " } });
  });
  await act(async () => {
    await policyForm.props.onSubmit({ preventDefault() {} });
  });
  assert.equal(policyPostCount, 1, "padded URL input is refused before POST");
});

test("owner approves a public executor and issues a short-lived protected action grant", async (t) => {
  const originalWindow = globalThis.window;
  const originalFetch = globalThis.fetch;
  const publicJwk = {
    kty: "EC",
    crv: "P-256",
    x: "synthetic-x-coordinate",
    y: "synthetic-y-coordinate",
  };
  const executorId = "exe_" + "A".repeat(43);
  let executors = [];
  let grants = [];
  let approvedBody;
  let issuedBody;
  globalThis.window = {
    location: {
      search: "?view=dashboard&tab=policies",
      origin: "https://broker.example.test",
    },
  };
  globalThis.fetch = async (url, options = {}) => {
    if (url === "/api/auth/me")
      return Response.json({
        authenticated: true,
        user: {
          id: "synthetic-account",
          name: "Synthetic User",
          provider: "github",
          plan: "free",
          quotaUsed: 0,
          quotaLimit: 10000,
        },
      });
    if (url === "/api/user/policies")
      return Response.json({
        policies: [
          {
            alias: "LOGIN",
            domains: "app.example.com",
            methods: "GET",
            injectionType: "bearer",
            desc: "synthetic login",
          },
        ],
      });
    if (url === "/api/user/vault-connections")
      return Response.json({ providerCapabilities: {}, connections: [] });
    if (url === "/api/executor/identities") return Response.json({ executors });
    if (url === "/api/executor/grants" && !options.method)
      return Response.json({ grants });
    if (url === "/api/executor/approve") {
      approvedBody = JSON.parse(options.body);
      executors = [
        {
          executorId,
          thumbprint: "synthetic-thumbprint",
          createdAt: 1000,
          enrolledAt: 2000,
        },
      ];
      return Response.json({ executorId, status: "enrolled" });
    }
    if (url === "/api/executor/grants" && options.method === "POST") {
      issuedBody = JSON.parse(options.body);
      const grant = {
        grantId: "bg1.c3ludGhldGlj.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        executorId,
        alias: "LOGIN",
        origin: "https://app.example.com",
        kinds: ["fill", "totp"],
        fieldSelector: "#password",
        expiresAt: 3000,
        redeemedAt: null,
        revokedAt: null,
      };
      grants = [grant];
      return Response.json(grant, { status: 201 });
    }
    throw new Error("Unexpected executor UI fixture request: " + url);
  };
  let renderer;
  t.after(() => {
    if (renderer) act(() => renderer.unmount());
    globalThis.window = originalWindow;
    globalThis.fetch = originalFetch;
  });
  await act(async () => {
    renderer = create(React.createElement(App));
  });

  const publicInput = renderer.root.findByProps({
    "aria-label": "Public executor identity JSON",
  });
  await act(async () => {
    publicInput.props.onChange({
      target: {
        value: JSON.stringify({
          status: "executor_identity",
          identity: {
            version: 1,
            executorId,
            createdAt: 1000,
            publicJwk,
          },
        }),
      },
    });
  });
  const approveForm = renderer.root
    .findAllByType("form")
    .find((form) =>
      form
        .findAllByType("button")
        .some((button) => button.children.includes("Approve public identity")),
    );
  await act(async () => {
    await approveForm.props.onSubmit({ preventDefault() {} });
  });
  assert.deepEqual(approvedBody, {
    executorId,
    publicJwk,
    createdAt: 1000,
  });
  assert.ok(JSON.stringify(renderer.toJSON()).includes(executorId));

  const setValue = async (label, value) => {
    await act(async () => {
      renderer.root
        .findByProps({ "aria-label": label })
        .props.onChange({ target: { value } });
    });
  };
  await setValue("Protected action executor", executorId);
  await setValue("Protected action alias", "LOGIN");
  await setValue("Protected action origin", "https://app.example.com");
  await setValue("Protected action kinds", "fill,totp");
  await setValue("Protected action field selector", "#password");
  const issueForm = renderer.root
    .findAllByType("form")
    .find((form) =>
      form
        .findAllByType("button")
        .some((button) => button.children.includes("Issue 60-second grant")),
    );
  await act(async () => {
    await issueForm.props.onSubmit({ preventDefault() {} });
  });
  assert.deepEqual(issuedBody, {
    executorId,
    alias: "LOGIN",
    origin: "https://app.example.com",
    kinds: ["fill", "totp"],
    fieldSelector: "#password",
    expiresIn: 60,
  });
  const rendered = JSON.stringify(renderer.toJSON());
  assert.ok(rendered.includes("bg1.c3ludGhldGlj"));
  assert.ok(rendered.includes("Issued bg1.c3ludGhldGlj"));
});

test("existing Connect policies can edit or clear their pinned login locator", async (t) => {
  const originalWindow = globalThis.window;
  const originalFetch = globalThis.fetch;
  const policy = {
    alias: "EXISTING_LOGIN",
    description: "existing policy",
    allowedDomains: ["api.github.com"],
    allowedMethods: ["GET"],
    injectionType: "bearer",
    connectionId: "onepassword-edit-locator",
    connectionRevision: 1,
    secretId: "0123456789abcdef0123456789#field%2Did",
    secretWrite: { update: true },
  };
  let patchBody;
  globalThis.window = {
    location: {
      search: "?view=dashboard&tab=policies",
      origin: "https://broker.example.test",
    },
  };
  globalThis.fetch = async (url, options = {}) => {
    if (url === "/api/auth/me")
      return Response.json({
        authenticated: true,
        user: {
          id: "synthetic-account",
          name: "Synthetic User",
          provider: "github",
          plan: "free",
          quotaUsed: 0,
          quotaLimit: 10000,
        },
      });
    if (url === "/api/user/policies" && options.method === "PATCH") {
      patchBody = JSON.parse(options.body);
      return Response.json({ success: true });
    }
    if (url === "/api/user/policies")
      return Response.json({ policies: [policy] });
    if (url === "/api/user/vault-connections")
      return Response.json({
        providerCapabilities: {},
        connections: [
          {
            id: policy.connectionId,
            alias: "personal",
            provider: "onepassword-connect",
            revision: 1,
            capabilities: { read: true, create: true, update: true },
          },
        ],
      });
    throw new Error("Unexpected policy edit fixture request: " + url);
  };
  let renderer;
  t.after(() => {
    if (renderer) act(() => renderer.unmount());
    globalThis.window = originalWindow;
    globalThis.fetch = originalFetch;
  });
  await act(async () => {
    renderer = create(React.createElement(App));
  });
  await act(async () => new Promise((resolve) => setTimeout(resolve, 0)));
  const configure = renderer.root
    .findAllByType("button")
    .find((button) => button.children.includes("Configure login lookup"));
  assert.ok(configure);
  await act(async () => configure.props.onClick());
  const findLabel = (prefix) =>
    renderer.root
      .findAllByType("label")
      .find((label) => labelText(label).includes(prefix));
  const labelText = (node) =>
    node.children
      .map((child) =>
        typeof child === "string"
          ? child
          : child?.children
            ? labelText(child)
            : "",
      )
      .join("");
  assert.ok(
    findLabel("Enable this exact login lookup"),
    renderer.root.findAllByType("label").map(labelText).join(" | "),
  );
  const toggle = findLabel("Enable this exact login lookup").findByType(
    "input",
  );
  await act(async () => toggle.props.onChange({ target: { checked: true } }));
  await act(async () => {
    findLabel("Exact Connect item title")
      .findByType("input")
      .props.onChange({
        target: { value: " Existing login " },
      });
    findLabel("Exact username")
      .findByType("input")
      .props.onChange({
        target: { value: " owner@example.test " },
      });
    findLabel("Exact item URLs")
      .findByType("textarea")
      .props.onChange({
        target: { value: "https://login.github.com" },
      });
  });
  const form = renderer.root
    .findAllByType("form")
    .find(
      (item) => item.props["aria-label"] === "Edit login lookup EXISTING_LOGIN",
    );
  assert.ok(form);
  await act(async () => form.props.onSubmit({ preventDefault() {} }));
  assert.deepEqual(patchBody, {
    alias: "EXISTING_LOGIN",
    findSelector: {
      kind: "login_lookup",
      title: " Existing login ",
      username: " owner@example.test ",
      uris: ["https://login.github.com"],
      fieldId: "field-id",
    },
  });
});

test("policy form clears a hidden Connect login locator when changing providers", async (t) => {
  const originalWindow = globalThis.window;
  const originalFetch = globalThis.fetch;
  let savedPolicy;
  globalThis.window = {
    location: {
      search: "?view=dashboard&tab=policies",
      origin: "https://broker.example.test",
    },
  };
  globalThis.fetch = async (url, options = {}) => {
    if (url === "/api/auth/me")
      return Response.json({
        authenticated: true,
        user: {
          id: "synthetic-account",
          name: "Synthetic User",
          provider: "github",
          plan: "free",
          quotaUsed: 0,
          quotaLimit: 10000,
        },
      });
    if (url === "/api/user/policies" && options.method === "POST") {
      savedPolicy = JSON.parse(options.body);
      return Response.json({ success: true });
    }
    if (url === "/api/user/policies") return Response.json({ policies: [] });
    if (url === "/api/user/vault-connections")
      return Response.json({
        providerCapabilities: {},
        connections: [
          {
            id: "connect-policy",
            alias: "connect",
            provider: "onepassword-connect",
            revision: 1,
            capabilities: { read: true },
          },
          {
            id: "bws-policy",
            alias: "bws",
            provider: "bitwarden_secrets",
            revision: 1,
            capabilities: { read: true },
          },
        ],
      });
    throw new Error("Unexpected policy UI fixture request: " + url);
  };
  let renderer;
  t.after(() => {
    if (renderer) act(() => renderer.unmount());
    globalThis.window = originalWindow;
    globalThis.fetch = originalFetch;
  });
  await act(async () => {
    renderer = create(React.createElement(App));
  });
  const labelText = (node) =>
    node.children
      .map((child) =>
        typeof child === "string"
          ? child
          : child?.children
            ? labelText(child)
            : "",
      )
      .join("");
  const loginLookupLabel = renderer.root
    .findAllByType("label")
    .find((label) =>
      labelText(label).includes("Allow lookup by this exact login locator"),
    );
  assert.ok(loginLookupLabel);
  await act(async () => {
    loginLookupLabel
      .findByType("input")
      .props.onChange({ target: { checked: true } });
  });
  const connectionSelect = renderer.root
    .findAllByType("label")
    .find((label) => labelText(label).startsWith("Vault connection"))
    .findByType("select");
  await act(async () => {
    connectionSelect.props.onChange({ target: { value: "bws-policy" } });
  });
  assert.equal(
    renderer.root
      .findAllByType("label")
      .some((label) =>
        labelText(label).includes("Allow lookup by this exact login locator"),
      ),
    false,
  );
  await act(async () => {
    renderer.root
      .findAllByType("input")
      .find((input) => input.props.placeholder === "Provider reference")
      .props.onChange({ target: { value: "0123456789abcdef0123456789" } });
    renderer.root
      .findAllByType("input")
      .find((input) => input.props.placeholder === "MY_SERVICE_KEY")
      .props.onChange({ target: { value: "BWS_ALIAS" } });
  });
  const policyForm = renderer.root
    .findAllByType("form")
    .find((form) =>
      form
        .findAllByType("button")
        .some((button) => button.children.includes("+ Register Policy")),
    );
  await act(async () => {
    await policyForm.props.onSubmit({ preventDefault() {} });
  });
  assert.equal(savedPolicy.connectionId, "bws-policy");
  assert.equal(Object.hasOwn(savedPolicy, "findSelector"), false);
});

test("policy form clears the locator opt-in when a connection disappears", async (t) => {
  const originalWindow = globalThis.window;
  const originalFetch = globalThis.fetch;
  let savedPolicy;
  let connections = [
    {
      id: "connect-policy",
      alias: "connect",
      provider: "onepassword-connect",
      revision: 1,
      capabilities: { read: true },
    },
    {
      id: "bws-policy",
      alias: "bws",
      provider: "bitwarden_secrets",
      revision: 1,
      capabilities: { read: true },
    },
  ];
  globalThis.window = {
    location: {
      search: "?view=dashboard&tab=policies",
      origin: "https://broker.example.test",
    },
  };
  globalThis.fetch = async (url, options = {}) => {
    if (url === "/api/auth/me")
      return Response.json({
        authenticated: true,
        user: {
          id: "synthetic-account",
          name: "Synthetic User",
          provider: "github",
          plan: "free",
          quotaUsed: 0,
          quotaLimit: 10000,
        },
      });
    if (url === "/api/user/policies" && options.method === "POST") {
      savedPolicy = JSON.parse(options.body);
      return Response.json({ success: true });
    }
    if (url === "/api/user/policies") return Response.json({ policies: [] });
    if (
      url.startsWith("/api/user/vault-connections?id=") &&
      options.method === "DELETE"
    ) {
      connections = connections.filter(
        (connection) => connection.id !== "connect-policy",
      );
      return Response.json({ success: true });
    }
    if (url === "/api/user/vault-connections")
      return Response.json({ providerCapabilities: {}, connections });
    throw new Error("Unexpected policy UI fixture request: " + url);
  };
  let renderer;
  t.after(() => {
    if (renderer) act(() => renderer.unmount());
    globalThis.window = originalWindow;
    globalThis.fetch = originalFetch;
  });
  await act(async () => {
    renderer = create(React.createElement(App));
  });
  const labelText = (node) =>
    node.children
      .map((child) =>
        typeof child === "string"
          ? child
          : child?.children
            ? labelText(child)
            : "",
      )
      .join("");
  const loginLookupLabel = () =>
    renderer.root
      .findAllByType("label")
      .find((label) =>
        labelText(label).includes("Allow lookup by this exact login locator"),
      );
  assert.ok(loginLookupLabel());
  await act(async () => {
    loginLookupLabel()
      .findByType("input")
      .props.onChange({ target: { checked: true } });
  });
  const navButton = (name) =>
    renderer.root
      .findAllByType("button")
      .find((button) => button.children.includes(name));
  await act(async () => {
    navButton("Vault Connections").props.onClick();
  });
  await act(async () => {
    await renderer.root
      .findAllByType("button")
      .find((button) => button.children.includes("Disconnect"))
      .props.onClick();
  });
  // Disconnecting is destructive, so the dashboard asks for confirmation.
  await act(async () => {
    await renderer.root
      .findAllByType("button")
      .find((button) => button.children.includes("Disconnect vault"))
      .props.onClick();
  });
  await act(async () => {
    navButton("Secret Policies").props.onClick();
  });
  assert.equal(loginLookupLabel(), undefined);
  await act(async () => {
    renderer.root
      .findAllByType("input")
      .find((input) => input.props.placeholder === "Provider reference")
      .props.onChange({ target: { value: "0123456789abcdef0123456789" } });
    renderer.root
      .findAllByType("input")
      .find((input) => input.props.placeholder === "MY_SERVICE_KEY")
      .props.onChange({ target: { value: "AFTER_DISCONNECT" } });
  });
  const policyForm = renderer.root
    .findAllByType("form")
    .find((form) =>
      form
        .findAllByType("button")
        .some((button) => button.children.includes("+ Register Policy")),
    );
  await act(async () => {
    await policyForm.props.onSubmit({ preventDefault() {} });
  });
  assert.equal(savedPolicy.connectionId, "bws-policy");
  assert.equal(Object.hasOwn(savedPolicy, "findSelector"), false);
});

test("Secrets tab creates, updates and confirms exact-field deletion", async (t) => {
  const originalWindow = globalThis.window;
  const originalFetch = globalThis.fetch;
  const calls = [];
  const compareCalls = [];
  const ensureCalls = [];
  const deleteCalls = [];
  const privateInputCalls = [];
  const privateInputPageCalls = [];
  const privateInputCursor = `private-input-active:${String(
    Math.floor(Date.now() / 1000),
  ).padStart(12, "0")}:${"c".repeat(43)}`;
  const privateInputRequest = {
    requestId: "r".repeat(43),
    alias: "MCP_WRITE",
    intent: "ensure",
    target: "0123456789abcdef0123456789#mcp-field",
    connectionId: "onepassword-create",
    expiresAt: Math.floor(Date.now() / 1000) + 1800,
    status: "pending",
  };
  const olderPrivateInputRequest = {
    ...privateInputRequest,
    requestId: "s".repeat(43),
    target: "Older pending request",
  };
  let holdFind = false;
  let finishFind;
  globalThis.window = {
    location: {
      search: "?view=dashboard&tab=secrets",
      origin: "https://broker.example.test",
    },
  };
  globalThis.fetch = async (url, options = {}) => {
    if (url === "/api/auth/me")
      return Response.json({
        authenticated: true,
        user: {
          id: "customer-one",
          name: "Customer One",
          provider: "github",
          plan: "free",
          quotaUsed: 0,
          quotaLimit: 10000,
        },
      });
    if (url === "/api/user/policies") return Response.json({ policies: [] });
    if (String(url).startsWith("/api/user/secrets/private-inputs")) {
      if (options.method === "POST") {
        privateInputCalls.push(JSON.parse(options.body));
        return Response.json({
          status: "unchanged",
          reference: "0123456789abcdef0123456789#mcp-field",
          verified: true,
          replayed: false,
        });
      }
      if (String(url).includes("?cursor=")) {
        privateInputPageCalls.push(String(url));
        return Response.json({
          requests: [olderPrivateInputRequest],
          nextCursor: null,
        });
      }
      return Response.json({
        requests: [privateInputRequest],
        nextCursor: privateInputCursor,
      });
    }
    if (url === "/api/user/vault-connections")
      return Response.json({
        providerCapabilities: {},
        connections: [
          {
            id: "bitwarden-read-only",
            alias: "work-bws",
            provider: "bitwarden",
            revision: 1,
            capabilities: {
              read: true,
              create: false,
              update: false,
              conditionalUpdate: false,
              verifyAfterWrite: false,
              delete: false,
            },
          },
          {
            id: "onepassword-create",
            alias: "personal-op",
            provider: "onepassword-connect",
            revision: 1,
            capabilities: {
              read: true,
              create: true,
              update: true,
              conditionalUpdate: false,
              verifyAfterWrite: true,
              delete: true,
            },
          },
          {
            id: "onepassword-other",
            alias: "shared-op",
            provider: "onepassword-connect",
            revision: 1,
            capabilities: {
              read: true,
              create: true,
              update: true,
              conditionalUpdate: false,
              verifyAfterWrite: true,
              delete: true,
            },
          },
          {
            id: "onepassword-service-account",
            alias: "team-op",
            provider: "onepassword-service-account",
            revision: 1,
            capabilities: {
              read: false,
              create: false,
              update: false,
              conditionalUpdate: false,
              verifyAfterWrite: false,
              delete: false,
            },
          },
        ],
      });
    if (url === "/api/user/secrets/save") {
      const body = JSON.parse(options.body);
      calls.push(body);
      if (calls.length === 1)
        return new Response('{"status":', { status: 200 });
      if (calls.length === 2)
        return Response.json({ error: "unauthorized" }, { status: 401 });
      if (calls.length === 3) return new Response("not-json", { status: 409 });
      return Response.json({
        status: "created",
        reference: "0123456789abcdef0123456789#field-id",
        verified: true,
        replayed: true,
      });
    }
    if (url === "/api/user/secrets/update") {
      calls.push(JSON.parse(options.body));
      return Response.json({
        status: "updated",
        reference: "0123456789abcdef0123456789#field-id",
        verified: true,
        replayed: false,
      });
    }
    if (url === "/api/user/secrets/compare") {
      const body = JSON.parse(options.body);
      compareCalls.push(body);
      return Response.json({
        matches: body.value !== "synthetic-ensure-changed-value",
      });
    }
    if (url === "/api/user/secrets/ensure") {
      const body = JSON.parse(options.body);
      ensureCalls.push(body);
      return Response.json({
        status:
          body.value === "synthetic-ensure-matching-value"
            ? "unchanged"
            : "updated",
        reference: body.reference,
        verified: true,
      });
    }
    if (url === "/api/user/secrets/delete") {
      deleteCalls.push(JSON.parse(options.body));
      if (deleteCalls.length === 1)
        return new Response('{"status":', { status: 200 });
      return Response.json({
        status: "deleted",
        reference: "0123456789abcdef0123456789#field-id",
        verified: true,
        replayed: true,
      });
    }
    if (url === "/api/user/secrets/find") {
      const body = JSON.parse(options.body);
      if (holdFind)
        return new Promise((resolve) => {
          finishFind = () =>
            resolve(
              Response.json({
                status: "available",
                provider: "onepassword-connect",
                reference: body.reference,
              }),
            );
        });
      return Response.json({
        status: "available",
        provider: "onepassword-connect",
        reference: body.reference,
      });
    }
    throw new Error("Unexpected UI fixture request: " + url);
  };

  let renderer;
  t.after(() => {
    if (renderer) act(() => renderer.unmount());
    globalThis.window = originalWindow;
    globalThis.fetch = originalFetch;
  });
  await act(async () => {
    renderer = create(React.createElement(App));
  });

  const destination = renderer.root.findByProps({
    "aria-label": "Destination connection",
  });
  const options = destination.findAllByType("option");
  assert.equal(
    options.find((option) => option.props.value === "bitwarden-read-only").props
      .disabled,
    true,
  );
  assert.equal(
    options.find(
      (option) => option.props.value === "onepassword-service-account",
    ).props.disabled,
    true,
  );

  await act(async () => {
    destination.props.onChange({ target: { value: "onepassword-create" } });
  });
  const title = renderer.root.findByProps({ "aria-label": "Secret title" });
  const value = renderer.root.findByProps({ "aria-label": "Secret value" });
  assert.equal(value.props.type, "password");
  assert.equal(value.props.autoComplete, "new-password");
  await act(async () => {
    title.props.onChange({ target: { value: "API credential" } });
    value.props.onChange({ target: { value: "synthetic-secret-value" } });
  });

  const form = renderer.root.findByProps({ "aria-label": "Save secret" });
  await act(async () => {
    await form.props.onSubmit({ preventDefault() {} });
  });
  const unknown = renderer.root
    .findAllByProps({ role: "alert" })
    .find((node) =>
      node.children.join("").includes("outcome is not confirmed"),
    );
  assert.ok(unknown);
  assert.equal(destination.props.disabled, true);
  assert.equal(title.props.disabled, true);
  assert.equal(value.props.disabled, true);
  const retry = renderer.root
    .findAllByType("button")
    .find((button) => button.children.includes("Retry safely"));
  assert.ok(retry);
  const operationId = calls[0].operationId;
  assert.match(operationId, /^save_[A-Za-z0-9_-]{20,128}$/);
  assert.deepEqual(calls[0], {
    connectionId: "onepassword-create",
    operationId,
    title: "API credential",
    value: "synthetic-secret-value",
  });

  await act(async () => {
    await form.props.onSubmit({ preventDefault() {} });
  });
  assert.equal(calls.length, 2);
  assert.equal(calls[1].operationId, operationId);
  assert.equal(title.props.disabled, true);
  assert.equal(value.props.disabled, true);
  assert.match(JSON.stringify(renderer.toJSON()), /outcome is not confirmed/);

  await act(async () => {
    await form.props.onSubmit({ preventDefault() {} });
  });
  assert.equal(calls.length, 3);
  assert.equal(calls[2].operationId, operationId);
  assert.equal(title.props.disabled, true);
  assert.equal(value.props.disabled, true);
  assert.match(JSON.stringify(renderer.toJSON()), /outcome is not confirmed/);

  await act(async () => {
    await form.props.onSubmit({ preventDefault() {} });
  });
  assert.equal(calls.length, 4);
  assert.equal(calls[2].value, "synthetic-secret-value");
  assert.equal(calls[3].operationId, operationId);
  assert.equal(calls[3].value, "synthetic-secret-value");
  assert.equal(value.props.value, "");
  const rendered = JSON.stringify(renderer.toJSON());
  assert.equal(rendered.includes("synthetic-secret-value"), false);
  assert.match(rendered, /created.*and verified/);
  assert.match(rendered, /0123456789abcdef0123456789#field-id/);

  const findConnection = renderer.root.findByProps({
    "aria-label": "Find connection",
  });
  const findForm = renderer.root.findByProps({
    "aria-label": "Find secret by reference",
  });
  const reference = "0123456789abcdef0123456789#field-id";
  await act(async () => {
    findConnection.props.onChange({
      target: { value: "onepassword-create" },
    });
    renderer.root
      .findByProps({ "aria-label": "Secret reference" })
      .props.onChange({ target: { value: reference } });
  });
  await act(async () => {
    await findForm.props.onSubmit({ preventDefault() {} });
  });
  assert.match(JSON.stringify(renderer.toJSON()), /Reference is available/);
  assert.equal(
    JSON.stringify(renderer.toJSON()).includes("synthetic-secret-value"),
    false,
  );

  await act(async () => {
    findConnection.props.onChange({ target: { value: "onepassword-create" } });
    renderer.root
      .findByProps({ "aria-label": "Secret reference" })
      .props.onChange({
        target: { value: "stale-reference" },
      });
  });
  holdFind = true;
  await act(async () => {
    findForm.props.onSubmit({ preventDefault() {} });
  });
  await act(async () => {
    findConnection.props.onChange({ target: { value: "bitwarden-read-only" } });
  });
  await act(async () => {
    finishFind();
    await new Promise((resolve) => setImmediate(resolve));
  });
  assert.doesNotMatch(
    JSON.stringify(renderer.toJSON()),
    /Reference is available/,
  );

  const operationMode = renderer.root.findByProps({
    "aria-label": "Secret operation",
  });
  await act(async () => {
    operationMode.props.onChange({ target: { value: "update" } });
  });
  const updateReference = renderer.root.findByProps({
    "aria-label": "Update secret reference",
  });
  const updateValue = renderer.root.findByProps({
    "aria-label": "Secret value",
  });
  await act(async () => {
    updateReference.props.onChange({ target: { value: reference } });
    updateValue.props.onChange({ target: { value: "synthetic-update-value" } });
  });
  await act(async () => {
    await renderer.root
      .findByProps({ "aria-label": "Save secret" })
      .props.onSubmit({ preventDefault() {} });
  });
  assert.equal(calls.length, 5);
  assert.equal(
    JSON.stringify(calls[4]),
    JSON.stringify({
      connectionId: "onepassword-create",
      operationId: calls[4].operationId,
      reference,
      value: "synthetic-update-value",
    }),
  );
  assert.match(calls[4].operationId, /^save_[A-Za-z0-9_-]{20,128}$/);
  assert.equal(
    renderer.root.findByProps({ "aria-label": "Secret value" }).props.value,
    "",
  );
  assert.match(JSON.stringify(renderer.toJSON()), /updated.*and verified/);
  assert.equal(
    JSON.stringify(renderer.toJSON()).includes("synthetic-update-value"),
    false,
  );

  await act(async () => {
    updateReference.props.onChange({ target: { value: reference } });
    updateValue.props.onChange({
      target: { value: "synthetic-private-compare-ui-value" },
    });
  });
  const compareButton = renderer.root
    .findAllByType("button")
    .find((button) => button.children.includes("Compare privately"));
  assert.ok(compareButton);
  assert.equal(compareButton.props.disabled, false);
  await act(async () => {
    await compareButton.props.onClick();
  });
  assert.deepEqual(compareCalls, [
    {
      connectionId: "onepassword-create",
      reference,
      value: "synthetic-private-compare-ui-value",
    },
  ]);
  assert.equal(updateValue.props.value, "");
  assert.match(JSON.stringify(renderer.toJSON()), /matches the field/);
  assert.equal(
    JSON.stringify(renderer.toJSON()).includes(
      "synthetic-private-compare-ui-value",
    ),
    false,
  );
  assert.equal(calls.length, 5, "comparison does not dispatch a write");

  await act(async () => {
    updateValue.props.onChange({
      target: { value: "synthetic-ensure-matching-value" },
    });
  });
  const ensureButton = () =>
    renderer.root
      .findAllByType("button")
      .find(
        (button) =>
          button.children.includes("Ensure field") &&
          typeof button.props.onClick === "function",
      );
  assert.ok(ensureButton());
  await act(async () => {
    await ensureButton().props.onClick();
  });
  assert.equal(calls.length, 5, "ensure uses its atomic customer endpoint");
  assert.equal(ensureCalls.length, 1);
  assert.equal(ensureCalls[0].connectionId, "onepassword-create");
  assert.equal(ensureCalls[0].reference, reference);
  assert.equal(updateValue.props.value, "");
  assert.match(JSON.stringify(renderer.toJSON()), /field already matches/i);
  assert.equal(
    JSON.stringify(renderer.toJSON()).includes(
      "synthetic-ensure-matching-value",
    ),
    false,
  );

  await act(async () => {
    updateValue.props.onChange({
      target: { value: "synthetic-ensure-changed-value" },
    });
  });
  await act(async () => {
    await ensureButton().props.onClick();
  });
  assert.equal(calls.length, 5, "ensure stays one atomic endpoint call");
  assert.equal(ensureCalls.length, 2);
  assert.equal(ensureCalls[1].reference, reference);
  assert.equal(ensureCalls[1].value, "synthetic-ensure-changed-value");
  assert.equal(updateValue.props.value, "");
  assert.match(
    JSON.stringify(renderer.toJSON()),
    /field differed.*updated and verified/i,
  );
  assert.equal(
    JSON.stringify(renderer.toJSON()).includes(
      "synthetic-ensure-changed-value",
    ),
    false,
  );

  await act(async () => {
    operationMode.props.onChange({ target: { value: "delete" } });
  });
  const deleteReference = renderer.root.findByProps({
    "aria-label": "Delete secret reference",
  });
  await act(async () => {
    deleteReference.props.onChange({ target: { value: reference } });
  });
  const deleteButton = () =>
    renderer.root
      .findAllByType("button")
      .find((button) => button.children.includes("Delete field"));
  assert.equal(deleteButton().props.disabled, true);
  assert.equal(
    renderer.root.findAllByProps({ "aria-label": "Secret value" }).length,
    0,
  );
  const deleteConfirmation = renderer.root.findByProps({
    "aria-label": "Confirm exact field deletion",
  });
  await act(async () => {
    deleteConfirmation.props.onChange({ target: { checked: true } });
  });
  assert.equal(deleteButton().props.disabled, false);
  await act(async () => {
    destination.props.onChange({ target: { value: "onepassword-other" } });
  });
  assert.equal(deleteConfirmation.props.checked, false);
  assert.equal(deleteButton().props.disabled, true);
  await act(async () => {
    destination.props.onChange({ target: { value: "onepassword-create" } });
  });
  assert.equal(deleteConfirmation.props.checked, false);
  assert.equal(deleteButton().props.disabled, true);
  await act(async () => {
    deleteConfirmation.props.onChange({ target: { checked: true } });
  });
  assert.equal(deleteButton().props.disabled, false);
  const saveForm = renderer.root.findByProps({ "aria-label": "Save secret" });
  await act(async () => {
    await saveForm.props.onSubmit({ preventDefault() {} });
  });
  assert.match(
    JSON.stringify(renderer.toJSON()),
    /operation outcome is not confirmed/,
  );
  assert.equal(deleteCalls.length, 1);
  assert.deepEqual(deleteCalls[0], {
    connectionId: "onepassword-create",
    operationId: deleteCalls[0].operationId,
    reference,
  });
  assert.match(deleteCalls[0].operationId, /^save_[A-Za-z0-9_-]{20,128}$/);
  assert.equal(Object.hasOwn(deleteCalls[0], "value"), false);
  await act(async () => {
    await saveForm.props.onSubmit({ preventDefault() {} });
  });
  assert.equal(deleteCalls.length, 2);
  assert.equal(deleteCalls[1].operationId, deleteCalls[0].operationId);
  assert.deepEqual(deleteCalls[1], deleteCalls[0]);
  assert.match(
    JSON.stringify(renderer.toJSON()),
    /Secret field deleted.*and verified/,
  );
  assert.equal(
    JSON.stringify(renderer.toJSON()).includes("synthetic-secret-value"),
    false,
  );

  const privateForm = renderer.root.findByProps({
    "aria-label": "Fulfill save request for MCP_WRITE",
  });
  const privateValue = privateForm.findByType("input");
  assert.equal(privateValue.props.type, "password");
  assert.equal(privateValue.props.disabled, false);
  await act(async () => {
    privateValue.props.onChange({ target: { value: "owner-private-value" } });
  });
  const privateSubmit = privateForm.findByType("button");
  assert.equal(privateSubmit.props.disabled, false);
  await act(async () => {
    privateForm.props.onSubmit({ preventDefault() {} });
    await new Promise((resolve) => setImmediate(resolve));
  });
  assert.deepEqual(privateInputCalls, [
    {
      requestId: privateInputRequest.requestId,
      value: "owner-private-value",
    },
  ]);
  assert.equal(
    JSON.stringify(renderer.toJSON()).includes("owner-private-value"),
    false,
  );
  assert.match(
    JSON.stringify(renderer.toJSON()),
    /Already matched; no write was made/,
  );

  const olderRequestsButton = renderer.root
    .findAllByType("button")
    .find((button) => button.children.includes("Show older requests"));
  assert.ok(olderRequestsButton);
  olderPrivateInputRequest.expiresAt = Math.floor(Date.now() / 1000) - 1;
  await act(async () => {
    await olderRequestsButton.props.onClick();
  });
  assert.deepEqual(privateInputPageCalls, [
    `/api/user/secrets/private-inputs?cursor=${encodeURIComponent(privateInputCursor)}`,
  ]);
  assert.equal(
    renderer.root.findAllByProps({
      "aria-label": "Fulfill save request for MCP_WRITE",
    }).length,
    0,
  );
  assert.match(JSON.stringify(renderer.toJSON()), /Older pending request/);
  assert.match(
    JSON.stringify(renderer.toJSON()),
    /This request expired before it was fulfilled/,
  );
});
