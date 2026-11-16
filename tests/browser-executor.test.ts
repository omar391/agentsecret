import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { calculateJwkThumbprint, compactVerify, importJWK } from "jose";
import { generateTotp, totpMatches } from "../cli/browser/totp";
import {
  createExecutorIdentity,
  executorProof,
  executorSigningPair,
  executorThumbprint,
  publicExecutorIdentity,
} from "../cli/browser/executor";
import {
  ExecutorStore,
  type ExecutorBackend,
} from "../cli/browser/executor-store";
import {
  BrowserDriver,
  BrowserDriverError,
  type BrowserTransport,
} from "../cli/browser/driver";
import {
  executeBrowserAction,
  type BrowserFillDriver,
} from "../cli/browser/execute";
import {
  BrowserGrantError,
  BrowserGrantLedger,
  type BrowserGrant,
} from "../cli/browser/grant";

const RFC_SECRET = ["GEZDGNBVGY3TQOJQ", "GEZDGNBVGY3TQOJQ"].join("");

function grant(overrides: Partial<BrowserGrant> = {}): BrowserGrant {
  return {
    grantId: "grant-1",
    accountId: "account-1",
    alias: "example-login",
    origin: "https://example.com",
    kinds: ["fill", "totp"],
    expiresAt: 2_000_000,
    redeemedAt: null,
    fieldSelector: "#password",
    ...overrides,
  };
}

function request(overrides: Record<string, unknown> = {}) {
  return {
    grantId: "grant-1",
    accountId: "account-1",
    origin: "https://example.com",
    kind: "fill" as const,
    fieldSelector: "#password",
    ...overrides,
  };
}

test("TOTP matches the RFC 6238 SHA-1 reference vectors", () => {
  const vectors: Array<[number, string]> = [
    [59, "94287082"],
    [1_111_111_109, "07081804"],
    [1_111_111_111, "14050471"],
    [1_234_567_890, "89005924"],
    [2_000_000_000, "69279037"],
    [20_000_000_000, "65353130"],
  ];
  for (const [seconds, expected] of vectors)
    assert.equal(
      generateTotp(RFC_SECRET, seconds * 1000, { digits: 8 }),
      expected,
    );
});

test("TOTP preserves leading zeroes and rejects invalid input", () => {
  assert.equal(
    generateTotp(RFC_SECRET, 1_111_111_109_000, { digits: 8 }),
    "07081804",
  );
  assert.throws(() => generateTotp("", 0), /totp_secret_invalid/);
  assert.throws(() => generateTotp("ABCD1", 0), /totp_secret_invalid/);
  assert.throws(
    () => generateTotp(RFC_SECRET, 0, { digits: 4 }),
    /totp_digits_invalid/,
  );
  assert.throws(
    () => generateTotp(RFC_SECRET, 0, { periodSeconds: 0 }),
    /totp_period_invalid/,
  );
  assert.throws(() => generateTotp(RFC_SECRET, -1), /totp_time_invalid/);
});

test("TOTP is stateless, stable inside a period, and changes at the boundary", () => {
  assert.equal(
    generateTotp(RFC_SECRET, 30_000),
    generateTotp(RFC_SECRET, 59_999),
  );
  assert.notEqual(
    generateTotp(RFC_SECRET, 59_999),
    generateTotp(RFC_SECRET, 60_000),
  );
  const expected = generateTotp(RFC_SECRET, 1_000);
  assert.equal(totpMatches(expected, expected), true);
  assert.equal(totpMatches(expected, "000000"), expected === "000000");
});

test("grant redemption returns only a value-free receipt and refuses replay", () => {
  const ledger = new BrowserGrantLedger();
  ledger.issue(grant());
  const receipt = ledger.redeem(request(), 1_000);
  assert.deepEqual(receipt, {
    status: "authorized",
    grantId: "grant-1",
    alias: "example-login",
    origin: "https://example.com",
    kind: "fill",
    fieldSelector: "#password",
    expiresAt: 2_000_000,
  });
  assert.equal("value" in receipt, false);
  assert.throws(
    () => ledger.redeem(request(), 1_001),
    (error: unknown) =>
      error instanceof BrowserGrantError && error.code === "grant_replayed",
  );
});

test("grant refuses wrong account, origin, action, field, expiry and unknown ids", () => {
  const cases: Array<[Record<string, unknown>, number, string]> = [
    [{ accountId: "other" }, 1_000, "account_mismatch"],
    [{ origin: "https://evil.example" }, 1_000, "origin_mismatch"],
    [{ origin: "http://example.com" }, 1_000, "origin_mismatch"],
    [{ kind: "capture" }, 1_000, "action_not_granted"],
    [{ fieldSelector: "#other" }, 1_000, "field_mismatch"],
    [{}, 2_000_000, "grant_expired"],
    [{ grantId: "missing" }, 1_000, "grant_unknown"],
  ];
  for (const [overrides, now, code] of cases) {
    const ledger = new BrowserGrantLedger();
    ledger.issue(grant());
    assert.throws(
      () => ledger.redeem(request(overrides), now),
      (error: unknown) =>
        error instanceof BrowserGrantError && error.code === code,
      code,
    );
  }
});

test("grant origin comparison is exact after safe normalization", () => {
  const ledger = new BrowserGrantLedger();
  ledger.issue(grant({ origin: "https://Example.com:443" }));
  const receipt = ledger.redeem(
    request({ origin: "https://example.com" }),
    1_000,
  );
  assert.equal(receipt.origin, "https://example.com");

  const local = new BrowserGrantLedger();
  local.issue(grant({ origin: "http://localhost:3000" }));
  assert.equal(
    local.redeem(request({ origin: "http://localhost:3000" }), 1_000).origin,
    "http://localhost:3000",
  );
  assert.throws(
    () => local.redeem(request({ origin: "http://example.com" }), 1_000),
    /origin_mismatch/,
  );
});

test("grant issue refuses duplicate ids and empty action sets", () => {
  const ledger = new BrowserGrantLedger();
  ledger.issue(grant());
  assert.throws(() => ledger.issue(grant()), /grant_replayed/);
  assert.throws(
    () => new BrowserGrantLedger().issue(grant({ kinds: [] })),
    /action_not_granted/,
  );
});

class FakeTransport implements BrowserTransport {
  origin = "https://example.com";
  found = true;
  currentValue = "page-current-value";
  childFrames: unknown[] = [];
  loaderId = "loader-1";
  failInsert = false;
  navigateAfterEvaluate = false;
  navigateDuringWorldCreation = false;
  navigateAfterRead = false;
  readonly methods: string[] = [];
  readonly inserted: string[] = [];

  async send(method: string, params: Record<string, unknown>) {
    this.methods.push(method);
    if (method === "Page.getFrameTree")
      return {
        frameTree: {
          frame: { id: "frame-1", loaderId: this.loaderId, url: this.origin },
          childFrames: this.childFrames,
        },
      };
    if (method === "Page.createIsolatedWorld") {
      if (this.navigateDuringWorldCreation) this.loaderId = "loader-2";
      return { executionContextId: 7 };
    }
    if (method === "Runtime.evaluate") {
      const expression = String(params.expression ?? "");
      if (expression.includes('__agentsecret = "FILL"')) {
        if (this.failInsert) throw new Error("raw transport secret 1234");
        if (!this.found) return { result: { value: "field" } };
        const match = expression.match(
          /setter\.call\(el, ("(?:\\.|[^"\\])*")\)/u,
        );
        if (!match) throw new Error("missing_fill_value");
        this.inserted.push(JSON.parse(match[1]!) as string);
        if (this.navigateAfterEvaluate) this.loaderId = "loader-2";
        return { result: { value: "filled" } };
      }
      if (expression.includes('__agentsecret = "READ"')) {
        if (this.navigateAfterRead) this.loaderId = "loader-2";
        return {
          result: {
            value: this.found ? this.currentValue : null,
          },
        };
      }
      throw new Error("unexpected_expression");
    }
    throw new Error("unexpected_method");
  }
  close() {}
}

test("driver fills only after an exact origin check and returns no value", async () => {
  const transport = new FakeTransport();
  const driver = new BrowserDriver(transport);
  const secret = "correct horse battery staple";
  const receipt = await driver.fill({
    origin: "https://example.com",
    selector: "#password",
    value: secret,
  });
  assert.deepEqual(receipt, {
    status: "filled",
    origin: "https://example.com",
    selector: "#password",
  });
  assert.deepEqual(transport.methods, [
    "Page.getFrameTree",
    "Page.createIsolatedWorld",
    "Page.getFrameTree",
    "Runtime.evaluate",
    "Page.getFrameTree",
  ]);
  assert.deepEqual(transport.inserted, [secret]);
  assert.equal(JSON.stringify(receipt).includes(secret), false);
});

test("driver refuses a different live origin before touching the field", async () => {
  const transport = new FakeTransport();
  transport.origin = "https://evil.example";
  const driver = new BrowserDriver(transport);
  await assert.rejects(
    driver.fill({
      origin: "https://example.com",
      selector: "#password",
      value: "secret",
    }),
    /browser_origin_mismatch/,
  );
  assert.equal(transport.inserted.length, 0);
  assert.deepEqual(transport.methods, ["Page.getFrameTree"]);
});

test("driver refuses a missing field and sanitizes transport errors", async () => {
  const transport = new FakeTransport();
  transport.found = false;
  await assert.rejects(
    new BrowserDriver(transport).fill({
      origin: "https://example.com",
      selector: "#missing",
      value: "secret",
    }),
    /browser_field_missing/,
  );
  assert.equal(transport.inserted.length, 0);

  const failing = new FakeTransport();
  failing.failInsert = true;
  await assert.rejects(
    new BrowserDriver(failing).fill({
      origin: "https://example.com",
      selector: "#password",
      value: "sensitive-value",
    }),
    (error: unknown) =>
      error instanceof BrowserDriverError &&
      error.code === "browser_transport_error" &&
      !error.message.includes("sensitive-value"),
  );
});

test("driver refuses child frames and navigation during a protected action", async () => {
  const framed = new FakeTransport();
  framed.childFrames = [{ frame: { id: "child" } }];
  await assert.rejects(
    new BrowserDriver(framed).fill({
      origin: "https://example.com",
      selector: "#password",
      value: "secret-value",
    }),
    /browser_frame_denied/,
  );
  assert.deepEqual(framed.inserted, []);

  const navigating = new FakeTransport();
  navigating.navigateAfterEvaluate = true;
  await assert.rejects(
    new BrowserDriver(navigating).fill({
      origin: "https://example.com",
      selector: "#password",
      value: "secret-value",
    }),
    /browser_navigation_changed/,
  );
  assert.deepEqual(navigating.inserted, ["secret-value"]);
});

test("driver refuses navigation during world creation and between ensure steps", async () => {
  const duringWorld = new FakeTransport();
  duringWorld.navigateDuringWorldCreation = true;
  await assert.rejects(
    new BrowserDriver(duringWorld).fill({
      origin: "https://example.com",
      selector: "#password",
      value: "secret-value",
    }),
    /browser_navigation_changed/,
  );
  assert.deepEqual(duringWorld.inserted, []);

  const betweenSteps = new FakeTransport();
  betweenSteps.navigateAfterRead = true;
  await assert.rejects(
    new BrowserDriver(betweenSteps).ensure({
      origin: "https://example.com",
      selector: "#password",
      value: "secret-value",
      authorizeDispatch() {},
    }),
    /browser_navigation_changed/,
  );
  assert.deepEqual(betweenSteps.inserted, []);
});

test("driver never requests DOM snapshots, cookies, recordings or debug data", async () => {
  const transport = new FakeTransport();
  await new BrowserDriver(transport).fill({
    origin: "https://example.com",
    selector: "#password",
    value: "secret-value",
  });
  const forbidden =
    /^(?:DOM\.|Network\.getAllCookies|Storage\.|Page\.captureScreenshot|Tracing\.|Browser\.getVersion)/u;
  assert.equal(
    transport.methods.some((method) => forbidden.test(method)),
    false,
  );
});

test("driver generates TOTP at the action and preserves leading zeroes", async () => {
  const transport = new FakeTransport();
  const receipt = await new BrowserDriver(transport).fillTotp({
    origin: "https://example.com",
    selector: "#otp",
    secret: RFC_SECRET,
    atMilliseconds: 1_111_111_109_000,
    totp: { digits: 8 },
  });
  assert.deepEqual(transport.inserted, ["07081804"]);
  assert.equal(receipt.status, "filled_totp");
  assert.equal(JSON.stringify(receipt).includes("07081804"), false);
});

test("driver rejects unsafe origins and empty selectors before dispatch", async () => {
  const transport = new FakeTransport();
  const driver = new BrowserDriver(transport);
  await assert.rejects(
    driver.fill({ origin: "http://example.com", selector: "#x", value: "v" }),
    /browser_target_invalid/,
  );
  await assert.rejects(
    driver.fill({
      origin: "https://example.com/?q=1",
      selector: "#x",
      value: "v",
    }),
    /browser_target_invalid/,
  );
  await assert.rejects(
    driver.fill({ origin: "https://example.com", selector: "", value: "v" }),
    /browser_target_invalid/,
  );
  assert.deepEqual(transport.methods, []);
});

class FakeFillDriver implements BrowserFillDriver {
  readonly fills: Array<{ origin: string; selector: string; value: string }> =
    [];
  readonly totps: Array<{ origin: string; selector: string; secret: string }> =
    [];
  current = "current-value";
  async read(input: { origin: string; selector: string }) {
    void input;
    return this.current;
  }
  async fill(input: {
    origin: string;
    selector: string;
    value: string;
    authorizeDispatch?: () => void;
  }) {
    input.authorizeDispatch?.();
    this.fills.push({
      origin: input.origin,
      selector: input.selector,
      value: input.value,
    });
    this.current = input.value;
    return {
      status: "filled" as const,
      origin: input.origin,
      selector: input.selector,
    };
  }
  async fillTotp(input: {
    origin: string;
    selector: string;
    secret: string;
    atMilliseconds: number | (() => number);
    authorizeDispatch?: () => void;
  }) {
    input.authorizeDispatch?.();
    const atMilliseconds =
      typeof input.atMilliseconds === "function"
        ? input.atMilliseconds()
        : input.atMilliseconds;
    this.totps.push({
      origin: input.origin,
      selector: input.selector,
      secret: input.secret,
      atMilliseconds,
    });
    return {
      status: "filled_totp" as const,
      origin: input.origin,
      selector: input.selector,
    };
  }
  async ensure(input: { origin: string; selector: string; value: string }) {
    void input.origin;
    void input.selector;
    const unchanged = this.current === input.value;
    if (!unchanged) await this.fill(input);
    return { unchanged, verified: this.current === input.value };
  }
}

function execution(
  ledger: BrowserGrantLedger,
  driver: FakeFillDriver,
  overrides: Record<string, unknown> = {},
) {
  return executeBrowserAction({
    ledger,
    request: request(overrides),
    atMilliseconds: 1_000,
    driver,
    resolveFill: async () => ({
      origin: "https://example.com",
      selector: "#password",
      value: "resolved-secret",
    }),
    resolveTotp: async () => ({
      origin: "https://example.com",
      selector: "#password",
      secret: RFC_SECRET,
    }),
    resolveCapture: async () => ({
      origin: "https://example.com",
      selector: "#password",
    }),
    storeCaptured: async () => ({ reference: "ref-captured", verified: true }),
    resolveDesired: async () => ({
      origin: "https://example.com",
      selector: "#password",
      value: "desired-value",
    }),
  });
}

test("execute redeems the grant, enforces the binding and returns no value", async () => {
  const ledger = new BrowserGrantLedger();
  ledger.issue(grant());
  const driver = new FakeFillDriver();
  const output = await execution(ledger, driver);
  assert.equal(output.result, "filled");
  assert.equal(output.receipt.kind, "fill");
  assert.deepEqual(driver.fills, [
    {
      origin: "https://example.com",
      selector: "#password",
      value: "resolved-secret",
    },
  ]);
  assert.equal(JSON.stringify(output).includes("resolved-secret"), false);
});

test("execute resolves TOTP only after redemption and never returns the code", async () => {
  const ledger = new BrowserGrantLedger();
  ledger.issue(grant({ kinds: ["totp"] }));
  const driver = new FakeFillDriver();
  const output = await execution(ledger, driver, { kind: "totp" });
  assert.equal(output.result, "filled_totp");
  assert.equal(driver.totps.length, 1);
  assert.equal(driver.totps[0].secret, RFC_SECRET);
  const code = generateTotp(RFC_SECRET, 1_000);
  assert.equal(JSON.stringify(output).includes(code), false);
});

test("TOTP is generated at use time and refuses an expired grant", async () => {
  const ledger = new BrowserGrantLedger();
  ledger.issue(grant({ kinds: ["totp"] }));
  const driver = new FakeFillDriver();
  const output = await executeBrowserAction({
    ledger,
    request: request({ kind: "totp" }),
    atMilliseconds: 1_000,
    clock: () => 30_001,
    driver,
    resolveFill: async () => {
      throw new Error("unused");
    },
    resolveTotp: async () => ({
      origin: "https://example.com",
      selector: "#password",
      secret: RFC_SECRET,
    }),
    resolveCapture: async () => ({
      origin: "https://example.com",
      selector: "#password",
    }),
    storeCaptured: async () => ({ reference: "unused", verified: false }),
    resolveDesired: async () => ({
      origin: "https://example.com",
      selector: "#password",
      value: "unused",
    }),
  });
  assert.equal(driver.totps[0]?.atMilliseconds, 30_001);
  assert.equal(JSON.stringify(output).includes(RFC_SECRET), false);

  const expired = new BrowserGrantLedger();
  expired.issue(grant({ kinds: ["totp"], grantId: "expired-totp" }));
  const expiredDriver = new FakeFillDriver();
  await assert.rejects(
    executeBrowserAction({
      ledger: expired,
      request: request({ kind: "totp", grantId: "expired-totp" }),
      atMilliseconds: 1_000,
      clock: () => 2_000_000,
      driver: expiredDriver,
      resolveFill: async () => {
        throw new Error("unused");
      },
      resolveTotp: async () => ({
        origin: "https://example.com",
        selector: "#password",
        secret: RFC_SECRET,
      }),
      resolveCapture: async () => ({
        origin: "https://example.com",
        selector: "#password",
      }),
      storeCaptured: async () => ({ reference: "unused", verified: false }),
      resolveDesired: async () => ({
        origin: "https://example.com",
        selector: "#password",
        value: "unused",
      }),
    }),
    /grant_expired/,
  );
  assert.equal(expiredDriver.totps.length, 0);
});

test("execute refuses a resolved origin that differs from the grant", async () => {
  const ledger = new BrowserGrantLedger();
  ledger.issue(grant());
  const driver = new FakeFillDriver();
  await assert.rejects(
    executeBrowserAction({
      ledger,
      request: request(),
      atMilliseconds: 1_000,
      driver,
      resolveFill: async () => ({
        origin: "https://evil.example",
        selector: "#password",
        value: "resolved-secret",
      }),
      resolveTotp: async () => {
        throw new Error("unused");
      },
      resolveCapture: async () => ({
        origin: "https://example.com",
        selector: "#password",
      }),
      storeCaptured: async () => ({ reference: "ref", verified: true }),
      resolveDesired: async () => ({
        origin: "https://example.com",
        selector: "#password",
        value: "x",
      }),
    }),
    /resolved_binding_mismatch/,
  );
  assert.equal(driver.fills.length, 0);
  assert.throws(
    () => ledger.redeem(request(), 1_001),
    (error: unknown) =>
      error instanceof BrowserGrantError && error.code === "grant_replayed",
  );
});

test("execute consumes the grant even when resolution fails", async () => {
  const ledger = new BrowserGrantLedger();
  ledger.issue(grant());
  await assert.rejects(
    executeBrowserAction({
      ledger,
      request: request(),
      atMilliseconds: 1_000,
      driver: new FakeFillDriver(),
      resolveFill: async () => {
        throw new Error("provider failed with a secret value");
      },
      resolveTotp: async () => {
        throw new Error("unused");
      },
      resolveCapture: async () => ({
        origin: "https://example.com",
        selector: "#password",
      }),
      storeCaptured: async () => ({ reference: "ref", verified: true }),
      resolveDesired: async () => ({
        origin: "https://example.com",
        selector: "#password",
        value: "x",
      }),
    }),
    /provider failed/,
  );
  assert.throws(() => ledger.redeem(request(), 1_001), /grant_replayed/);
});

test("capture stores the page value privately and returns only a reference", async () => {
  const ledger = new BrowserGrantLedger();
  ledger.issue(grant({ kinds: ["capture"] }));
  const driver = new FakeFillDriver();
  driver.current = "page-secret-value";
  const captured: string[] = [];
  const output = await executeBrowserAction({
    ledger,
    request: request({ kind: "capture" }),
    atMilliseconds: 1_000,
    driver,
    resolveFill: async () => {
      throw new Error("unused");
    },
    resolveTotp: async () => {
      throw new Error("unused");
    },
    resolveCapture: async () => ({
      origin: "https://example.com",
      selector: "#password",
    }),
    storeCaptured: async (_receipt, value) => {
      captured.push(value);
      return { reference: "ref-123", verified: true };
    },
    resolveDesired: async () => {
      throw new Error("unused");
    },
  });
  assert.deepEqual(captured, ["page-secret-value"]);
  assert.equal(output.result, "captured");
  assert.equal(output.reference, "ref-123");
  assert.equal(JSON.stringify(output).includes("page-secret-value"), false);
});

test("ensure skips filling when the page already matches", async () => {
  const ledger = new BrowserGrantLedger();
  ledger.issue(grant({ kinds: ["ensure"] }));
  const driver = new FakeFillDriver();
  driver.current = "desired-value";
  const output = await executeBrowserAction({
    ledger,
    request: request({ kind: "ensure" }),
    atMilliseconds: 1_000,
    driver,
    resolveFill: async () => {
      throw new Error("unused");
    },
    resolveTotp: async () => {
      throw new Error("unused");
    },
    resolveCapture: async () => {
      throw new Error("unused");
    },
    storeCaptured: async () => {
      throw new Error("unused");
    },
    resolveDesired: async () => ({
      origin: "https://example.com",
      selector: "#password",
      value: "desired-value",
    }),
  });
  assert.equal(driver.fills.length, 0);
  assert.equal(output.result, "unchanged");
  assert.equal(output.verified, true);
  assert.equal(JSON.stringify(output).includes("desired-value"), false);
});

test("ensure fills and verifies a differing page value privately", async () => {
  const ledger = new BrowserGrantLedger();
  ledger.issue(grant({ kinds: ["ensure"] }));
  const driver = new FakeFillDriver();
  driver.current = "old-value";
  const output = await executeBrowserAction({
    ledger,
    request: request({ kind: "ensure" }),
    atMilliseconds: 1_000,
    driver,
    resolveFill: async () => {
      throw new Error("unused");
    },
    resolveTotp: async () => {
      throw new Error("unused");
    },
    resolveCapture: async () => {
      throw new Error("unused");
    },
    storeCaptured: async () => {
      throw new Error("unused");
    },
    resolveDesired: async () => ({
      origin: "https://example.com",
      selector: "#password",
      value: "desired-value",
    }),
  });
  assert.equal(output.result, "updated");
  assert.equal(output.verified, true);
  assert.deepEqual(driver.fills, [
    {
      origin: "https://example.com",
      selector: "#password",
      value: "desired-value",
    },
  ]);
  assert.equal(JSON.stringify(output).includes("desired-value"), false);
});

test("ensure reports an unverified readback when filling does not take", async () => {
  const ledger = new BrowserGrantLedger();
  ledger.issue(grant({ kinds: ["ensure"] }));
  const driver = new FakeFillDriver();
  driver.current = "old-value";
  driver.fill = async (input) => {
    driver.fills.push(input);
    return {
      status: "filled",
      origin: input.origin,
      selector: input.selector,
    };
  };
  const output = await executeBrowserAction({
    ledger,
    request: request({ kind: "ensure" }),
    atMilliseconds: 1_000,
    driver,
    resolveFill: async () => {
      throw new Error("unused");
    },
    resolveTotp: async () => {
      throw new Error("unused");
    },
    resolveCapture: async () => {
      throw new Error("unused");
    },
    storeCaptured: async () => {
      throw new Error("unused");
    },
    resolveDesired: async () => ({
      origin: "https://example.com",
      selector: "#password",
      value: "desired-value",
    }),
  });
  assert.equal(output.result, "updated");
  assert.equal(output.verified, false);
});

test("capture refuses a binding mismatch before reading the page", async () => {
  const ledger = new BrowserGrantLedger();
  ledger.issue(grant({ kinds: ["capture"] }));
  const driver = new FakeFillDriver();
  let stored = 0;
  await assert.rejects(
    executeBrowserAction({
      ledger,
      request: request({ kind: "capture" }),
      atMilliseconds: 1_000,
      driver,
      resolveFill: async () => {
        throw new Error("unused");
      },
      resolveTotp: async () => {
        throw new Error("unused");
      },
      resolveCapture: async () => ({
        origin: "https://evil.example",
        selector: "#password",
      }),
      storeCaptured: async () => {
        stored += 1;
        return { reference: "ref", verified: true };
      },
      resolveDesired: async () => {
        throw new Error("unused");
      },
    }),
    /resolved_binding_mismatch/,
  );
  assert.equal(stored, 0);
});

test("executor identity is separate, stable and never exports its private key", async () => {
  const first = await createExecutorIdentity(1_000);
  const second = await createExecutorIdentity(1_000);
  assert.match(first.executorId, /^exe_[A-Za-z0-9_-]{43}$/u);
  assert.notEqual(first.executorId, second.executorId);
  assert.equal(Object.hasOwn(first.publicJwk, "d"), false);
  assert.equal(typeof first.privateJwk.d, "string");
  const published = JSON.stringify(publicExecutorIdentity(first));
  assert.equal(published.includes(String(first.privateJwk.d)), false);
  assert.equal(published.includes("privateJwk"), false);
  assert.equal(
    first.executorId,
    "exe_" +
      createHash("sha256")
        .update(await executorThumbprint(first.publicJwk))
        .digest("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/u, ""),
  );
});

test("executor proof verifies with the public key and binds method and URL", async () => {
  const identity = await createExecutorIdentity();
  const proof = await executorProof(
    identity,
    "POST",
    "https://agentsecret.astronlab.com/api/executor/grants?x=1",
  );
  const [headerPart, payloadPart, signaturePart] = proof.split(".");
  assert.equal(headerPart && payloadPart && signaturePart ? true : false, true);
  const header = JSON.parse(Buffer.from(headerPart, "base64url").toString());
  assert.equal(header.typ, "dpop+jwt");
  assert.equal(header.alg, "ES256");
  assert.equal(Object.hasOwn(header.jwk, "d"), false);
  const key = await importJWK(header.jwk, "ES256");
  const verified = await compactVerify(proof, key, { algorithms: ["ES256"] });
  const payload = JSON.parse(Buffer.from(verified.payload).toString());
  assert.equal(payload.htm, "POST");
  assert.equal(
    payload.htu,
    "https://agentsecret.astronlab.com/api/executor/grants",
  );
  assert.equal(typeof payload.jti, "string");
  assert.equal(Number.isSafeInteger(payload.iat), true);
  assert.equal(
    await calculateJwkThumbprint(header.jwk),
    await executorThumbprint(identity.publicJwk),
  );
  await executorSigningPair(identity);
});

test("executor records fail closed when tampered or malformed", async () => {
  const identity = await createExecutorIdentity();
  await assert.rejects(
    executorSigningPair({ ...identity, executorId: "exe_tampered" }),
    /executor_record_invalid/,
  );
  await assert.rejects(
    executorSigningPair({ ...identity, privateJwk: {} }),
    /executor_record_invalid/,
  );
  await assert.rejects(createExecutorIdentity(-1), /executor_time_invalid/);
});

class MemoryExecutorBackend implements ExecutorBackend {
  value: string | undefined;
  read() {
    return this.value;
  }
  write(value: string) {
    this.value = value;
  }
  delete() {
    this.value = undefined;
  }
}

test("executor store round-trips one identity and rejects corrupt records", async () => {
  const backend = new MemoryExecutorBackend();
  const store = new ExecutorStore(backend);
  assert.equal(await store.load(), undefined);
  const identity = await createExecutorIdentity();
  await store.save(identity);
  const loaded = await store.load();
  assert.equal(loaded?.executorId, identity.executorId);
  assert.equal(loaded?.privateJwk.d, identity.privateJwk.d);

  backend.value = "not-json";
  await assert.rejects(store.load(), /executor_store_corrupt/);
  backend.value = Buffer.from(JSON.stringify({ version: 1 })).toString(
    "base64url",
  );
  await assert.rejects(store.load(), /executor_store_corrupt/);
  await assert.rejects(
    store.save({ ...identity, executorId: "exe_tampered" }),
    /executor_store_invalid/,
  );
  store.remove();
  assert.equal(await store.load(), undefined);
});

test("executor store surfaces an unavailable backend", async () => {
  const store = new ExecutorStore({
    read() {
      throw new Error("keychain locked");
    },
    write() {
      throw new Error("keychain locked");
    },
    delete() {
      throw new Error("keychain locked");
    },
  });
  await assert.rejects(store.load(), /executor_store_unavailable/);
  const identity = await createExecutorIdentity();
  await assert.rejects(store.save(identity), /executor_store_unavailable/);
  assert.throws(() => store.remove(), /executor_store_unavailable/);
});

test("verify compares privately and returns only the verified bit", async () => {
  const ledger = new BrowserGrantLedger();
  ledger.issue(grant({ kinds: ["verify"] }));
  const driver = new FakeFillDriver();
  driver.current = "desired-value";
  const output = await executeBrowserAction({
    ledger,
    request: request({ kind: "verify" }),
    atMilliseconds: 1_000,
    driver,
    resolveFill: async () => {
      throw new Error("unused");
    },
    resolveTotp: async () => {
      throw new Error("unused");
    },
    resolveCapture: async () => {
      throw new Error("unused");
    },
    storeCaptured: async () => {
      throw new Error("unused");
    },
    resolveDesired: async () => ({
      origin: "https://example.com",
      selector: "#password",
      value: "desired-value",
    }),
  });
  assert.equal(output.result, "verified");
  assert.equal(output.verified, true);
  assert.equal(driver.fills.length, 0);
  assert.equal(JSON.stringify(output).includes("desired-value"), false);

  const mismatch = new BrowserGrantLedger();
  mismatch.issue(grant({ kinds: ["verify"], grantId: "grant-2" }));
  driver.current = "another-value";
  const failed = await executeBrowserAction({
    ledger: mismatch,
    request: request({ kind: "verify", grantId: "grant-2" }),
    atMilliseconds: 1_000,
    driver,
    resolveFill: async () => {
      throw new Error("unused");
    },
    resolveTotp: async () => {
      throw new Error("unused");
    },
    resolveCapture: async () => {
      throw new Error("unused");
    },
    storeCaptured: async () => {
      throw new Error("unused");
    },
    resolveDesired: async () => ({
      origin: "https://example.com",
      selector: "#password",
      value: "desired-value",
    }),
  });
  assert.equal(failed.verified, false);
  assert.equal(driver.fills.length, 0);
});
