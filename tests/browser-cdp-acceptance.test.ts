import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createServer as createTlsServer } from "node:https";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { runBrowserAction } from "../cli/browser/action";
import { CdpPipeTransport } from "../cli/browser/cdp-pipe";
import { launchChromeDriver } from "../cli/browser/chrome";
import { BrowserDriver } from "../cli/browser/driver";
import { executeBrowserAction } from "../cli/browser/execute";
import { createExecutorIdentity, executorProof } from "../cli/browser/executor";
import { BrowserGrantLedger } from "../cli/browser/grant";
import { BrowserActionReceiptStore } from "../cli/browser/receipt-store";
import { fixture, origin } from "./helpers.mjs";

const CHROME =
  process.env.CHROME_BIN ??
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

test(
  "real headless Chrome fills the approved origin and returns no value",
  { skip: process.env.AGENTSECRET_BROWSER_ACCEPTANCE !== "1" },
  async () => {
    assert.equal(existsSync(CHROME), true, "chrome_binary_missing");
    const server = createServer((_, response) => {
      response.setHeader("content-type", "text/html; charset=utf-8");
      response.end(
        '<!doctype html><input id="password" autocomplete="off"><input id="otp">',
      );
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const origin = `http://127.0.0.1:${address.port}`;
    const directory = mkdtempSync(join(tmpdir(), "agentsecret-chrome-"));
    let browser: CdpPipeTransport | undefined;
    let transport:
      Awaited<ReturnType<CdpPipeTransport["attachPage"]>> | undefined;
    try {
      browser = CdpPipeTransport.launch({
        executable: CHROME,
        profileDirectory: directory,
        url: origin,
        origin,
      });
      const deadline = Date.now() + 10_000;
      while (true) {
        try {
          transport = await browser.attachPage();
          break;
        } catch {
          if (Date.now() >= deadline) throw new Error("browser_target_timeout");
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 800));
      const driver = new BrowserDriver(transport);
      const secret = "synthetic-cdp-value";
      const ledger = new BrowserGrantLedger();
      ledger.issue({
        grantId: "fill-grant",
        accountId: "test-account",
        alias: "TEST",
        origin,
        kinds: ["fill"],
        expiresAt: Date.now() + 10_000,
        redeemedAt: null,
        fieldSelector: "#password",
      });
      const output = await executeBrowserAction({
        ledger,
        request: {
          grantId: "fill-grant",
          accountId: "test-account",
          origin,
          kind: "fill",
          fieldSelector: "#password",
        },
        atMilliseconds: Date.now(),
        driver,
        resolveFill: async () => ({
          origin,
          selector: "#password",
          value: secret,
        }),
        resolveTotp: async () => {
          throw new Error("unused");
        },
        resolveCapture: async () => ({ origin, selector: "#password" }),
        storeCaptured: async () => ({ reference: "unused", verified: false }),
        resolveDesired: async () => ({
          origin,
          selector: "#password",
          value: secret,
        }),
      });
      assert.equal(output.result, "filled");
      assert.equal(JSON.stringify(output).includes(secret), false);

      const verifyLedger = new BrowserGrantLedger();
      verifyLedger.issue({
        grantId: "verify-grant",
        accountId: "test-account",
        alias: "TEST",
        origin,
        kinds: ["verify"],
        expiresAt: Date.now() + 10_000,
        redeemedAt: null,
        fieldSelector: "#password",
      });
      const verified = await executeBrowserAction({
        ledger: verifyLedger,
        request: {
          grantId: "verify-grant",
          accountId: "test-account",
          origin,
          kind: "verify",
          fieldSelector: "#password",
        },
        atMilliseconds: Date.now(),
        driver,
        resolveFill: async () => {
          throw new Error("unused");
        },
        resolveTotp: async () => {
          throw new Error("unused");
        },
        resolveCapture: async () => ({ origin, selector: "#password" }),
        storeCaptured: async () => ({ reference: "unused", verified: false }),
        resolveDesired: async () => ({
          origin,
          selector: "#password",
          value: secret,
        }),
      });
      assert.equal(verified.verified, true);
      assert.equal(JSON.stringify(verified).includes(secret), false);
      assert.equal(existsSync(join(directory, "DevToolsActivePort")), false);
    } finally {
      await transport?.close();
      await browser?.close();
      await new Promise((resolve) => server.close(resolve));
      rmSync(directory, { recursive: true, force: true });
    }
  },
);

test(
  "browser act consumes a real broker grant and fills inside headless Chrome",
  { skip: process.env.AGENTSECRET_BROWSER_ACCEPTANCE !== "1" },
  async () => {
    assert.equal(existsSync(CHROME), true, "chrome_binary_missing");
    const secret = "synthetic-e2e-value-9d41";
    let reported = "";
    const host = "e2e.agentsecret.dev";
    const tlsDir = mkdtempSync(join(tmpdir(), "agentsecret-tls-"));
    const keyPath = join(tlsDir, "key.pem");
    const certPath = join(tlsDir, "cert.pem");
    execFileSync("openssl", [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      keyPath,
      "-out",
      certPath,
      "-days",
      "1",
      "-subj",
      "/CN=" + host,
      "-addext",
      "subjectAltName=DNS:" + host,
    ]);
    const spki = createHash("sha256")
      .update(
        new X509Certificate(readFileSync(certPath)).publicKey.export({
          format: "der",
          type: "spki",
        }),
      )
      .digest("base64");
    const server = createTlsServer(
      {
        key: readFileSync(keyPath),
        cert: readFileSync(certPath),
      },
      (request, response) => {
        if (request.url?.startsWith("/report")) {
          reported = decodeURIComponent(
            new URL(request.url, "https://" + host).searchParams.get("d") || "",
          );
          response.end("ok");
          return;
        }
        response.setHeader("content-type", "text/html; charset=utf-8");
        response.end(
          `<!doctype html><input id="password" autocomplete="off" onchange="fetch('/report?d='+encodeURIComponent(this.value)).catch(()=>{})">`,
        );
      },
    );
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const pageOrigin = "https://" + host + ":" + address.port;
    const f = await fixture();
    const receiptsDir = mkdtempSync(join(tmpdir(), "agentsecret-e2e-"));
    try {
      await f.createAccount("default", "Default Tenant");
      await f.policy("TEST", { allowedDomains: [host] });
      const token = await f.signIn("default");
      const executor = await createExecutorIdentity();
      const enrollBody = JSON.stringify({
        executorId: executor.executorId,
        publicJwk: executor.publicJwk,
        createdAt: executor.createdAt,
      });
      const enrolled = await f.call("/api/executor/enroll", {
        method: "POST",
        headers: {
          Cookie: "agentsecret_session=" + token,
          Origin: origin,
          "Content-Type": "application/json",
          DPoP: await executorProof(
            executor,
            "POST",
            origin + "/api/executor/enroll",
          ),
        },
        body: enrollBody,
      });
      assert.equal(enrolled.status, 200, await enrolled.clone().text());
      const issued = await f.admin("/api/executor/grants", {
        executorId: executor.executorId,
        alias: "TEST",
        origin: pageOrigin,
        kinds: ["fill"],
        fieldSelector: "#password",
        expiresIn: 120,
      });
      assert.equal(issued.status, 201, await issued.clone().text());
      const grant = (await issued.json()) as { grantId: string };

      const receipt = await runBrowserAction(
        {
          grantId: grant.grantId,
          kind: "fill",
          origin: pageOrigin,
          fieldSelector: "#password",
          reference: "bwp-item#/fields/password",
          url: pageOrigin + "/",
        },
        {
          executor,
          accountId: "default",
          server: origin,
          fetchImpl: (url, init) =>
            f.call(new URL(url).pathname, {
              method: init.method,
              headers: init.headers,
              body: init.body,
            }),
          receipts: new BrowserActionReceiptStore(receiptsDir),
          now: () => Date.now(),
          launchDriver: ({ url, origin: wanted }) =>
            launchChromeDriver({
              executable: CHROME,
              url,
              origin: wanted,
              extraArgs: [
                "--host-resolver-rules=MAP " + host + " 127.0.0.1",
                "--ignore-certificate-errors-spki-list=" + spki,
              ],
            }),
          resolveSecret: async () => secret,
          storeCaptured: async () => {
            throw new Error("capture_not_in_scope");
          },
        },
      );
      assert.deepEqual(receipt, {
        status: "completed",
        grantId: grant.grantId,
        action: "filled",
        origin: pageOrigin,
        fieldSelector: "#password",
      });
      assert.equal(JSON.stringify(receipt).includes(secret), false);
      const deadline = Date.now() + 5_000;
      while (reported !== secret && Date.now() < deadline)
        await new Promise((resolve) => setTimeout(resolve, 100));
      assert.equal(reported, secret);

      const listed = await f.admin("/api/executor/grants");
      const grants = ((await listed.json()) as { grants: any[] }).grants;
      const stored = grants.find((g) => g.grantId === grant.grantId);
      assert.ok(stored && typeof stored.redeemedAt === "number");
    } finally {
      await f.dispose();
      await new Promise((resolve) => server.close(resolve));
      rmSync(receiptsDir, { recursive: true, force: true });
      rmSync(tlsDir, { recursive: true, force: true });
    }
  },
);
