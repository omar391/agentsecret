import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdtempSync,
  existsSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
  chmodSync,
} from "node:fs";
import { Writable } from "node:stream";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";

// The TypeScript CLI ships uncompiled under tsx; tests import the source module directly.
import {
  parseRunArgs,
  buildRunRequest,
  resolveHostPath,
  RunSpecError,
} from "../cli/run-spec";
import {
  isCredentialEmpty,
  buildRunPlan,
  verifySecretAudit,
  executeSbxPlan,
  runGuestCommand,
  runtimeQualified,
  SBX_QUALIFIED_SHA256,
  SBX_QUALIFIED_VERSION,
  T015_EVIDENCE_SHA256,
  pinSbxRuntime,
} from "../cli/docker-runtime";

const hostRoot = "/workspace/project";

test("run spec parses command after --", () => {
  const spec = parseRunArgs(
    [
      "--egress",
      "api.example.com:GET:/v1/status",
      "--",
      "/usr/bin/curl",
      "--silent",
    ],
    hostRoot,
  );
  assert.equal(spec.executable, "/usr/bin/curl");
  assert.deepEqual(spec.argv, ["--silent"]);
  assert.deepEqual(spec.egress, [
    { host: "api.example.com", method: "GET", path: "/v1/status" },
  ]);
  const request = buildRunRequest(spec);
  assert.equal(request.version, 1);
  assert.equal(request.reference_bindings.length, 0);
  assert.equal(request.egress[0].port, 443);
  assert.equal(request.egress[0].method, "GET");
});

test("run spec refuses missing separator and unsupported methods", () => {
  assert.throws(() => parseRunArgs(["/usr/bin/curl"], hostRoot), RunSpecError);
  assert.throws(
    () =>
      parseRunArgs(
        ["--egress", "api.example.com:CONNECT:/v1", "--", "/usr/bin/curl"],
        hostRoot,
      ),
    /run_egress_method_invalid/,
  );
});

test("managed reference bindings stay value-free and fail closed upstream", () => {
  const spec = parseRunArgs(
    [
      "--reference-binding",
      "API_TOKEN=EXAMPLE_API#/login/password",
      "--",
      "/usr/bin/true",
    ],
    hostRoot,
  );
  assert.equal(spec.executable, "/usr/bin/true");
  assert.deepEqual(spec.referenceBindings, [
    {
      envName: "API_TOKEN",
      alias: "EXAMPLE_API",
      fieldPath: "/login/password",
    },
  ]);
  const placeholder = "ASRC1.EXAMPLE_API." + "A".repeat(43);
  const request = buildRunRequest(
    spec,
    [{ envName: "API_TOKEN", placeholder }],
    {
      mediatorOrigin: "http://127.0.0.1:49151",
      bindingFile: "/tmp/agentsecret-bindings.json",
      envFile: "/tmp/agentsecret-guest.env",
    },
  );
  assert.deepEqual(request.reference_bindings, [
    {
      env_name: "API_TOKEN",
      alias: "EXAMPLE_API",
      field_path: "/login/password",
      placeholder,
    },
  ]);
  assert.deepEqual(request.mediation, {
    mediator_origin: "http://127.0.0.1:49151",
    binding_file: "/tmp/agentsecret-bindings.json",
    env_file: "/tmp/agentsecret-guest.env",
  });
  assert.equal(JSON.stringify(request).includes("value"), false);

  for (const invalid of [
    "API_TOKEN",
    "API_TOKEN=EXAMPLE_API",
    "API_TOKEN=EXAMPLE_API#",
    "API_TOKEN=example-api#/",
    "API_TOKEN=EXAMPLE-API#/",
    "API_TOKEN=EXAMPLE.API#/",
    "API_TOKEN=1EXAMPLE#/",
    "API_TOKEN=" + "A".repeat(65) + "#/",
    "PATH=EXAMPLE_API#/",
    "AGENTSECRET_X=EXAMPLE_API#/",
    "API_TOKEN=EXAMPLE_API#/x\u0000y",
    "API_TOKEN=EXAMPLE_API#/x\ty",
  ]) {
    assert.throws(
      () =>
        parseRunArgs(
          ["--reference-binding", invalid, "--", "/usr/bin/true"],
          hostRoot,
        ),
      /run_reference_binding_invalid/,
      invalid,
    );
  }
  assert.throws(
    () =>
      parseRunArgs(
        [
          "--reference-binding",
          "API_TOKEN=EXAMPLE_API#/",
          "--reference-binding",
          "api_token=OTHER#/",
          "--",
          "/usr/bin/true",
        ],
        hostRoot,
      ),
    /run_reference_binding_duplicate/,
  );
  assert.throws(
    () => buildRunRequest(spec, [{ envName: "API_TOKEN", placeholder }]),
    /run_mediation_required/,
  );
  assert.throws(
    () =>
      buildRunRequest(
        parseRunArgs(["--", "/usr/bin/true"], hostRoot),
        undefined,
        {
          mediatorOrigin: "http://127.0.0.1:49151",
          bindingFile: "/tmp/agentsecret-bindings.json",
          envFile: "/tmp/agentsecret-guest.env",
        },
      ),
    /run_mediation_unnecessary/,
  );
  const tooMany = [
    "--file",
    "/workspace/project/file=/workspace/file",
    "--",
    "/usr/bin/true",
  ];
  for (let i = 0; i <= 32; i++)
    tooMany.unshift("--reference-binding", `ENV_${i}=ALIAS_${i}#/`);
  assert.throws(
    () => parseRunArgs(tooMany, hostRoot),
    /run_reference_bindings_too_many/,
  );
});

test("run spec rejects host paths outside the declared host root", () => {
  assert.throws(
    () =>
      parseRunArgs(
        ["--file", "/tmp/outside=/workspace/out.txt", "--", "/bin/echo"],
        hostRoot,
      ),
    /run_file_outside_workspace/,
  );
  assert.throws(
    () => resolveHostPath("/tmp/outside", hostRoot),
    /run_file_outside_workspace/,
  );
});

test("credential audit accepts only empty mappings", () => {
  assert.equal(isCredentialEmpty([]), true);
  assert.equal(isCredentialEmpty({ secrets: [] }), true);
  assert.equal(isCredentialEmpty({}), true);
  assert.equal(isCredentialEmpty({ secrets: [{ name: "x" }] }), false);
  // The real sbx v0.53.0 audit reports env_only_count: 0 for a clean
  // credential state; a zero count is empty, a positive count is not.
  assert.equal(isCredentialEmpty({ count: 0 }), true);
  assert.equal(isCredentialEmpty({ env_only_count: 1 }), false);
  assert.equal(
    isCredentialEmpty({
      secrets: [],
      custom_secrets: [],
      shadowed_services: [],
      env_only_count: 0,
    }),
    true,
  );
  assert.equal(isCredentialEmpty({ enabled: false }), true);
  assert.equal(isCredentialEmpty({ enabled: true }), false);
  assert.doesNotThrow(() => verifySecretAudit("[]", "global"));
  assert.throws(
    () => verifySecretAudit('[{"name":"ghp"}]', "global"),
    /unapproved_credential_mapping:global/,
  );
  assert.doesNotThrow(() =>
    verifySecretAudit(
      '{"secrets":[],"custom_secrets":[],"shadowed_services":[],"env_only_count":0}',
      "sandbox",
    ),
  );
});

test("cancellation still runs bounded sandbox cleanup with an independent signal", async () => {
  const scratch = mkdtempSync(join(tmpdir(), "agentsecret-runtime-test-"));
  const controller = new AbortController();
  let removed = false;
  const plan = {
    schema: "agentsecret-supervisor/docker-plan/v1",
    sandbox_name: "agentsecret-run-test",
    scratch,
    host_environment_to_remove: [],
    global_credential_audit: ["secret", "ls"],
    sandbox_credential_audit: ["secret", "ls"],
    account_policy_audit: ["policy", "ls"],
    create: ["create"],
    sandbox_policy_audit: ["policy", "ls", "agentsecret-run-test"],
    allow_rules: [],
    verify_policy: ["policy", "ls", "agentsecret-run-test"],
    execute: ["exec"],
    remove: ["rm"],
    staged_files: [],
  };
  const emptySecrets = JSON.stringify([]);
  const receipt = await executeSbxPlan(plan, "sbx", {
    hostRoot,
    signal: controller.signal,
    verifyPolicyAudit: () => {},
    runArgv: async (argv, options) => {
      const command = argv.at(-1);
      if (argv.includes("ls")) {
        return {
          exitCode: 0,
          signal: null,
          stdout: argv.includes("secret") ? emptySecrets : JSON.stringify({}),
        };
      }
      if (command === "exec") {
        controller.abort();
        return { exitCode: null, signal: "SIGTERM" };
      }
      if (command === "rm") {
        assert.notEqual(options.signal, controller.signal);
        assert.equal(options.signal?.aborted, false);
        removed = true;
      }
      return { exitCode: 0, signal: null };
    },
  });

  assert.equal(receipt.status, "cancelled", receipt.reason);
  assert.equal(removed, true);
  assert.deepEqual(receipt.cleanup, {
    sandboxRemoved: true,
    scratchRemoved: true,
  });
  assert.equal(existsSync(scratch), false);
  rmSync(scratch, { recursive: true, force: true });
});

test("unqualified runtime refuses run closed", async () => {
  const receipt = await runGuestCommand(
    parseRunArgs(["--", "/usr/bin/curl"], hostRoot),
    { hostRoot, configDir: "/definitely/not/a/real/config/dir" },
  );
  assert.equal(receipt.status, "runtime_not_qualified");
  assert.equal(receipt.stages.length, 0);
  assert.equal(runtimeQualified("/definitely/not/a/real/config/dir"), false);
});

test("real policy verifier refuses an audit without a global default-deny", async () => {
  const scratch = mkdtempSync(join(tmpdir(), "agentsecret-policy-gate-test-"));
  const plan = {
    schema: "agentsecret-supervisor/docker-plan/v1",
    sandbox_name: "agentsecret-run-test",
    scratch,
    host_environment_to_remove: [],
    global_credential_audit: ["secret", "ls"],
    sandbox_credential_audit: ["secret", "ls"],
    account_policy_audit: ["policy", "ls"],
    create: ["create"],
    sandbox_policy_audit: ["policy", "ls"],
    allow_rules: [],
    verify_policy: ["policy", "ls"],
    execute: ["exec"],
    remove: ["rm", "--force", "agentsecret-run-test"],
    staged_files: [],
  };
  const emptySecrets = JSON.stringify([]);
  let executed = false;
  let removed = false;
  const receipt = await executeSbxPlan(plan, "sbx", {
    hostRoot,
    runArgv: async (argv) => {
      if (argv.includes("secret"))
        return { exitCode: 0, signal: null, stdout: emptySecrets };
      if (argv.includes("exec")) executed = true;
      if (argv.includes("rm")) removed = true;
      return {
        exitCode: 0,
        signal: null,
        stdout: JSON.stringify({ rules: [] }),
      };
    },
  });

  assert.equal(receipt.status, "policy_refused", receipt.reason);
  assert.equal(receipt.reason, "account_network_default_deny_missing");
  assert.equal(executed, false);
  assert.equal(removed, true);
  assert.equal(receipt.cleanup.sandboxRemoved, true);
  rmSync(scratch, { recursive: true, force: true });
});

test("injected policy verifier receives the retained audit evidence", async () => {
  const scratch = mkdtempSync(join(tmpdir(), "agentsecret-policy-pass-test-"));
  const plan = {
    schema: "agentsecret-supervisor/docker-plan/v1",
    sandbox_name: "agentsecret-run-test",
    scratch,
    host_environment_to_remove: [],
    global_credential_audit: ["secret", "ls"],
    sandbox_credential_audit: ["secret", "ls"],
    account_policy_audit: ["policy", "ls"],
    create: ["create"],
    sandbox_policy_audit: ["policy", "ls"],
    allow_rules: [],
    verify_policy: ["policy", "ls"],
    execute: ["exec"],
    remove: ["rm"],
    staged_files: [],
  };
  const emptySecrets = JSON.stringify([]);
  const seen: unknown[] = [];
  const receipt = await executeSbxPlan(plan, "sbx", {
    hostRoot,
    verifyPolicyAudit: (audits, _declared, sandboxName) => {
      seen.push({ audits, sandboxName });
    },
    runArgv: async (argv) => {
      if (argv.includes("secret"))
        return { exitCode: 0, signal: null, stdout: emptySecrets };
      return { exitCode: 0, signal: null, stdout: JSON.stringify({}) };
    },
  });

  assert.equal(receipt.status, "completed", receipt.reason);
  assert.equal(seen.length, 1);
  assert.deepEqual(seen[0], {
    audits: {
      account: JSON.stringify({}),
      sandbox: JSON.stringify({}),
      verify: JSON.stringify({}),
    },
    sandboxName: "agentsecret-run-test",
  });
  rmSync(scratch, { recursive: true, force: true });
});

const lifecyclePlan = (scratch: string, removeArgv = ["rm"]) => ({
  schema: "agentsecret-supervisor/docker-plan/v1",
  sandbox_name: "agentsecret-run-test",
  scratch,
  host_environment_to_remove: [],
  global_credential_audit: ["secret", "ls"],
  sandbox_credential_audit: ["secret", "ls"],
  account_policy_audit: ["policy", "ls"],
  create: ["create"],
  sandbox_policy_audit: ["policy", "ls"],
  allow_rules: [],
  verify_policy: ["policy", "ls"],
  execute: ["exec"],
  remove: removeArgv,
  staged_files: [],
});

test("optional restart probe re-runs the same argv after a stop between execute and cleanup", async () => {
  const scratch = mkdtempSync(join(tmpdir(), "agentsecret-restart-test-"));
  const emptySecrets = JSON.stringify([]);
  const calls: string[] = [];
  const receipt = await executeSbxPlan(lifecyclePlan(scratch), "sbx", {
    hostRoot,
    restartProbe: { stopArgv: ["stop", "agentsecret-run-test"] },
    verifyPolicyAudit: () => {},
    runArgv: async (argv) => {
      calls.push(argv.slice(1).join(" "));
      if (argv.includes("secret"))
        return { exitCode: 0, signal: null, stdout: emptySecrets };
      return { exitCode: 0, signal: null, stdout: JSON.stringify({}) };
    },
  });

  assert.equal(receipt.status, "completed", receipt.reason);
  const executeCalls = calls.filter((call) => call === "exec");
  assert.deepEqual(executeCalls, ["exec", "exec"]);
  assert.ok(calls.includes("stop agentsecret-run-test"));
  assert.ok(calls.indexOf("stop agentsecret-run-test") > executeCalls.length);
  assert.ok(
    receipt.stages.some((stage) => stage.stage === "restart_stop") &&
      receipt.stages.some((stage) => stage.stage === "restart_execute"),
  );
  assert.equal(receipt.cleanup.sandboxRemoved, true);
  rmSync(scratch, { recursive: true, force: true });
});

test("restart probe failure marks the receipt failed while cleanup still runs", async () => {
  const scratch = mkdtempSync(join(tmpdir(), "agentsecret-restart-fail-"));
  const emptySecrets = JSON.stringify([]);
  let removed = false;
  const receipt = await executeSbxPlan(lifecyclePlan(scratch), "sbx", {
    hostRoot,
    restartProbe: { stopArgv: ["stop", "agentsecret-run-test"] },
    verifyPolicyAudit: () => {},
    runArgv: async (argv) => {
      if (argv.includes("secret"))
        return { exitCode: 0, signal: null, stdout: emptySecrets };
      if (argv.at(-1) === "agentsecret-run-test" && argv.includes("stop"))
        return { exitCode: 1, signal: null };
      if (argv.includes("rm")) removed = true;
      return { exitCode: 0, signal: null, stdout: JSON.stringify({}) };
    },
  });

  assert.equal(receipt.status, "failed", receipt.reason);
  assert.equal(receipt.reason, "restart_stop:exit:1");
  assert.equal(removed, true);
  assert.equal(receipt.cleanup.sandboxRemoved, true);
  assert.equal(receipt.cleanup.scratchRemoved, true);
  rmSync(scratch, { recursive: true, force: true });
});

test("immediate destination EPIPE becomes a failed receipt while cleanup still runs", async () => {
  const scratch = mkdtempSync(join(tmpdir(), "agentsecret-epipe-test-"));
  let removed = false;
  const stdout = new Writable({
    write(_chunk, _encoding, callback) {
      callback(new Error("EPIPE"));
    },
  });
  const receipt = await executeSbxPlan(lifecyclePlan(scratch), "sbx", {
    hostRoot,
    stdout,
    verifyPolicyAudit: () => {},
    runArgv: async (argv, options) => {
      const command = argv.at(-1);
      if (argv.includes("ls")) {
        return {
          exitCode: 0,
          signal: null,
          stdout: argv.includes("secret") ? "[]" : JSON.stringify({}),
        };
      }
      if (command === "exec") {
        // Route the guest through the default runner so its real stdout
        // reaches the EPIPE-emitting destination stream.
        return await (
          await import("../cli/docker-runtime")
        ).defaultArgvRunner(["echo", "hello"], options);
      }
      if (command === "rm") removed = true;
      return { exitCode: 0, signal: null };
    },
  });

  assert.equal(receipt.status, "failed");
  assert.match(receipt.reason ?? "", /EPIPE|output_stream_error/);
  assert.equal(removed, true);
  assert.equal(receipt.cleanup.scratchRemoved, true);
  rmSync(scratch, { recursive: true, force: true });
});

test("delayed destination EPIPE after guest exit still completes bounded cleanup", async () => {
  const scratch = mkdtempSync(join(tmpdir(), "agentsecret-delayed-epipe-"));
  let removed = false;
  const stdout = new Writable({
    write(_chunk, _encoding, callback) {
      setTimeout(() => callback(new Error("EPIPE")), 200);
    },
  });
  const receipt = await executeSbxPlan(lifecyclePlan(scratch), "sbx", {
    hostRoot,
    stdout,
    verifyPolicyAudit: () => {},
    runArgv: async (argv, options) => {
      const command = argv.at(-1);
      if (argv.includes("ls")) {
        return {
          exitCode: 0,
          signal: null,
          stdout: argv.includes("secret") ? "[]" : JSON.stringify({}),
        };
      }
      if (command === "exec") {
        // Route the guest through the default runner so its output crosses
        // the delayed-EPIPE destination stream.
        return await (
          await import("../cli/docker-runtime")
        ).defaultArgvRunner(["echo", "hello"], options);
      }
      if (command === "rm") {
        await delay(20);
        removed = true;
      }
      return { exitCode: 0, signal: null };
    },
  });

  assert.equal(removed, true);
  assert.equal(receipt.cleanup.sandboxRemoved, true);
  assert.equal(receipt.cleanup.scratchRemoved, true);
  rmSync(scratch, { recursive: true, force: true });
}, 15000);

test("a stalled output consumer cannot block cancellation-time cleanup", async () => {
  const scratch = mkdtempSync(join(tmpdir(), "agentsecret-stalled-pipe-"));
  const controller = new AbortController();
  let removed = false;
  let readerResumed = false;
  let stalledWritePending = false;
  const destination = new Writable({
    write(_chunk, _encoding, callback) {
      stalledWritePending = true;
      // Simulate a paused consumer that only resumes after removal ran.
      const timer = setInterval(() => {
        if (removed) {
          clearInterval(timer);
          readerResumed = true;
          callback();
        }
      }, 25);
    },
  });
  const receipt = await executeSbxPlan(lifecyclePlan(scratch), "sbx", {
    hostRoot,
    signal: controller.signal,
    stdout: destination,
    verifyPolicyAudit: () => {},
    runArgv: async (argv, options) => {
      const command = argv.at(-1);
      if (argv.includes("ls")) {
        return {
          exitCode: 0,
          signal: null,
          stdout: argv.includes("secret") ? "[]" : JSON.stringify({}),
        };
      }
      if (command === "exec") {
        const run = (await import("../cli/docker-runtime")).defaultArgvRunner(
          ["echo", "hello"],
          options,
        );
        // Wait until the destination has a pending, stalled write, then
        // cancel while that write can never complete on its own. The runner
        // must still settle within its bounded drain interval.
        let waited = 0;
        while (!stalledWritePending && waited < 2000) {
          await delay(25);
          waited += 25;
        }
        controller.abort();
        return await run;
      }
      if (command === "rm") {
        await delay(20);
        removed = true;
      }
      return { exitCode: 0, signal: null };
    },
  });

  assert.equal(removed, true);
  // Cleanup completed while the destination consumer was still stalled; the
  // receipt did not wait for the pending write to finish.
  assert.equal(readerResumed, false);
  assert.equal(receipt.status, "failed");
  assert.match(receipt.reason ?? "", /output_drain_timeout/);
  assert.equal(receipt.cleanup.sandboxRemoved, true);
  assert.equal(receipt.cleanup.scratchRemoved, true);
  // Let the paused consumer drain once removal has happened so the test
  // does not leave a live interval behind.
  await delay(50);
  assert.equal(readerResumed, true);
  rmSync(scratch, { recursive: true, force: true });
}, 15000);

test("a stalled output consumer after normal child exit times out and settles", async () => {
  const destination = new Writable({
    write(_chunk, _encoding, _callback) {
      // Deliberately leave the write pending until after the runner settles.
    },
  });
  const started = Date.now();
  const result = await (
    await import("../cli/docker-runtime")
  ).defaultArgvRunner(["echo", "hello"], {
    env: process.env,
    stdout: destination,
  });

  assert.equal(result.error, "output_drain_timeout");
  assert.ok(Date.now() - started < 5000);
  destination.destroy();
});

test("slow output applies backpressure to a sustained producer", async () => {
  const controller = new AbortController();
  let maxBuffered = 0;
  const destination = new Writable({
    highWaterMark: 1024,
    write(_chunk, _encoding, callback) {
      maxBuffered = Math.max(maxBuffered, destination.writableLength);
      setTimeout(callback, 10);
    },
  });
  const run = (await import("../cli/docker-runtime")).defaultArgvRunner(
    [
      process.execPath,
      "-e",
      "const b=Buffer.alloc(16384); for (;;) process.stdout.write(b)",
    ],
    { env: process.env, stdout: destination, signal: controller.signal },
  );
  await delay(150);
  controller.abort();
  const result = await run;

  assert.notEqual(result.exitCode, 0);
  assert.ok(maxBuffered < 128 * 1024, `buffer grew to ${maxBuffered} bytes`);
  destination.destroy();
}, 15000);

test("captured output preserves UTF-8 characters split across chunks", async () => {
  const result = await (
    await import("../cli/docker-runtime")
  ).defaultArgvRunner(
    [
      process.execPath,
      "-e",
      "process.stdout.write(Buffer.from([0xc3])); setTimeout(() => process.stdout.write(Buffer.from([0xa9])), 10)",
    ],
    { env: process.env },
  );

  assert.equal(result.stdout, "é");
});

test("early supervisor stdin closure returns plan_failed and removes scratch", async () => {
  const scratchParent = mkdtempSync(join(tmpdir(), "agentsecret-plan-epipe-"));
  const supervisor = join(scratchParent, "early-exit-supervisor");
  writeFileSync(supervisor, "#!/bin/sh\nexit 0\n");
  chmodSync(supervisor, 0o755);
  const spec = {
    executable: "/bin/echo",
    argv: ["x".repeat(24 * 1024 * 1024)],
    workingDirectory: "/workspace",
    fileAccess: [],
    egress: [],
    referenceBindings: [],
  };

  await assert.rejects(
    buildRunPlan(spec, {
      hostRoot,
      supervisorPath: supervisor,
      sbxPath: "sbx",
      scratchParent,
    }),
    /plan_failed:/,
  );
  assert.deepEqual(readdirSync(scratchParent), ["early-exit-supervisor"]);
  rmSync(scratchParent, { recursive: true, force: true });
});

// The positional primary workspace must be private and contain directories
// only; declared staged files are mounted individually at /workspace paths.
// This keeps undeclared caller files out of the guest and preserves per-file
// :ro mounts. Pin the create argv so the caller root cannot become a mount.
test("supervisor keeps caller files out of the primary workspace", async (t) => {
  const envSupervisor = process.env.AGENTSECRET_TEST_SUPERVISOR;
  const supervisor =
    envSupervisor ??
    join(
      import.meta.dirname,
      "../native/agentsecret-supervisor/target/debug/agentsecret-supervisor",
    );
  if (!envSupervisor && !existsSync(supervisor)) {
    t.skip(
      "real supervisor binary unavailable; run cargo build in native/agentsecret-supervisor",
    );
    return;
  }
  const scratchParent = mkdtempSync(join(tmpdir(), "agentsecret-plan-mount-"));
  try {
    const runHostRoot = mkdtempSync(join(tmpdir(), "agentsecret-plan-root-"));
    const spec = parseRunArgs(["--", "/usr/bin/true"], runHostRoot);
    const built = await buildRunPlan(spec, {
      hostRoot: runHostRoot,
      supervisorPath: supervisor,
      sbxPath: "sbx",
      scratchParent,
    });
    try {
      const canonicalHostRoot = realpathSync(runHostRoot);
      const positional = built.plan.create.filter(
        (arg) => typeof arg === "string" && !arg.includes(":"),
      );
      assert.equal(positional.includes(canonicalHostRoot), false);
      const workspaceMount = built.plan.create.find(
        (arg) => typeof arg === "string" && arg.endsWith(":/workspace"),
      );
      assert.ok(workspaceMount, "create argv must map the private workspace");
      assert.equal(
        workspaceMount?.slice(0, -":/workspace".length),
        positional.find((arg) => arg.endsWith("/primary")),
      );
      assert.equal(
        built.plan.create.some(
          (arg) => typeof arg === "string" && arg.includes(canonicalHostRoot),
        ),
        false,
        "caller workspace must not be mounted into the guest",
      );
    } finally {
      built.cleanupScratch();
    }
    rmSync(runHostRoot, { recursive: true, force: true });
  } finally {
    rmSync(scratchParent, { recursive: true, force: true });
  }
});

// Real sbx v0.53.0 stores HTTP allow rules as host:443. A bare-host rule would
// not match HTTPS targets and the guest would be denied despite a "successful"
// policy stage. Pins the real supervisor binary's emitted argv.
test("supervisor emits explicit :443 port for HTTPS allow rules", async (t) => {
  const envSupervisor = process.env.AGENTSECRET_TEST_SUPERVISOR;
  const supervisor =
    envSupervisor ??
    join(
      import.meta.dirname,
      "../native/agentsecret-supervisor/target/debug/agentsecret-supervisor",
    );
  if (!envSupervisor && !existsSync(supervisor)) {
    t.skip(
      "real supervisor binary unavailable; run cargo build in native/agentsecret-supervisor",
    );
    return;
  }
  const scratchParent = mkdtempSync(join(tmpdir(), "agentsecret-plan-port-"));
  try {
    const runHostRoot = mkdtempSync(join(tmpdir(), "agentsecret-plan-root-"));
    const spec = parseRunArgs(
      ["--egress", "example.com:GET:/index.html", "--", "/usr/bin/true"],
      runHostRoot,
    );
    const built = await buildRunPlan(spec, {
      hostRoot: runHostRoot,
      supervisorPath: supervisor,
      sbxPath: "sbx",
      scratchParent,
    });
    try {
      assert.equal(built.plan.allow_rules.length, 1);
      const rule = built.plan.allow_rules[0];
      assert.equal(rule.indexOf("example.com"), -1);
      assert.ok(rule.includes("example.com:443"));
      assert.equal(rule[rule.indexOf("--method") + 1], "GET");
      assert.equal(rule[rule.indexOf("--path") + 1], "/index.html");
    } finally {
      built.cleanupScratch();
    }
    rmSync(runHostRoot, { recursive: true, force: true });
  } finally {
    rmSync(scratchParent, { recursive: true, force: true });
  }
});

test("teardown failure prevents a completed receipt", async () => {
  const scratch = mkdtempSync(join(tmpdir(), "agentsecret-teardown-fail-"));
  let removed = false;
  const receipt = await executeSbxPlan(lifecyclePlan(scratch), "sbx", {
    hostRoot,
    verifyPolicyAudit: () => {},
    removeScratch: () => {},
    runArgv: async (argv) => {
      const command = argv.at(-1);
      if (argv.includes("ls")) {
        return {
          exitCode: 0,
          signal: null,
          stdout: argv.includes("secret") ? "[]" : JSON.stringify({}),
        };
      }
      if (command === "rm") {
        removed = true;
        return { exitCode: 1, signal: null, stdout: "" };
      }
      if (command === "exec") {
        return { exitCode: 0, signal: null };
      }
      return { exitCode: 0, signal: null };
    },
  });

  assert.equal(removed, true);
  assert.equal(receipt.status, "failed");
  assert.equal(receipt.reason, "cleanup_failed");
  assert.equal(receipt.cleanup.sandboxRemoved, false);
  rmSync(scratch, { recursive: true, force: true });
});

test("synthetic receipts and a replacement runtime cannot open the T-015 gate", async () => {
  const configDir = mkdtempSync(
    join(tmpdir(), "agentsecret-runtime-qualification-"),
  );
  const receiptPath = join(configDir, "runtime-qualified.json");
  let runtimeInvocations = 0;
  for (const receipt of [
    {
      schema: "agentsecret.runtime-qualified/v1",
      sbx_version: "never-qualified",
      evidence_sha256: "x".repeat(64),
    },
    {
      schema: "agentsecret.runtime-qualified/v1",
      sbx_version: "v0.53.0",
      evidence_sha256: "0".repeat(64),
      sbx_sha256: "0".repeat(64),
    },
  ]) {
    writeFileSync(receiptPath, JSON.stringify(receipt));
    assert.equal(runtimeQualified(configDir), false);
    const run = await runGuestCommand(
      parseRunArgs(["--", "/usr/bin/echo"], hostRoot),
      {
        hostRoot,
        configDir,
        sbxPath: "/replacement/sbx",
        runArgv: async () => {
          runtimeInvocations += 1;
          return { exitCode: 0, signal: null };
        },
      },
    );
    assert.equal(run.status, "runtime_not_qualified");
    assert.equal(run.stages.length, 0);
  }
  assert.equal(runtimeInvocations, 0);
  rmSync(configDir, { recursive: true, force: true });
});

test("a pinned receipt does not authorize a replacement sbx executable", async () => {
  const configDir = mkdtempSync(
    join(tmpdir(), "agentsecret-runtime-replaced-"),
  );
  const replacement = join(configDir, "sbx");
  writeFileSync(
    join(configDir, "runtime-qualified.json"),
    JSON.stringify({
      schema: "agentsecret.runtime-qualified/v1",
      sbx_version: SBX_QUALIFIED_VERSION,
      sbx_sha256: SBX_QUALIFIED_SHA256,
      evidence_sha256: T015_EVIDENCE_SHA256,
      qualified_at: "2026-11-14T00:00:00.000Z",
    }),
  );
  writeFileSync(replacement, "replacement runtime");
  chmodSync(replacement, 0o755);
  const originalSbx = process.env.AGENTSECRET_SBX;
  const originalPath = process.env.PATH;
  const cases = [
    {
      name: "explicit path",
      sbxPath: replacement,
      envSbx: undefined,
      path: originalPath,
    },
    {
      name: "environment selection",
      sbxPath: undefined,
      envSbx: replacement,
      path: originalPath,
    },
    {
      name: "PATH selection",
      sbxPath: undefined,
      envSbx: undefined,
      path: [configDir, originalPath].filter(Boolean).join(delimiter),
    },
  ];
  try {
    for (const item of cases) {
      if (item.envSbx === undefined) delete process.env.AGENTSECRET_SBX;
      else process.env.AGENTSECRET_SBX = item.envSbx;
      if (item.path === undefined) delete process.env.PATH;
      else process.env.PATH = item.path;
      let invocations = 0;
      const receipt = await runGuestCommand(
        parseRunArgs(["--", "/usr/bin/echo"], hostRoot),
        {
          hostRoot,
          configDir,
          ...(item.sbxPath ? { sbxPath: item.sbxPath } : {}),
          runArgv: async () => {
            invocations += 1;
            return { exitCode: 0, signal: null };
          },
        },
      );
      assert.equal(receipt.status, "runtime_not_qualified", item.name);
      assert.equal(invocations, 0, item.name);
    }
  } finally {
    if (originalSbx === undefined) delete process.env.AGENTSECRET_SBX;
    else process.env.AGENTSECRET_SBX = originalSbx;
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
    rmSync(configDir, { recursive: true, force: true });
  }
});

test("runtime replacement during supervisor planning cannot change the pinned artifact", async () => {
  const scratchParent = mkdtempSync(
    join(tmpdir(), "agentsecret-runtime-plan-race-"),
  );
  const source = join(scratchParent, "sbx");
  const supervisor = join(scratchParent, "supervisor");
  const original = Buffer.from("qualified-runtime-fixture");
  const digest = createHash("sha256").update(original).digest("hex");
  writeFileSync(source, original, { mode: 0o700 });
  writeFileSync(supervisor, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  const pinned = pinSbxRuntime(source, digest);
  try {
    const planned = await buildRunPlan(
      parseRunArgs(["--", "/usr/bin/true"], hostRoot),
      {
        hostRoot,
        supervisorPath: supervisor,
        sbxPath: pinned.path,
        scratchParent,
        runArgv: async () => {
          chmodSync(source, 0o600);
          writeFileSync(source, "replaced during planning");
          return {
            exitCode: 0,
            signal: null,
            stdout: JSON.stringify({
              schema: "agentsecret-supervisor/docker-plan/v1",
              create: [],
              execute: [],
              remove: [],
              allow_rules: [],
            }),
          };
        },
      },
    );
    planned.cleanupScratch();
    assert.equal(
      createHash("sha256").update(readFileSync(pinned.path)).digest("hex"),
      digest,
    );
    assert.notEqual(
      createHash("sha256").update(readFileSync(source)).digest("hex"),
      digest,
    );
  } finally {
    pinned.cleanup();
    rmSync(scratchParent, { recursive: true, force: true });
  }
});

test("runtime replacement between stages stops all later sbx launches", async () => {
  const scratch = mkdtempSync(
    join(tmpdir(), "agentsecret-runtime-stage-race-"),
  );
  const source = join(scratch, "source-sbx");
  const bytes = Buffer.from("qualified-runtime-fixture");
  const digest = createHash("sha256").update(bytes).digest("hex");
  writeFileSync(source, bytes, { mode: 0o700 });
  const pinned = pinSbxRuntime(source, digest);
  let launches = 0;
  try {
    const receipt = await executeSbxPlan(
      lifecyclePlan(scratch),
      pinned.path,
      {
        hostRoot,
        verifyPolicyAudit: () => {},
        runArgv: async () => {
          launches += 1;
          chmodSync(pinned.path, 0o700);
          writeFileSync(pinned.path, "replaced between stages");
          return { exitCode: 0, signal: null, stdout: "[]" };
        },
      },
      pinned.sha256,
    );
    assert.equal(receipt.status, "failed");
    assert.match(receipt.reason ?? "", /runtime_integrity_lost/);
    assert.equal(launches, 1);
  } finally {
    pinned.cleanup();
    rmSync(scratch, { recursive: true, force: true });
  }
});
