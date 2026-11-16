/**
 * Docker Sandboxes-backed run executor. Consumes the supervisor
 * docker-plan/v1 JSON and drives the emitted sbx argv sequence with a
 * scrubbed environment, ordered policy audits, guaranteed sandbox removal
 * and bounded receipts. Credential reference bindings are refused upstream
 * by the supervisor; this module never handles secret values.
 */

import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { StringDecoder } from "node:string_decoder";
import {
  mkdtempSync,
  rmSync,
  existsSync,
  statSync,
  readFileSync,
  accessSync,
  chmodSync,
  mkdirSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { PolicyAuditError, verifyRuntimePolicyAudit } from "./policy-audit";
import type { RunSpec } from "./run-spec";
import { buildRunRequest } from "./run-spec";

export interface SbxArgvPlan {
  schema: string;
  sandbox_name: string;
  scratch: string;
  host_environment_to_remove: string[];
  global_credential_audit: string[];
  sandbox_credential_audit: string[];
  account_policy_audit: string[];
  create: string[];
  sandbox_policy_audit: string[];
  allow_rules: string[][];
  verify_policy: string[];
  execute: string[];
  remove: string[];
  staged_files: { guest_path: string; mode: string; byte_length: number }[];
}

export interface RunStageResult {
  stage: string;
  exitCode: number | null;
  signal: string | null;
  audit?: unknown;
  error?: string;
}

export interface RunReceipt {
  status:
    | "completed"
    | "failed"
    | "cancelled"
    | "runtime_not_qualified"
    | "plan_failed"
    | "policy_refused";
  reason?: string;
  sandboxName?: string;
  exitCode?: number | null;
  signal?: string | null;
  stages: RunStageResult[];
  cleanup: { sandboxRemoved: boolean; scratchRemoved: boolean };
}

export interface RunOptions {
  sbxPath?: string;
  supervisorPath?: string;
  /** Config dir for the qualification receipt; defaults to the AgentSecret config dir. */
  configDir?: string;
  hostRoot: string;
  scratchParent?: string;
  signal?: AbortSignal;
  runArgv?: ArgvRunner;
  stdout?: NodeJS.WritableStream;
  stderr?: NodeJS.WritableStream;
  auditCaptureLimit?: number;
  /**
   * Policy audit verifier. The default enforces the T-015 sbx contract
   * against the captured policy listings; tests may inject a verifier to
   * exercise the surrounding lifecycle mechanics.
   */
  verifyPolicyAudit?: (
    audits: {
      account: string | undefined;
      sandbox: string | undefined;
      verify: string | undefined;
    },
    declared: DeclaredEgress[],
    sandboxName: string,
  ) => void;
  removeScratch?: (scratch: string) => void;
}

export type ArgvRunner = (
  argv: string[],
  options: ArgvRunOptions,
) => Promise<ArgvRunResult>;

export interface ArgvRunOptions {
  env: NodeJS.ProcessEnv;
  signal?: AbortSignal;
  stdin?: string;
  stdout?: NodeJS.WritableStream;
  stderr?: NodeJS.WritableStream;
  captureStdoutLimit?: number;
}

export interface ArgvRunResult {
  exitCode: number | null;
  signal: string | null;
  stdout?: string;
  stderr?: string;
  error?: string;
}

const DEFAULT_AUDIT_CAPTURE_LIMIT = 256 * 1024;
const KILL_GRACE_MS = 5_000;
const OUTPUT_DRAIN_GRACE_MS = 1_000;
const CLEANUP_TIMEOUT_MS = 10_000;
export const SBX_QUALIFIED_VERSION = "v0.53.0";
export const SBX_QUALIFIED_SHA256 =
  "d0c226ef44eaf5327d00adeee5db0a753cbce790a9fd0a8047d96a98479aeba9";
export const T015_EVIDENCE_SHA256 =
  "7a429a4b4455c61eaff9755b6ddc7525f0982128570101a5c7e16bf31d831d4b";

export class RunSpecLikeError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

export function supervisorCandidates(
  env: NodeJS.ProcessEnv = process.env,
): string[] {
  const candidates: string[] = [];
  if (env.AGENTSECRET_SUPERVISOR) candidates.push(env.AGENTSECRET_SUPERVISOR);
  const configDir = env.AGENTSECRET_CONFIG_DIR;
  if (configDir)
    candidates.push(join(configDir, "bin", "agentsecret-supervisor"));
  candidates.push("/usr/local/bin/agentsecret-supervisor");
  candidates.push("/opt/homebrew/bin/agentsecret-supervisor");
  return candidates;
}

export function sbxCandidates(env: NodeJS.ProcessEnv = process.env): string[] {
  const candidates: string[] = [];
  if (env.AGENTSECRET_SBX) candidates.push(env.AGENTSECRET_SBX);
  candidates.push("sbx");
  return candidates;
}

function executableFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

export function resolveBinary(
  candidates: string[],
  explicit?: string,
): string | undefined {
  if (explicit) {
    if (explicit.includes("/"))
      return executableFile(explicit) ? explicit : undefined;
    return explicit;
  }
  for (const candidate of candidates) {
    if (candidate.includes("/")) {
      if (executableFile(candidate)) return candidate;
    } else {
      return candidate;
    }
  }
  return undefined;
}

export function generateSandboxName(): string {
  return "agentsecret-run-" + randomBytes(8).toString("hex");
}

export async function buildRunPlan(
  spec: RunSpec,
  options: RunOptions,
): Promise<{
  plan: SbxArgvPlan;
  requestJson: string;
  scratchParent: string;
  cleanupScratch(): void;
}> {
  const supervisor = resolveBinary(
    supervisorCandidates(),
    options.supervisorPath,
  );
  if (!supervisor) throw new RunSpecLikeError("supervisor_unavailable");
  const sbx = resolveBinary(sbxCandidates(), options.sbxPath);
  if (!sbx) throw new RunSpecLikeError("sbx_unavailable");

  const requestJson = JSON.stringify(buildRunRequest(spec));
  const scratchParent = mkdtempSync(
    join(options.scratchParent || tmpdir(), "agentsecret-run-"),
  );
  const scratch = join(scratchParent, "workspace");
  const sandboxName = generateSandboxName();

  const runArgv = options.runArgv ?? defaultArgvRunner;
  const result = await runArgv(
    [
      supervisor,
      "docker-plan",
      "--host-root",
      options.hostRoot,
      "--scratch",
      scratch,
      "--sandbox-name",
      sandboxName,
    ],
    { env: scrubEnv(process.env, []), stdin: requestJson },
  );

  const cleanupScratch = () => {
    try {
      rmSync(scratchParent, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  };

  if (result.error || result.exitCode !== 0) {
    cleanupScratch();
    const detail = (result.stderr || result.error || "unknown")
      .trim()
      .slice(0, 120);
    throw new RunSpecLikeError("plan_failed:" + detail);
  }

  let plan: SbxArgvPlan;
  try {
    plan = JSON.parse(result.stdout || "") as SbxArgvPlan;
  } catch {
    cleanupScratch();
    throw new RunSpecLikeError("plan_invalid_json");
  }
  if (
    plan.schema !== "agentsecret-supervisor/docker-plan/v1" ||
    !Array.isArray(plan.create) ||
    !Array.isArray(plan.execute) ||
    !Array.isArray(plan.remove) ||
    !Array.isArray(plan.allow_rules)
  ) {
    cleanupScratch();
    throw new RunSpecLikeError("plan_schema_invalid");
  }
  return { plan, requestJson, scratchParent, cleanupScratch };
}

function scrubEnv(env: NodeJS.ProcessEnv, remove: string[]): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = { ...env };
  for (const key of remove) delete out[key];
  return out;
}

export const defaultArgvRunner: ArgvRunner = (argv, options) =>
  new Promise((resolve) => {
    const [command, ...args] = argv;
    const child = spawn(command, args, {
      env: options.env,
      stdio: ["pipe", "pipe", "pipe"],
      detached: true,
    });
    let stdout = "";
    let stderr = "";
    const stdoutDecoder = new StringDecoder("utf8");
    const stderrDecoder = new StringDecoder("utf8");
    let outputError: string | undefined;
    let killTimer: NodeJS.Timeout | undefined;
    let outputDrainTimer: NodeJS.Timeout | undefined;
    const outputStreams = new Set<NodeJS.WritableStream>();
    let pendingWrites = 0;
    let childResult: ArgvRunResult | undefined;
    let childClosed = false;
    let cancellationRequested = false;
    let outputDrainTimedOut = false;
    let outputListenersRemoved = false;
    let outputListenerCleanupScheduled = false;
    const captureLimit =
      options.captureStdoutLimit ?? DEFAULT_AUDIT_CAPTURE_LIMIT;
    let settled = false;
    const removeOutputListenersWhenDrained = () => {
      if (
        !settled ||
        pendingWrites > 0 ||
        outputListenersRemoved ||
        outputListenerCleanupScheduled
      )
        return;
      outputListenerCleanupScheduled = true;
      setImmediate(() => {
        outputListenerCleanupScheduled = false;
        if (!settled || pendingWrites > 0 || outputListenersRemoved) return;
        outputListenersRemoved = true;
        for (const stream of outputStreams)
          stream.removeListener("error", onOutputError);
      });
    };
    const finishWhenDrained = () => {
      if (!childClosed || settled) return;
      if (pendingWrites > 0 && !outputDrainTimedOut) {
        if (!outputDrainTimer) {
          outputDrainTimer = setTimeout(() => {
            outputDrainTimer = undefined;
            outputDrainTimedOut = true;
            outputError ||= "output_drain_timeout";
            finishWhenDrained();
          }, OUTPUT_DRAIN_GRACE_MS);
        }
        return;
      }
      setImmediate(() => {
        if (
          !childClosed ||
          (pendingWrites > 0 && !outputDrainTimedOut) ||
          settled ||
          !childResult
        ) {
          finishWhenDrained();
          return;
        }
        settled = true;
        if (killTimer) clearTimeout(killTimer);
        if (outputDrainTimer) clearTimeout(outputDrainTimer);
        outputDrainTimer = undefined;
        if (pendingWrites === 0 || outputDrainTimedOut) {
          outputListenersRemoved = true;
          for (const stream of outputStreams)
            stream.removeListener("error", onOutputError);
        }
        cleanup();
        resolve(
          outputError ? { ...childResult, error: outputError } : childResult,
        );
      });
    };
    const finish = (result: ArgvRunResult) => {
      if (childClosed) return;
      childResult = result;
      childClosed = true;
      if (killTimer) clearTimeout(killTimer);
      killTimer = undefined;
      finishWhenDrained();
    };
    const killGroup = (signal: NodeJS.Signals) => {
      try {
        if (child.pid) process.kill(-child.pid, signal);
      } catch {
        try {
          child.kill(signal);
        } catch {
          /* already gone */
        }
      }
    };
    const terminateChild = () => {
      if (childClosed) return;
      killGroup("SIGTERM");
      if (killTimer) return;
      killTimer = setTimeout(() => {
        killTimer = undefined;
        if (!childClosed) killGroup("SIGKILL");
      }, KILL_GRACE_MS);
      killTimer.unref();
    };
    const onOutputError = (error: Error) => {
      if (outputError) return;
      outputError = error.message || "output_stream_error";
      if (childClosed) {
        finishWhenDrained();
        return;
      }
      terminateChild();
    };
    const onAbort = () => {
      cancellationRequested = true;
      terminateChild();
      finishWhenDrained();
    };
    const cleanup = () => {
      options.signal?.removeEventListener("abort", onAbort);
    };
    for (const stream of [options.stdout, options.stderr]) {
      if (!stream || outputStreams.has(stream)) continue;
      outputStreams.add(stream);
      stream.on("error", onOutputError);
    }
    const writeOutput = (
      readable: NodeJS.ReadableStream,
      stream: NodeJS.WritableStream,
      chunk: Buffer,
    ) => {
      pendingWrites += 1;
      let writeFinished = false;
      const completeWrite = (error?: Error | null) => {
        if (writeFinished) return;
        writeFinished = true;
        if (error) onOutputError(error);
        pendingWrites -= 1;
        if (settled) removeOutputListenersWhenDrained();
        else finishWhenDrained();
      };
      try {
        const canContinue = stream.write(chunk, completeWrite);
        if (!canContinue) {
          readable.pause();
          stream.once("drain", () => readable.resume());
        }
      } catch (error) {
        completeWrite(
          error instanceof Error ? error : new Error(String(error)),
        );
      }
    };
    child.stdout?.on("data", (chunk: Buffer) => {
      if (outputError) return;
      if (options.stdout) {
        writeOutput(child.stdout!, options.stdout, chunk);
      } else {
        const decoded = stdoutDecoder.write(chunk);
        if (stdout.length < captureLimit)
          stdout += decoded.slice(0, captureLimit - stdout.length);
      }
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      if (outputError) return;
      if (options.stderr) {
        writeOutput(child.stderr!, options.stderr, chunk);
      } else {
        const decoded = stderrDecoder.write(chunk);
        if (stderr.length < captureLimit)
          stderr += decoded.slice(0, captureLimit - stderr.length);
      }
    });
    child.stdin?.on("error", onOutputError);
    if (options.stdin !== undefined) {
      try {
        child.stdin?.write(options.stdin);
      } catch (error) {
        onOutputError(
          error instanceof Error ? error : new Error(String(error)),
        );
      }
    }
    child.stdin?.end();
    options.signal?.addEventListener("abort", onAbort, { once: true });
    if (options.signal?.aborted) onAbort();

    child.on("error", (error) =>
      finish({ exitCode: null, signal: null, error: error.message }),
    );
    child.on("close", (code, signal) => {
      if (!options.stdout && stdout.length < captureLimit)
        stdout += stdoutDecoder.end().slice(0, captureLimit - stdout.length);
      if (!options.stderr && stderr.length < captureLimit)
        stderr += stderrDecoder.end().slice(0, captureLimit - stderr.length);
      finish({
        exitCode: code,
        signal,
        stdout: options.stdout ? undefined : stdout,
        stderr: options.stderr ? undefined : stderr,
      });
    });
  });

export function isCredentialEmpty(value: unknown): boolean {
  if (value === null || value === undefined) return true;
  if (Array.isArray(value)) return value.every(isCredentialEmpty);
  if (typeof value === "object") {
    return Object.values(value as Record<string, unknown>).every(
      isCredentialEmpty,
    );
  }
  if (typeof value === "string") return value.length === 0;
  if (typeof value === "number") return value === 0;
  if (typeof value === "boolean") return !value;
  return false;
}

export function parseAuditJson(stdout: string | undefined): unknown {
  if (!stdout) throw new RunSpecLikeError("audit_empty_output");
  try {
    return JSON.parse(stdout);
  } catch {
    throw new RunSpecLikeError("audit_invalid_json");
  }
}

export function verifySecretAudit(
  stdout: string | undefined,
  stage: string,
): void {
  const parsed = parseAuditJson(stdout);
  if (!isCredentialEmpty(parsed))
    throw new RunSpecLikeError("unapproved_credential_mapping:" + stage);
}

interface DeclaredEgress {
  host: string;
  method: string;
  path: string;
}

function declaredEgress(plan: SbxArgvPlan): DeclaredEgress[] {
  const out: DeclaredEgress[] = [];
  for (const argv of plan.allow_rules) {
    // Supervisor emits: policy allow network --sandbox <name> <host>
    //   --method <METHOD> --path <path>
    const sandboxFlag = argv.indexOf("--sandbox");
    if (sandboxFlag < 0) continue;
    const host = argv[sandboxFlag + 2];
    const methodIndex = argv.indexOf("--method");
    const pathIndex = argv.indexOf("--path");
    if (host && methodIndex > 0 && pathIndex > 0) {
      out.push({
        host,
        method: argv[methodIndex + 1],
        path: argv[pathIndex + 1],
      });
    }
  }
  return out;
}

export async function executeSbxPlan(
  plan: SbxArgvPlan,
  sbxPath: string,
  options: RunOptions,
  expectedSbxSha256?: string,
): Promise<RunReceipt> {
  const runArgv = options.runArgv ?? defaultArgvRunner;
  const env = scrubEnv(process.env, plan.host_environment_to_remove || []);
  const stages: RunStageResult[] = [];
  const receipt: RunReceipt = {
    status: "failed",
    sandboxName: plan.sandbox_name,
    stages,
    cleanup: { sandboxRemoved: false, scratchRemoved: false },
  };
  const egress = declaredEgress(plan);
  const auditLimit = options.auditCaptureLimit ?? DEFAULT_AUDIT_CAPTURE_LIMIT;

  const run = async (
    stage: string,
    argv: string[],
    opts: {
      capture?: boolean;
      stdin?: string;
      stream?: boolean;
      signal?: AbortSignal;
    } = {},
  ): Promise<ArgvRunResult> => {
    if (
      expectedSbxSha256 !== undefined &&
      !sbxDigestMatches(sbxPath, expectedSbxSha256)
    ) {
      const error = "runtime_integrity_lost";
      stages.push({ stage, exitCode: null, signal: null, error });
      throw new RunSpecLikeError(stage + ":" + error);
    }
    const fullArgv = [sbxPath, ...argv];
    const result = await runArgv(fullArgv, {
      env,
      signal: opts.signal ?? options.signal,
      stdin: opts.stdin,
      stdout: opts.stream ? options.stdout : undefined,
      stderr: opts.stream ? options.stderr : undefined,
      captureStdoutLimit: auditLimit,
    });
    stages.push({
      stage,
      exitCode: result.exitCode,
      signal: result.signal,
      audit: opts.capture ? safeParse(result.stdout) : undefined,
      error: result.error,
    });
    return result;
  };

  const requireOk = (stage: string, result: ArgvRunResult) => {
    if (result.error)
      throw new RunSpecLikeError(stage + ":spawn:" + result.error);
    if (result.exitCode !== 0)
      throw new RunSpecLikeError(
        stage + ":exit:" + (result.exitCode ?? "signal"),
      );
  };

  let sandboxCreated = false;
  try {
    const globalAudit = await run(
      "global_credential_audit",
      plan.global_credential_audit,
      {
        capture: true,
      },
    );
    requireOk("global_credential_audit", globalAudit);
    verifySecretAudit(globalAudit.stdout, "global");

    const sandboxAudit = await run(
      "sandbox_credential_audit",
      plan.sandbox_credential_audit,
      { capture: true },
    );
    requireOk("sandbox_credential_audit", sandboxAudit);
    verifySecretAudit(sandboxAudit.stdout, "sandbox");

    const accountAudit = await run(
      "account_policy_audit",
      plan.account_policy_audit,
      {
        capture: true,
      },
    );
    requireOk("account_policy_audit", accountAudit);

    const create = await run("create", plan.create);
    requireOk("create", create);
    sandboxCreated = true;

    const sandboxPolicy = await run(
      "sandbox_policy_audit",
      plan.sandbox_policy_audit,
      { capture: true },
    );
    requireOk("sandbox_policy_audit", sandboxPolicy);

    for (const [index, argv] of plan.allow_rules.entries()) {
      const grant = await run("allow_rule_" + index, argv);
      requireOk("allow_rule_" + index, grant);
    }

    const verify = await run("verify_policy", plan.verify_policy, {
      capture: true,
    });
    requireOk("verify_policy", verify);

    const verifyPolicyAudit =
      options.verifyPolicyAudit ?? verifyRuntimePolicyAudit;
    verifyPolicyAudit(
      {
        account: accountAudit.stdout,
        sandbox: sandboxPolicy.stdout,
        verify: verify.stdout,
      },
      egress,
      plan.sandbox_name,
    );

    const execute = await run("execute", plan.execute, { stream: true });
    receipt.exitCode = execute.exitCode;
    receipt.signal = execute.signal;
    if (execute.error)
      throw new RunSpecLikeError("execute:spawn:" + execute.error);
    receipt.status = execute.exitCode === 0 ? "completed" : "failed";
    if (execute.exitCode !== 0 && !execute.signal)
      receipt.reason = "guest_exit:" + execute.exitCode;
    if (execute.signal) {
      receipt.status = "cancelled";
      receipt.reason = "guest_signal:" + execute.signal;
    }
  } catch (error) {
    if (error instanceof PolicyAuditError) {
      receipt.status = "policy_refused";
      receipt.reason = error.code;
    } else if (error instanceof RunSpecLikeError) {
      receipt.status =
        error.code.startsWith("unapproved_") || error.code.startsWith("policy_")
          ? "policy_refused"
          : "failed";
      receipt.reason = error.code;
    } else if (options.signal?.aborted) {
      receipt.status = "cancelled";
      receipt.reason = "aborted";
    } else {
      receipt.status = "failed";
      receipt.reason = "internal_error";
    }
  } finally {
    if (sandboxCreated || plan.remove.length > 0) {
      try {
        const remove = await run("remove", plan.remove, {
          capture: true,
          signal: AbortSignal.timeout(CLEANUP_TIMEOUT_MS),
        });
        receipt.cleanup.sandboxRemoved = remove.exitCode === 0 && !remove.error;
      } catch {
        receipt.cleanup.sandboxRemoved = false;
      }
    } else {
      receipt.cleanup.sandboxRemoved = true;
    }
    try {
      const removeScratch =
        options.removeScratch ??
        ((scratch: string) =>
          rmSync(scratch, { recursive: true, force: true }));
      removeScratch(plan.scratch);
      receipt.cleanup.scratchRemoved = !existsSync(plan.scratch);
    } catch {
      receipt.cleanup.scratchRemoved = false;
    }
    if (
      receipt.status === "completed" &&
      (!receipt.cleanup.sandboxRemoved || !receipt.cleanup.scratchRemoved)
    ) {
      receipt.status = "failed";
      receipt.reason = "cleanup_failed";
    }
  }
  return receipt;
}

function safeParse(stdout: string | undefined): unknown {
  if (!stdout) return undefined;
  try {
    return JSON.parse(stdout);
  } catch {
    return { _unparsed: stdout.slice(0, 512) };
  }
}

export async function runGuestCommand(
  spec: RunSpec,
  options: RunOptions,
): Promise<RunReceipt> {
  const sbx = resolvePinnedSbx(options.sbxPath);
  const qualified =
    runtimeQualified(options.configDir) && !!sbx && pinnedSbxDigestMatches(sbx);
  if (!qualified || !sbx) {
    return {
      status: "runtime_not_qualified",
      reason: "runtime_not_qualified",
      stages: [],
      cleanup: { sandboxRemoved: true, scratchRemoved: true },
    };
  }
  let pinnedSbx: PinnedSbxRuntime;
  try {
    pinnedSbx = pinSbxRuntime(sbx);
  } catch {
    return {
      status: "runtime_not_qualified",
      reason: "runtime_not_qualified",
      stages: [],
      cleanup: { sandboxRemoved: true, scratchRemoved: true },
    };
  }
  let built: Awaited<ReturnType<typeof buildRunPlan>>;
  try {
    built = await buildRunPlan(spec, { ...options, sbxPath: pinnedSbx.path });
  } catch (error) {
    pinnedSbx.cleanup();
    return {
      status: "plan_failed",
      reason:
        error instanceof Error ? error.message.slice(0, 160) : "plan_failed",
      stages: [],
      cleanup: { sandboxRemoved: true, scratchRemoved: true },
    };
  }
  try {
    return await executeSbxPlan(
      built.plan,
      pinnedSbx.path,
      options,
      pinnedSbx.sha256,
    );
  } finally {
    built.cleanupScratch();
    pinnedSbx.cleanup();
  }
}

function resolvePinnedSbx(explicit?: string): string | undefined {
  const selected = explicit ?? process.env.AGENTSECRET_SBX ?? "sbx";
  if (selected.includes("/"))
    return executableFile(selected) && isExecutable(selected)
      ? selected
      : undefined;
  for (const directory of (process.env.PATH ?? "").split(delimiter)) {
    if (!directory) continue;
    const candidate = join(directory, selected);
    try {
      if (executableFile(candidate) && isExecutable(candidate))
        return candidate;
    } catch {
      // Continue through PATH; an unresolved command is not qualified.
    }
  }
  return undefined;
}

function isExecutable(path: string): boolean {
  try {
    accessSync(path, 1);
    return true;
  } catch {
    return false;
  }
}

function pinnedSbxDigestMatches(sbxPath: string): boolean {
  return sbxDigestMatches(sbxPath, SBX_QUALIFIED_SHA256);
}

function sbxDigestMatches(sbxPath: string, expectedSha256: string): boolean {
  try {
    return (
      createHash("sha256").update(readFileSync(sbxPath)).digest("hex") ===
      expectedSha256
    );
  } catch {
    return false;
  }
}

interface PinnedSbxRuntime {
  path: string;
  sha256: string;
  cleanup(): void;
}

/** Copy verified bytes into a private directory before any asynchronous work. */
export function pinSbxRuntime(
  sbxPath: string,
  expectedSha256 = SBX_QUALIFIED_SHA256,
): PinnedSbxRuntime {
  const bytes = readFileSync(sbxPath);
  const sourceDigest = createHash("sha256").update(bytes).digest("hex");
  if (sourceDigest !== expectedSha256)
    throw new RunSpecLikeError("runtime_integrity_unverified");

  const directory = mkdtempSync(join(tmpdir(), "agentsecret-sbx-runtime-"));
  try {
    const path = join(directory, "sbx");
    writeFileSync(path, bytes, { mode: 0o500, flag: "wx" });
    chmodSync(path, 0o500);
    const copiedDigest = createHash("sha256")
      .update(readFileSync(path))
      .digest("hex");
    if (copiedDigest !== expectedSha256)
      throw new RunSpecLikeError("runtime_integrity_unverified");
    return {
      path,
      sha256: expectedSha256,
      cleanup: () => rmSync(directory, { recursive: true, force: true }),
    };
  } catch (error) {
    rmSync(directory, { recursive: true, force: true });
    throw error;
  }
}

export function runtimeQualified(configDir?: string): boolean {
  if (!configDir) return false;
  let receipt: unknown;
  try {
    receipt = JSON.parse(
      readFileSync(join(configDir, "runtime-qualified.json"), "utf8"),
    );
  } catch {
    return false;
  }
  if (typeof receipt !== "object" || receipt === null) return false;
  const record = receipt as Record<string, unknown>;
  const keys = [
    "schema",
    "sbx_version",
    "sbx_sha256",
    "evidence_sha256",
    "qualified_at",
  ];
  return (
    Object.keys(record).length === keys.length &&
    keys.every((key) => Object.hasOwn(record, key)) &&
    record.schema === "agentsecret.runtime-qualified/v1" &&
    record.sbx_version === SBX_QUALIFIED_VERSION &&
    record.sbx_sha256 === SBX_QUALIFIED_SHA256 &&
    record.evidence_sha256 === T015_EVIDENCE_SHA256 &&
    typeof record.qualified_at === "string" &&
    Number.isFinite(Date.parse(record.qualified_at))
  );
}

export function writeRuntimeQualificationReceipt(configDir: string): void {
  mkdirSync(configDir, { recursive: true, mode: 0o700 });
  const receiptPath = join(configDir, "runtime-qualified.json");
  writeFileSync(
    receiptPath,
    JSON.stringify(
      {
        schema: "agentsecret.runtime-qualified/v1",
        sbx_version: SBX_QUALIFIED_VERSION,
        sbx_sha256: SBX_QUALIFIED_SHA256,
        evidence_sha256: T015_EVIDENCE_SHA256,
        qualified_at: new Date().toISOString(),
      },
      null,
      2,
    ) + "\n",
    { mode: 0o600 },
  );
  chmodSync(receiptPath, 0o600);
}
