/**
 * Parse `agentsecret run` arguments into the supervisor's closed v1 run
 * request. This module validates early for clear errors; the Rust supervisor
 * re-validates the emitted JSON before staging or planning.
 */

export const RUN_SPEC_LIMITS = {
  maxArguments: 128,
  maxFileAccess: 64,
  maxEgressRules: 64,
  maxAliasBindings: 32,
} as const;

const SUPPORTED_METHODS = new Set([
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
]);

export interface RunFileGrant {
  hostPath: string;
  guestPath: string;
  mode: "read_only" | "read_write";
}

export interface RunEgressRule {
  host: string;
  method: string;
  path: string;
}

export interface RunSpec {
  executable: string;
  argv: string[];
  workingDirectory: string;
  fileAccess: RunFileGrant[];
  referenceBindings: RunReferenceBinding[];
  egress: RunEgressRule[];
}

export interface RunReferenceBinding {
  envName: string;
  alias: string;
  fieldPath?: string;
}

export class RunSpecError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

function fail(code: string): never {
  throw new RunSpecError(code);
}

function isGuestAbsolutePath(value: string): boolean {
  return (
    value.startsWith("/") &&
    !value.includes("\0") &&
    !value.includes("\\") &&
    value !== "/" &&
    !value.endsWith("/") &&
    value
      .slice(1)
      .split("/")
      .every((part) => part.length > 0 && part !== "." && part !== "..")
  );
}

function isWorkspacePath(value: string): boolean {
  return (
    isGuestAbsolutePath(value) &&
    (value === "/workspace" || value.startsWith("/workspace/"))
  );
}

function isHostAbsolutePath(value: string): boolean {
  return (
    isGuestAbsolutePath(value) && !value.includes("\n") && !value.includes("\r")
  );
}

function isDnsHostname(value: string): boolean {
  if (
    value.length < 4 ||
    value.length > 253 ||
    value !== value.toLowerCase() ||
    /^[0-9.]+$/.test(value) ||
    value.endsWith(".local") ||
    value.endsWith(".localhost")
  )
    return false;
  const labels = value.split(".");
  if (labels.length < 2) return false;
  return labels.every(
    (label) =>
      label.length > 0 &&
      label.length <= 63 &&
      !label.startsWith("-") &&
      !label.endsWith("-") &&
      /^[a-z0-9-]+$/.test(label),
  );
}

function isExactPath(value: string): boolean {
  return (
    isGuestAbsolutePath(value) &&
    !value.includes("*") &&
    !value.includes("?") &&
    !value.includes("#") &&
    !value.includes("%") &&
    !/[\s]/.test(value) &&
    !value.includes("\n") &&
    !value.includes("\r")
  );
}

/** Resolve a declared host path to an absolute path beneath hostRoot. */
export function resolveHostPath(hostPath: string, hostRoot: string): string {
  if (!isHostAbsolutePath(hostPath)) fail("run_file_host_path_invalid");
  const root = hostRoot.endsWith("/") ? hostRoot.slice(0, -1) : hostRoot;
  if (hostPath !== root && !hostPath.startsWith(root + "/"))
    fail("run_file_outside_workspace");
  return hostPath;
}

function parseFileGrant(value: string, hostRoot: string): RunFileGrant {
  const eq = value.indexOf("=");
  if (eq <= 0) fail("run_file_grant_invalid");
  const hostPath = resolveHostPath(value.slice(0, eq), hostRoot);
  let guest = value.slice(eq + 1);
  let mode: RunFileGrant["mode"] = "read_only";
  for (const [suffix, mapped] of [
    [":rw", "read_write"],
    [":read-write", "read_write"],
    [":read_write", "read_write"],
    [":ro", "read_only"],
    [":read-only", "read_only"],
    [":read_only", "read_only"],
  ] as const) {
    if (guest.endsWith(suffix)) {
      mode = mapped;
      guest = guest.slice(0, guest.length - suffix.length);
      break;
    }
  }
  if (!isWorkspacePath(guest)) fail("run_file_guest_path_invalid");
  return { hostPath, guestPath: guest, mode };
}

function parseEgressRule(value: string): RunEgressRule {
  const first = value.indexOf(":");
  if (first <= 0) fail("run_egress_rule_invalid");
  const host = value.slice(0, first);
  const second = value.indexOf(":", first + 1);
  if (second <= first + 1) fail("run_egress_rule_invalid");
  const method = value.slice(first + 1, second);
  const path = value.slice(second + 1);
  if (!isDnsHostname(host)) fail("run_egress_host_invalid");
  if (!SUPPORTED_METHODS.has(method)) fail("run_egress_method_invalid");
  if (!isExactPath(path)) fail("run_egress_path_invalid");
  return { host, method, path };
}

function isEnvName(value: string): boolean {
  return (
    /^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(value) &&
    value !== "PATH" &&
    !value.startsWith("AGENTSECRET_")
  );
}

function isRunAlias(value: string): boolean {
  return /^[A-Z][A-Z0-9_-]{0,127}$/.test(value);
}

function isFieldPath(value: string): boolean {
  return (
    value.startsWith("/") &&
    value.length <= 512 &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function parseReferenceBinding(value: string): RunReferenceBinding {
  const first = value.indexOf("=");
  if (first <= 0) fail("run_reference_binding_invalid");
  const envName = value.slice(0, first);
  const rest = value.slice(first + 1);
  const second = rest.indexOf("#");
  if (second <= 0) fail("run_reference_binding_invalid");
  const alias = rest.slice(0, second);
  const fieldPath = rest.slice(second + 1);
  if (!isEnvName(envName) || !isRunAlias(alias) || !isFieldPath(fieldPath))
    fail("run_reference_binding_invalid");
  return { envName, alias, fieldPath };
}

/**
 * Parse `run` arguments. Everything after a literal `--` is the guest command;
 * options before it declare workspace files and exact HTTPS egress grants.
 */
export function parseRunArgs(args: string[], hostRoot: string): RunSpec {
  const separator = args.indexOf("--");
  if (separator < 0) fail("run_command_separator_required");
  const options = args.slice(0, separator);
  const command = args.slice(separator + 1);
  if (command.length === 0) fail("run_command_required");

  const fileAccess: RunFileGrant[] = [];
  const referenceBindings: RunReferenceBinding[] = [];
  const egress: RunEgressRule[] = [];
  let workingDirectory = "/workspace";
  const seenFiles = new Set<string>();
  const seenReferenceEnv = new Set<string>();
  const seenEgress = new Set<string>();

  for (let i = 0; i < options.length; i++) {
    const flag = options[i];
    const take = () => {
      const value = options[++i];
      if (value === undefined) fail("run_option_value_required");
      return value;
    };
    if (flag === "--file" || flag === "--grant-file") {
      const grant = parseFileGrant(take(), hostRoot);
      if (seenFiles.has(grant.guestPath)) fail("run_file_guest_path_duplicate");
      seenFiles.add(grant.guestPath);
      fileAccess.push(grant);
    } else if (flag === "--reference-binding") {
      const binding = parseReferenceBinding(take());
      const key = binding.envName.toLowerCase();
      if (seenReferenceEnv.has(key)) fail("run_reference_binding_duplicate");
      seenReferenceEnv.add(key);
      referenceBindings.push(binding);
    } else if (flag === "--egress") {
      const rule = parseEgressRule(take());
      const key = `${rule.host}\0${rule.method}\0${rule.path}`;
      if (seenEgress.has(key)) fail("run_egress_rule_duplicate");
      seenEgress.add(key);
      egress.push(rule);
    } else if (flag === "--cwd") {
      const value = take();
      if (!isWorkspacePath(value)) fail("run_working_directory_invalid");
      workingDirectory = value;
    } else {
      fail("run_option_unknown");
    }
  }

  if (fileAccess.length > RUN_SPEC_LIMITS.maxFileAccess)
    fail("run_file_access_too_many");
  if (referenceBindings.length > RUN_SPEC_LIMITS.maxAliasBindings)
    fail("run_reference_bindings_too_many");
  if (egress.length > RUN_SPEC_LIMITS.maxEgressRules)
    fail("run_egress_too_many");

  const executable = command[0];
  const argv = command.slice(1);
  if (!isGuestAbsolutePath(executable)) fail("run_executable_invalid");
  if (argv.length > RUN_SPEC_LIMITS.maxArguments) fail("run_argv_too_many");
  if (argv.some((arg) => arg.includes("\0"))) fail("run_argv_invalid");

  return {
    executable,
    argv,
    workingDirectory,
    fileAccess,
    referenceBindings,
    egress,
  };
}

/** Build the closed v1 run-request JSON consumed by the supervisor. */
export function buildRunRequest(spec: RunSpec): Record<string, unknown> {
  return {
    version: 1,
    executable: spec.executable,
    argv: spec.argv,
    working_directory: spec.workingDirectory,
    file_access: spec.fileAccess.map((grant) => ({
      host_path: grant.hostPath,
      guest_path: grant.guestPath,
      mode: grant.mode,
    })),
    reference_bindings: spec.referenceBindings.map((binding) => ({
      env_name: binding.envName,
      alias: binding.alias,
      ...(binding.fieldPath !== undefined
        ? { field_path: binding.fieldPath }
        : {}),
    })),
    egress: spec.egress.map((rule) => ({
      host: rule.host,
      method: rule.method,
      path: rule.path,
      port: 443,
    })),
  };
}
