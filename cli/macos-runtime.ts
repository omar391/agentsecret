import childProcess, { spawn, type StdioOptions } from "node:child_process";
import {
  accessSync,
  constants,
  lstatSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const SANDBOX_EXEC = "/usr/bin/sandbox-exec";
const SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin";

export interface MacSandboxOptions {
  executable: string;
  args: string[];
  cwd: string;
  readPaths?: string[];
  writePaths?: string[];
}

export interface MacSandboxInvocation {
  command: string;
  args: string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
  runtimeIdentity: MacSandboxRuntimeIdentity;
  cleanup(): void;
}

export interface MacSandboxRuntimeIdentity {
  executable: string;
  identifier: "com.apple.sandbox-exec";
  cdhash: string;
  osVersion: string;
  osBuild: string;
}

export function parseMacSandboxRuntimeIdentity(
  signature: string,
  osVersion: string,
  osBuild: string,
): MacSandboxRuntimeIdentity {
  const identifier = /^Identifier=([^\r\n]+)$/m.exec(signature)?.[1];
  const cdhash = /^CDHash=([a-f0-9]{40})$/m.exec(signature)?.[1];
  if (
    identifier !== "com.apple.sandbox-exec" ||
    !cdhash ||
    !/^Authority=Apple Code Signing Certification Authority$/m.test(
      signature,
    ) ||
    !/^Authority=Apple Root CA$/m.test(signature) ||
    !/^\d+(?:\.\d+){1,3}$/.test(osVersion) ||
    !/^[A-Za-z0-9._-]{1,64}$/.test(osBuild)
  )
    throw new Error("Unexpected system runtime identity.");
  return {
    executable: SANDBOX_EXEC,
    identifier,
    cdhash,
    osVersion,
    osBuild,
  };
}

/** Verify the OS-provided sandbox component independently of the downloaded CLI module. */
export function verifyMacSandboxRuntime(): MacSandboxRuntimeIdentity {
  if (process.platform !== "darwin")
    throw new Error("Native command execution is supported on macOS only.");
  try {
    if (realpathSync(SANDBOX_EXEC) !== SANDBOX_EXEC)
      throw new Error("Unexpected system runtime path.");
    accessSync(SANDBOX_EXEC, constants.X_OK);
    childProcess.execFileSync(
      "/usr/bin/codesign",
      ["--verify", "--strict", SANDBOX_EXEC],
      { stdio: "ignore", timeout: 5000 },
    );
    const details = childProcess.spawnSync(
      "/usr/bin/codesign",
      ["-dv", "--verbose=4", SANDBOX_EXEC],
      {
        encoding: "utf8",
        timeout: 5000,
        windowsHide: true,
      },
    );
    if (details.error || details.status !== 0)
      throw new Error("Unable to inspect system runtime signature.");
    const signature = `${details.stdout}\n${details.stderr}`;
    const osVersion = childProcess
      .execFileSync("/usr/bin/sw_vers", ["-productVersion"], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        timeout: 5000,
      })
      .trim();
    const osBuild = childProcess
      .execFileSync("/usr/bin/sw_vers", ["-buildVersion"], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        timeout: 5000,
      })
      .trim();
    return parseMacSandboxRuntimeIdentity(signature, osVersion, osBuild);
  } catch {
    throw new Error(
      "The Apple-signed macOS sandbox runtime could not be verified.",
    );
  }
}

function canonicalPath(
  value: string,
  kind: "file" | "directory",
  label: string,
) {
  if (typeof value !== "string" || !value || value.includes("\0"))
    throw new Error(`${label} must be a valid path.`);
  let resolved: string;
  try {
    resolved = realpathSync(path.resolve(value));
  } catch {
    throw new Error(`${label} does not exist.`);
  }
  let info;
  try {
    info = statSync(resolved);
  } catch {
    throw new Error(`${label} is unavailable.`);
  }
  if (kind === "directory" ? !info.isDirectory() : !info.isFile())
    throw new Error(`${label} must be an existing ${kind}.`);
  return resolved;
}

function isWithinPath(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return (
    relative === "" ||
    (relative !== ".." &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative))
  );
}

function resolveActiveCommandLineGit(): {
  executable: string;
  readPaths: string[];
  execPath: string;
} {
  let developerDirValue: string;
  try {
    developerDirValue = childProcess
      .execFileSync("/usr/bin/xcode-select", ["-p"], {
        encoding: "utf8",
        timeout: 2000,
        stdio: ["ignore", "pipe", "pipe"],
      })
      .trim();
  } catch {
    throw new Error("Unable to resolve active Command Line Tools Git.");
  }
  const developerDir = canonicalPath(
    developerDirValue,
    "directory",
    "Active developer directory",
  );
  const gitBin = canonicalPath(
    path.join(developerDir, "usr", "bin"),
    "directory",
    "Command Line Tools Git binary directory",
  );
  const gitCore = canonicalPath(
    path.join(developerDir, "usr", "libexec", "git-core"),
    "directory",
    "Command Line Tools Git support directory",
  );
  const gitShare = canonicalPath(
    path.join(developerDir, "usr", "share", "git-core"),
    "directory",
    "Command Line Tools Git data directory",
  );
  const executable = canonicalPath(
    path.join(gitBin, "git"),
    "file",
    "Command Line Tools Git executable",
  );
  if (
    ![gitBin, gitCore, gitShare, executable].every((candidate) =>
      isWithinPath(developerDir, candidate),
    )
  )
    throw new Error("Active Command Line Tools Git paths are inconsistent.");
  try {
    accessSync(executable, constants.X_OK);
  } catch {
    throw new Error("Active Command Line Tools Git is not executable.");
  }
  return {
    executable,
    readPaths: [gitBin, gitCore, gitShare],
    execPath: gitCore,
  };
}

function addPathRule(
  profile: string[],
  args: string[],
  access: "read" | "write",
  value: string,
  kind: "file" | "directory",
  index: number,
) {
  const parameter = `${access.toUpperCase()}_${index}`;
  const rule = kind === "directory" ? "subpath" : "literal";
  profile.push(`(allow file-${access}* (${rule} (param "${parameter}")))`);
  args.push("-D", `${parameter}=${value}`);
}

/**
 * Seatbelt canonicalization (realpath) walks a path component by component
 * from /. A subpath grant on a deep directory does not cover the literal
 * ancestor directories above it, so git clone file:// fails with
 * fatal: Invalid path while the receiving clone canonicalizes the remote
 * path. Fetch into an existing repo does not hit this because it operates
 * on the granted cwd tree only. Grant literal read access to every ancestor
 * directory of each granted directory root, from / down to the root parent,
 * so canonicalization can resolve the chain. A literal rule allows only
 * that exact directory, not its contents, so this does not expose sibling
 * files outside the granted subtree.
 */
function ancestorDirs(value: string): string[] {
  const ancestors: string[] = [];
  let current = path.resolve(value);
  while (current !== path.parse(current).root) {
    current = path.dirname(current);
    ancestors.push(current);
  }
  return [...ancestors].reverse();
}

function addAncestorLiteralRules(
  profile: string[],
  args: string[],
  value: string,
  startIndex: number,
): number {
  let index = startIndex;
  for (const ancestor of ancestorDirs(value)) {
    const parameter = `READ_ANCESTOR_${index++}`;
    // Ancestor access exists only to let path canonicalization stat each
    // component. `file-read*` also permits directory enumeration, exposing
    // names outside the granted roots (for example `ls /private`). Metadata
    // access is sufficient for Git's file:// clone and keeps contents and
    // directory entries denied.
    profile.push(`(allow file-read-metadata (literal (param "${parameter}")))`);
    args.push("-D", `${parameter}=${ancestor}`);
  }
  return index;
}

/**
 * Seatbelt's path rules do not distinguish a file from a hard link to the same
 * inode outside the allowed tree. Refuse pre-existing hard links in every
 * directory root we grant to a child. The profile also denies child-created
 * hard links, but a concurrent host-side change can still race this preflight.
 */
export function assertNoHardLinksInRoots(roots: string[]): void {
  const pending = [...new Set(roots.map((root) => realpathSync(root)))];
  let visited = 0;
  while (pending.length > 0) {
    const current = pending.pop()!;
    let entries;
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      throw new Error("Unable to inspect a sandbox filesystem root.");
    }
    for (const entry of entries) {
      visited++;
      if (visited > 100_000)
        throw new Error("Sandbox filesystem root is too large to inspect.");
      if (entry.isSymbolicLink()) continue;
      const entryPath = path.join(current, entry.name);
      let info;
      try {
        info = lstatSync(entryPath);
      } catch {
        throw new Error("Unable to inspect a sandbox filesystem entry.");
      }
      if (info.isDirectory()) pending.push(entryPath);
      else if (info.isFile() && info.nlink > 1)
        throw new Error(
          "Sandbox filesystem roots must not contain hard-linked files.",
        );
    }
  }
}

/** Build a macOS system Seatbelt invocation; callers must always clean its private temp directory. */
export function prepareMacSandbox(
  options: MacSandboxOptions,
): MacSandboxInvocation {
  const runtimeIdentity = verifyMacSandboxRuntime();
  if (
    !Array.isArray(options.args) ||
    options.args.some((arg) => typeof arg !== "string" || arg.includes("\0"))
  )
    throw new Error("Command arguments must be valid strings.");

  const cwd = canonicalPath(options.cwd, "directory", "Working directory");
  const requestedExecutable = canonicalPath(
    path.isAbsolute(options.executable)
      ? options.executable
      : path.resolve(cwd, options.executable),
    "file",
    "Executable",
  );
  let executable = requestedExecutable;
  let implicitReadPaths: string[] = [];
  const envOverrides: NodeJS.ProcessEnv = {};
  if (requestedExecutable === "/usr/bin/git") {
    const activeGit = resolveActiveCommandLineGit();
    executable = activeGit.executable;
    implicitReadPaths = activeGit.readPaths;
    envOverrides.GIT_EXEC_PATH = activeGit.execPath;
  }
  try {
    accessSync(executable, constants.X_OK);
  } catch {
    throw new Error("Executable is not executable.");
  }

  const readPathInputs = [...(options.readPaths || []), ...implicitReadPaths];
  const readPaths = [
    ...new Set(
      readPathInputs.map((value, index) => {
        const resolved = canonicalPath(
          value,
          "directory",
          `Read path ${index + 1}`,
        );
        return resolved;
      }),
    ),
  ];
  const writePaths = (options.writePaths || []).map((value, index) =>
    canonicalPath(value, "directory", `Write path ${index + 1}`),
  );
  assertNoHardLinksInRoots([cwd, ...readPaths, ...writePaths]);
  const scratch = realpathSync(
    mkdtempSync(path.join(tmpdir(), "agentsecret-run-")),
  );

  try {
    const profile = [
      "(version 1)",
      "(deny default)",
      '(import "system.sb")',
      "(deny file-link)",
      "(allow process-exec* process-fork)",
      "(allow signal (target self))",
      '(allow file-read* (subpath "/bin") (subpath "/usr/bin") (subpath "/usr/sbin") (subpath "/sbin"))',
      '(allow file-read* (literal "/private/var/select/sh"))',
      '(allow process-exec (subpath "/bin") (subpath "/usr/bin") (subpath "/usr/sbin") (subpath "/sbin"))',
      '(allow process-exec (literal "/private/var/select/sh"))',
      "(deny network*)",
    ];
    const runtimeArgs = ["-p", profile.join("\n")];
    addPathRule(profile, runtimeArgs, "read", cwd, "directory", 0);
    addPathRule(profile, runtimeArgs, "write", cwd, "directory", 0);
    addPathRule(profile, runtimeArgs, "read", executable, "file", 1);
    addPathRule(profile, runtimeArgs, "read", scratch, "directory", 2);
    addPathRule(profile, runtimeArgs, "write", scratch, "directory", 1);
    for (const [index, root] of readPaths.entries())
      addPathRule(profile, runtimeArgs, "read", root, "directory", index + 3);
    for (const [index, root] of writePaths.entries())
      addPathRule(profile, runtimeArgs, "write", root, "directory", index + 2);
    {
      // Grant literal reads on ancestor dirs of cwd and every read root so
      // realpath canonicalization of deep paths (file:// clone URLs, dest
      // paths) can resolve the chain without exposing sibling contents.
      let nextAncestor = 1000;
      nextAncestor = addAncestorLiteralRules(
        profile,
        runtimeArgs,
        cwd,
        nextAncestor,
      );
      for (const root of readPaths) {
        nextAncestor = addAncestorLiteralRules(
          profile,
          runtimeArgs,
          root,
          nextAncestor,
        );
      }
      for (const root of writePaths) {
        nextAncestor = addAncestorLiteralRules(
          profile,
          runtimeArgs,
          root,
          nextAncestor,
        );
      }
      void nextAncestor;
    }
    runtimeArgs[1] = profile.join("\n");
    runtimeArgs.push(executable, ...options.args);

    const env: NodeJS.ProcessEnv = {
      PATH: SYSTEM_PATH,
      HOME: cwd,
      TMPDIR: scratch,
      ...envOverrides,
    };
    for (const name of ["LANG", "LC_ALL", "LC_CTYPE", "TERM"] as const) {
      const value = process.env[name];
      if (value && /^[A-Za-z0-9_.@+-]{1,128}$/.test(value)) env[name] = value;
    }
    return {
      command: SANDBOX_EXEC,
      args: runtimeArgs,
      cwd,
      env,
      runtimeIdentity,
      cleanup() {
        rmSync(scratch, { recursive: true, force: true });
      },
    };
  } catch (error) {
    rmSync(scratch, { recursive: true, force: true });
    throw error;
  }
}

export async function runMacSandbox(
  options: MacSandboxOptions,
  signal: AbortSignal,
  stdio: StdioOptions = "inherit",
): Promise<number> {
  signal.throwIfAborted();
  const invocation = prepareMacSandbox(options);
  let terminated = false;
  let spawned = false;
  try {
    const result = await new Promise<number>((resolve, reject) => {
      const child = spawn(invocation.command, invocation.args, {
        cwd: invocation.cwd,
        env: invocation.env,
        stdio,
        detached: true,
        shell: false,
        windowsHide: true,
      });
      // Node may assign pid before emitting the deferred "spawn" event. A
      // pid is enough to treat the process as possibly live for cleanup.
      spawned = child.pid !== undefined;
      child.once("spawn", () => {
        spawned = true;
      });
      let finished = false;
      let stopping = false;
      let closed = false;
      let exitCode: number | null = null;
      let spawnError: Error | undefined;
      let escalation: ReturnType<typeof setTimeout> | undefined;
      let poll: ReturnType<typeof setTimeout> | undefined;
      const groupExists = () => {
        if (!child.pid) return false;
        try {
          process.kill(-child.pid, 0);
          return true;
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
          if ((error as NodeJS.ErrnoException).code === "EPERM") {
            // macOS can refuse a group probe after its leader exits. Confirm
            // absence using the host process inventory; EPERM alone proves nothing.
            try {
              const inventory = childProcess.execFileSync(
                "/bin/ps",
                ["-axo", "pgid="],
                {
                  encoding: "utf8",
                  timeout: 1000,
                  stdio: ["ignore", "pipe", "pipe"],
                },
              );
              const groups = inventory.trim().split("\n");
              if (
                groups.length > 0 &&
                groups.every((group) => /^\s*\d+\s*$/.test(group))
              ) {
                if (!groups.some((group) => Number(group) === child.pid))
                  return false;
                return true;
              }
            } catch {
              // A failed inventory leaves termination unproven.
            }
          }
          throw error;
        }
      };
      const killGroup = (kind: NodeJS.Signals) => {
        if (!child.pid) return;
        try {
          process.kill(-child.pid, kind);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
        }
      };
      const finish = (error?: Error) => {
        if (finished) return;
        finished = true;
        signal.removeEventListener("abort", cancel);
        if (escalation) clearTimeout(escalation);
        if (poll) clearTimeout(poll);
        if (error || spawnError) reject(error || spawnError);
        else resolve(signal.aborted ? 130 : (exitCode ?? 1));
      };
      let deadline = 0;
      const check = () => {
        try {
          if (closed && !groupExists()) return finish();
          if (Date.now() >= deadline)
            return finish(
              new Error("Could not terminate sandbox process group."),
            );
          poll = setTimeout(check, 25);
        } catch (error) {
          finish(error as Error);
        }
      };
      const stopGroup = () => {
        if (stopping) return;
        stopping = true;
        deadline = Date.now() + 5000;
        try {
          killGroup("SIGTERM");
          escalation = setTimeout(() => {
            try {
              killGroup("SIGKILL");
            } catch (error) {
              finish(error as Error);
            }
          }, 1200);
          check();
        } catch (error) {
          finish(error as Error);
        }
      };
      const cancel = () => stopGroup();
      signal.addEventListener("abort", cancel, { once: true });
      child.once("error", (error) => {
        spawnError = error;
      });
      child.once("close", (code) => {
        closed = true;
        exitCode = code;
        if (!stopping) stopGroup();
      });
      if (signal.aborted) cancel();
    });
    terminated = true;
    return result;
  } finally {
    // A failed spawn cannot still be using scratch. Once a process did start,
    // retain scratch when process-group termination could not be established.
    if (terminated || !spawned) invocation.cleanup();
  }
}
