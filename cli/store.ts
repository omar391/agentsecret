import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  chmodSync,
  readFileSync,
  writeFileSync,
  renameSync,
  existsSync,
  lstatSync,
  unlinkSync,
  rmSync,
} from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
export interface Credentials {
  server: string;
  accessToken: string;
  expiresAt: number;
  tenant: string;
}
const folder =
  process.env.AGENTSECRET_CONFIG_DIR || path.join(homedir(), ".agentsecret-v3");
export const configDir = folder;
const file = path.join(folder, "session.json");
const pendingWritesFile = path.join(folder, "pending-secret-writes.json");
const pendingWritesLock = path.join(folder, "pending-secret-writes.lock");
const sessionStateLock = path.join(folder, "session-state.lock");
function profile(server: string) {
  return Buffer.from(server).toString("base64url");
}
function windowsProfile(server: string) {
  return createHash("sha256").update(server).digest("base64url");
}
const windowsCredentialScript = String.raw`
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class AgentSecretCredential {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  private struct CREDENTIAL {
    public UInt32 Flags; public UInt32 Type; public string TargetName;
    public string Comment; public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public UInt32 CredentialBlobSize; public IntPtr CredentialBlob;
    public UInt32 Persist; public UInt32 AttributeCount; public IntPtr Attributes;
    public string TargetAlias; public string UserName;
  }
  [DllImport("advapi32.dll", EntryPoint="CredWriteW", CharSet=CharSet.Unicode, SetLastError=true)]
  private static extern bool CredWrite(ref CREDENTIAL credential, UInt32 flags);
  [DllImport("advapi32.dll", EntryPoint="CredReadW", CharSet=CharSet.Unicode, SetLastError=true)]
  private static extern bool CredRead(string target, UInt32 type, UInt32 flags, out IntPtr credential);
  [DllImport("advapi32.dll", EntryPoint="CredDeleteW", CharSet=CharSet.Unicode, SetLastError=true)]
  private static extern bool CredDelete(string target, UInt32 type, UInt32 flags);
  [DllImport("advapi32.dll", SetLastError=true)] private static extern void CredFree(IntPtr credential);
  public static void Write(string target, string value) {
    byte[] bytes = Encoding.UTF8.GetBytes(value);
    IntPtr blob = Marshal.AllocHGlobal(bytes.Length);
    try {
      Marshal.Copy(bytes, 0, blob, bytes.Length);
      var c = new CREDENTIAL { Type=1, TargetName=target, CredentialBlobSize=(UInt32)bytes.Length,
        CredentialBlob=blob, Persist=2, UserName=Environment.UserName };
      if (!CredWrite(ref c, 0)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    } finally { Marshal.FreeHGlobal(blob); Array.Clear(bytes, 0, bytes.Length); }
  }
  public static string Read(string target) {
    IntPtr ptr;
    if (!CredRead(target, 1, 0, out ptr)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    try {
      var c = Marshal.PtrToStructure<CREDENTIAL>(ptr);
      if (c.CredentialBlobSize == 0 || c.CredentialBlobSize > 5120)
        throw new InvalidOperationException("Credential size is invalid.");
      byte[] bytes = new byte[c.CredentialBlobSize];
      Marshal.Copy(c.CredentialBlob, bytes, 0, bytes.Length);
      try { return Convert.ToBase64String(bytes); }
      finally { Array.Clear(bytes, 0, bytes.Length); }
    } finally { CredFree(ptr); }
  }
  public static void Delete(string target) {
    if (!CredDelete(target, 1, 0)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  }
}
'@
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
switch ($request.operation) {
  'write' { [AgentSecretCredential]::Write($request.target, $request.value) }
  'read' { [Console]::Out.Write([AgentSecretCredential]::Read($request.target)) }
  'delete' { [AgentSecretCredential]::Delete($request.target) }
  default { throw 'Invalid credential operation' }
}
`;
function windowsCredential(
  operation: "write" | "read" | "delete",
  target: string,
  value?: string,
) {
  return execFileSync(
    "powershell.exe",
    [
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      windowsCredentialScript,
    ],
    {
      input: JSON.stringify({
        operation,
        target,
        ...(value === undefined ? {} : { value }),
      }),
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    },
  ).trim();
}
function assertKeyMatches(actual: JsonWebKey, expected: JsonWebKey) {
  if (
    actual.d !== expected.d ||
    actual.x !== expected.x ||
    actual.y !== expected.y
  )
    throw new Error("Credential-store verification failed");
}
export function privateKey(server: string, value?: JsonWebKey): JsonWebKey {
  const account = profile(server);
  const service = "AgentSecret-v3";
  try {
    if (process.platform === "darwin") {
      if (value) {
        const encoded = Buffer.from(JSON.stringify(value)).toString(
          "base64url",
        );
        execFileSync("/usr/bin/security", ["-i"], {
          input: `add-generic-password -U -a "${account}" -s "${service}" -w "${encoded}"\n`,
          stdio: ["pipe", "ignore", "pipe"],
        });
        const restored = privateKey(server);
        assertKeyMatches(restored, value);
        return value;
      }
      const encoded = execFileSync(
        "/usr/bin/security",
        ["find-generic-password", "-a", account, "-s", service, "-w"],
        { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
      ).trim();
      return JSON.parse(Buffer.from(encoded, "base64url").toString());
    }
    if (process.platform === "linux") {
      if (value) {
        execFileSync(
          "secret-tool",
          [
            "store",
            "--label=AgentSecret signing key",
            "service",
            service,
            "profile",
            account,
          ],
          { input: JSON.stringify(value), stdio: ["pipe", "ignore", "pipe"] },
        );
        assertKeyMatches(privateKey(server), value);
        return value;
      }
      return JSON.parse(
        execFileSync(
          "secret-tool",
          ["lookup", "service", service, "profile", account],
          { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
        ),
      );
    }
    if (process.platform === "win32") {
      const target = service + ":" + windowsProfile(server);
      if (value) {
        const encoded = Buffer.from(JSON.stringify(value)).toString(
          "base64url",
        );
        windowsCredential("write", target, encoded);
        const restored = privateKey(server);
        assertKeyMatches(restored, value);
        return value;
      }
      const encoded = windowsCredential("read", target);
      return JSON.parse(
        Buffer.from(
          Buffer.from(encoded, "base64").toString("utf8"),
          "base64url",
        ).toString("utf8"),
      );
    }
  } catch {
    throw new Error(
      "Operating-system credential storage is unavailable or denied. Use an unlocked macOS Keychain, Linux Secret Service, Windows Credential Manager, or ephemeral CI federation.",
    );
  }
  throw new Error(
    "Persistent signing-key storage is unsupported on this platform. Use ephemeral CI federation.",
  );
}
function deletePrivateKey(server: string) {
  if (process.platform === "darwin") {
    execFileSync(
      "/usr/bin/security",
      [
        "delete-generic-password",
        "-a",
        profile(server),
        "-s",
        "AgentSecret-v3",
      ],
      { stdio: "ignore" },
    );
    return;
  }
  if (process.platform === "linux") {
    execFileSync(
      "secret-tool",
      ["clear", "service", "AgentSecret-v3", "profile", profile(server)],
      { stdio: "ignore" },
    );
    return;
  }
  if (process.platform === "win32") {
    windowsCredential("delete", "AgentSecret-v3:" + windowsProfile(server));
    return;
  }
  throw new Error("Persistent signing-key storage is unsupported.");
}
export function load(): Credentials | null {
  let folderInfo;
  try {
    folderInfo = lstatSync(folder);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
  if (folderInfo.isSymbolicLink() || !folderInfo.isDirectory())
    throw new Error("Refusing non-directory or symlinked credential folder.");
  if (process.platform !== "win32" && (folderInfo.mode & 0o077) !== 0)
    throw new Error("Refusing credential folder with non-private permissions.");
  let fileInfo;
  try {
    fileInfo = lstatSync(file);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
  if (fileInfo.isSymbolicLink() || !fileInfo.isFile())
    throw new Error("Refusing non-regular or symlinked credential file.");
  if (process.platform !== "win32" && (fileInfo.mode & 0o077) !== 0)
    throw new Error("Refusing credential file with non-private permissions.");
  const value: unknown = JSON.parse(readFileSync(file, "utf8"));
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Session metadata is invalid.");
  return value as Credentials;
}
/** Only operation IDs are persisted; the secret value, title and reference are never stored here. */
export function pendingSecretWrites(): Record<string, string> {
  let folderInfo;
  try {
    folderInfo = lstatSync(folder);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return {};
    throw error;
  }
  if (folderInfo.isSymbolicLink() || !folderInfo.isDirectory())
    throw new Error("Refusing non-directory or symlinked credential folder.");
  if (process.platform !== "win32" && (folderInfo.mode & 0o077) !== 0)
    throw new Error("Refusing credential folder with non-private permissions.");
  let info;
  try {
    info = lstatSync(pendingWritesFile);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return {};
    throw error;
  }
  if (info.isSymbolicLink() || !info.isFile())
    throw new Error("Refusing non-regular or symlinked pending-write file.");
  if (process.platform !== "win32" && (info.mode & 0o077) !== 0)
    throw new Error(
      "Refusing pending-write file with non-private permissions.",
    );
  const value = JSON.parse(readFileSync(pendingWritesFile, "utf8"));
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.entries(value).some(
      ([key, operationId]) =>
        !/^[A-Za-z0-9_-]{43}$/.test(key) ||
        typeof operationId !== "string" ||
        !/^[A-Za-z0-9_-]{20,128}$/.test(operationId),
    )
  )
    throw new Error("Pending-write metadata is invalid.");
  return value as Record<string, string>;
}
export function storePendingSecretWrites(value: Record<string, string>) {
  if (existsSync(folder) && lstatSync(folder).isSymbolicLink())
    throw new Error("Refusing symlinked credential directory.");
  mkdirSync(folder, { recursive: true, mode: 0o700 });
  chmodSync(folder, 0o700);
  const temp = path.join(
    folder,
    "pending-write-" + crypto.randomUUID() + ".tmp",
  );
  writeFileSync(temp, JSON.stringify(value), { mode: 0o600, flag: "wx" });
  try {
    renameSync(temp, pendingWritesFile);
  } catch (error) {
    try {
      if (existsSync(temp)) unlinkSync(temp);
    } catch {}
    throw error;
  }
}
async function withPendingSecretWritesLock<T>(work: () => T): Promise<T> {
  if (existsSync(folder) && lstatSync(folder).isSymbolicLink())
    throw new Error("Refusing symlinked credential directory.");
  mkdirSync(folder, { recursive: true, mode: 0o700 });
  chmodSync(folder, 0o700);
  const started = Date.now();
  while (true) {
    try {
      mkdirSync(pendingWritesLock, { mode: 0o700 });
      const ownerTemp = path.join(
        pendingWritesLock,
        "owner-" + crypto.randomUUID() + ".tmp",
      );
      writeFileSync(
        ownerTemp,
        JSON.stringify({ pid: process.pid, createdAt: Date.now() }),
        { mode: 0o600, flag: "wx" },
      );
      renameSync(ownerTemp, path.join(pendingWritesLock, "owner"));
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      try {
        const owner = JSON.parse(
          readFileSync(path.join(pendingWritesLock, "owner"), "utf8"),
        ) as { pid?: number; createdAt?: number };
        if (
          Number.isSafeInteger(owner.pid) &&
          Number.isSafeInteger(owner.createdAt) &&
          Date.now() - owner.createdAt! > 30_000
        ) {
          try {
            process.kill(owner.pid!, 0);
          } catch (probeError) {
            if ((probeError as NodeJS.ErrnoException).code === "ESRCH")
              throw new Error(
                "Pending-write metadata lock is stale; remove " +
                  pendingWritesLock +
                  " after confirming no AgentSecret CLI is running.",
              );
          }
        }
      } catch (readError) {
        if (
          (readError as NodeJS.ErrnoException).code === "ENOENT" ||
          readError instanceof SyntaxError
        ) {
          try {
            if (Date.now() - lstatSync(pendingWritesLock).mtimeMs > 30_000)
              throw new Error(
                "Pending-write metadata lock is stale; remove " +
                  pendingWritesLock +
                  " after confirming no AgentSecret CLI is running.",
              );
          } catch (lockError) {
            if ((lockError as NodeJS.ErrnoException).code !== "ENOENT")
              throw lockError;
          }
        } else {
          throw readError;
        }
      }
      if (Date.now() - started > 10_000)
        throw new Error("Timed out waiting for pending-write metadata.");
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  }
  try {
    return work();
  } finally {
    rmSync(pendingWritesLock, { recursive: true, force: true });
  }
}
/** Serialize provider-keychain replacement with other CLI credential mutations. */
export function withProviderCredentialLock<T>(work: () => T): Promise<T> {
  return withPendingSecretWritesLock(work);
}
/** Claims a per-target retry ID without overwriting concurrent writes for other targets. */
export function beginPendingSecretWrite(
  key: string,
  candidate: string,
  replace: boolean,
): Promise<string> {
  if (!/^[A-Za-z0-9_-]{43}$/.test(key))
    throw new Error("Pending-write metadata is invalid.");
  if (!/^[A-Za-z0-9_-]{20,128}$/.test(candidate))
    throw new Error("Pending-write operation ID is invalid.");
  return withPendingSecretWritesLock(() => {
    const current = pendingSecretWrites();
    if (!replace && current[key]) return current[key]!;
    current[key] = candidate;
    storePendingSecretWrites(current);
    return candidate;
  });
}
/** Removes only the completed operation, preserving IDs recorded by other processes. */
export function completePendingSecretWrite(
  key: string,
  expectedOperationId: string,
): Promise<void> {
  return withPendingSecretWritesLock(() => {
    const current = pendingSecretWrites();
    if (current[key] === expectedOperationId) {
      delete current[key];
      storePendingSecretWrites(current);
    }
  });
}
function withSessionStateLock<T>(work: () => T): T {
  if (existsSync(folder) && lstatSync(folder).isSymbolicLink())
    throw new Error("Refusing symlinked credential directory.");
  mkdirSync(folder, { recursive: true, mode: 0o700 });
  chmodSync(folder, 0o700);
  try {
    mkdirSync(sessionStateLock, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      const info = lstatSync(sessionStateLock);
      if (info.isSymbolicLink() || !info.isDirectory())
        throw new Error("Refusing unsafe local session lock.");
      let owner: { pid?: number; createdAt?: number } | undefined;
      try {
        owner = JSON.parse(
          readFileSync(path.join(sessionStateLock, "owner"), "utf8"),
        );
      } catch (readError) {
        if (
          (readError as NodeJS.ErrnoException).code !== "ENOENT" &&
          !(readError instanceof SyntaxError)
        )
          throw readError;
      }
      if (
        owner &&
        Number.isSafeInteger(owner.pid) &&
        Number.isSafeInteger(owner.createdAt) &&
        Date.now() - owner.createdAt! > 30_000
      ) {
        try {
          process.kill(owner.pid!, 0);
        } catch (probeError) {
          if ((probeError as NodeJS.ErrnoException).code === "ESRCH")
            throw new Error(
              "Local session lock is stale; remove " +
                sessionStateLock +
                " after confirming no AgentSecret CLI is running.",
            );
        }
      } else if (!owner && Date.now() - info.mtimeMs > 30_000) {
        throw new Error(
          "Local session lock may be stale; remove " +
            sessionStateLock +
            " after confirming no AgentSecret CLI is running.",
        );
      }
      throw new Error(
        "Local session state is being updated by another AgentSecret process; retry.",
      );
    }
    throw error;
  }
  try {
    writeFileSync(
      path.join(sessionStateLock, "owner"),
      JSON.stringify({ pid: process.pid, createdAt: Date.now() }),
      { mode: 0o600, flag: "wx" },
    );
    return work();
  } finally {
    rmSync(sessionStateLock, { recursive: true, force: true });
  }
}
function removeSession(saved: Credentials) {
  try {
    deletePrivateKey(saved.server);
  } catch {
    throw new Error(
      "Unable to remove signing key from the operating-system store.",
    );
  }
  unlinkSync(file);
}
export function save(value: Credentials, key: JsonWebKey) {
  withSessionStateLock(() => {
    const existing = load();
    const previousKey = existing ? privateKey(existing.server) : null;
    const temp = path.join(folder, "session-" + crypto.randomUUID() + ".tmp");
    let staged = false;
    try {
      privateKey(value.server, key);
      writeFileSync(temp, JSON.stringify(value), { mode: 0o600, flag: "wx" });
      staged = true;
      renameSync(temp, file);
    } catch (error) {
      let cleanupFailed = false;
      if (staged) {
        try {
          if (existsSync(temp)) unlinkSync(temp);
        } catch {
          cleanupFailed = true;
        }
      }
      try {
        if (existing?.server === value.server && previousKey)
          privateKey(value.server, previousKey);
        else deletePrivateKey(value.server);
      } catch {
        throw new Error("Session save failed and signing-key rollback failed.");
      }
      if (cleanupFailed)
        throw new Error(
          "Session save failed and temporary-file cleanup failed.",
        );
      throw error;
    }
  });
}
export function clear() {
  withSessionStateLock(() => {
    const saved = load();
    if (saved) removeSession(saved);
  });
}
export function clearIfUnchanged(
  expected: Credentials,
): "cleared" | "replacement_preserved" | "absent" {
  return withSessionStateLock(() => {
    const current = load();
    if (!current) return "absent";
    if (JSON.stringify(current) !== JSON.stringify(expected))
      return "replacement_preserved";
    removeSession(current);
    return "cleared";
  });
}
