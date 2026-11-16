import { createHash } from "node:crypto";
import { browserGrantTenant } from "../../src/security/browser-grant";
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  openSync,
  closeSync,
  mkdirSync as makeDirectorySync,
  readFileSync,
  rmSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

export interface SafeBrowserActionReceipt {
  status: "completed";
  grantId: string;
  action:
    | "filled"
    | "filled_totp"
    | "captured"
    | "unchanged"
    | "updated"
    | "verified";
  origin: string;
  fieldSelector: string;
  reference?: string;
  verified?: boolean;
}

interface StoredReceipt {
  requestSha256: string;
  state: "started" | "completed" | "rejected" | "unknown";
  updatedAt: number;
  receipt?: SafeBrowserActionReceipt;
}

interface ReceiptFile {
  schema: "agentsecret/browser-action-receipts/v1";
  records: Record<string, StoredReceipt>;
}

export function browserActionRequestDigest(request: unknown): string {
  return createHash("sha256").update(JSON.stringify(request)).digest("hex");
}

function ensurePrivateDirectory(directory: string): void {
  try {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
  } catch {
    throw new Error("browser_receipt_store_unavailable");
  }
  let info;
  try {
    info = lstatSync(directory);
  } catch {
    throw new Error("browser_receipt_store_unavailable");
  }
  if (
    info.isSymbolicLink() ||
    !info.isDirectory() ||
    (typeof process.getuid === "function" && info.uid !== process.getuid())
  )
    throw new Error("browser_receipt_store_unsafe");
  try {
    chmodSync(directory, 0o700);
  } catch {
    throw new Error("browser_receipt_store_unavailable");
  }
}

function exactReceipt(value: unknown): value is SafeBrowserActionReceipt {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort().join(",");
  return (
    (keys === "action,fieldSelector,grantId,origin,status" ||
      keys === "action,fieldSelector,grantId,origin,reference,status" ||
      keys === "action,fieldSelector,grantId,origin,status,verified" ||
      keys ===
        "action,fieldSelector,grantId,origin,reference,status,verified") &&
    record.status === "completed" &&
    typeof record.grantId === "string" &&
    typeof record.action === "string" &&
    [
      "filled",
      "filled_totp",
      "captured",
      "unchanged",
      "updated",
      "verified",
    ].includes(record.action) &&
    typeof record.origin === "string" &&
    typeof record.fieldSelector === "string" &&
    (record.reference === undefined || typeof record.reference === "string") &&
    (record.verified === undefined || typeof record.verified === "boolean")
  );
}

function loadFile(path: string): ReceiptFile {
  let text: string;
  try {
    const info = lstatSync(path);
    if (
      info.isSymbolicLink() ||
      !info.isFile() ||
      (process.platform !== "win32" && (info.mode & 0o077) !== 0)
    )
      throw new Error("browser_receipt_store_unsafe");
    text = readFileSync(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT")
      return { schema: "agentsecret/browser-action-receipts/v1", records: {} };
    if (error instanceof Error && error.message.startsWith("browser_receipt_"))
      throw error;
    throw new Error("browser_receipt_store_unavailable");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("browser_receipt_store_corrupt");
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    Object.keys(parsed).sort().join(",") !== "records,schema" ||
    (parsed as Record<string, unknown>).schema !==
      "agentsecret/browser-action-receipts/v1" ||
    !(parsed as Record<string, unknown>).records ||
    typeof (parsed as Record<string, unknown>).records !== "object" ||
    Array.isArray((parsed as Record<string, unknown>).records)
  )
    throw new Error("browser_receipt_store_corrupt");
  const records = (parsed as ReceiptFile).records;
  for (const [grantId, entry] of Object.entries(records)) {
    try {
      browserGrantTenant(grantId);
    } catch {
      throw new Error("browser_receipt_store_corrupt");
    }
    if (
      !entry ||
      typeof entry !== "object" ||
      !/^[a-f0-9]{64}$/u.test(entry.requestSha256) ||
      !["started", "completed", "rejected", "unknown"].includes(entry.state) ||
      !Number.isSafeInteger(entry.updatedAt) ||
      (entry.state === "completed" && !exactReceipt(entry.receipt)) ||
      (entry.state !== "completed" && entry.receipt !== undefined)
    )
      throw new Error("browser_receipt_store_corrupt");
  }
  return parsed as ReceiptFile;
}

export class BrowserActionReceiptStore {
  private readonly file: string;
  private readonly lock: string;

  constructor(private readonly directory: string) {
    ensurePrivateDirectory(directory);
    this.file = join(directory, "browser-action-receipts.json");
    this.lock = join(directory, "browser-action-receipts.lock");
  }

  private withLock<T>(operation: () => T): T {
    const deadline = Date.now() + 30_000;
    while (true) {
      try {
        makeDirectorySync(this.lock, { mode: 0o700 });
        try {
          const ownerPath = join(this.lock, "owner");
          const fd = openSync(ownerPath, "wx", 0o600);
          try {
            writeFileSync(fd, String(process.pid));
          } finally {
            closeSync(fd);
          }
        } catch (error) {
          rmSync(this.lock, { recursive: true, force: true });
          throw error;
        }
        break;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST")
          throw new Error("browser_receipt_store_unavailable");
        // A stale lock is intentionally left in place. Removing a path after
        // observing its owner could delete a replacement lock acquired by a
        // competing recovery process.
        try {
          const owner = Number(readFileSync(join(this.lock, "owner"), "utf8"));
          if (Number.isSafeInteger(owner) && owner > 0) {
            try {
              process.kill(owner, 0);
            } catch (probeError) {
              if ((probeError as NodeJS.ErrnoException).code === "ESRCH")
                throw new Error("browser_receipt_store_busy");
            }
          }
        } catch (error) {
          if (
            error instanceof Error &&
            error.message === "browser_receipt_store_busy"
          )
            throw error;
          // A creator may still be writing the owner record; wait below.
        }
        if (Date.now() >= deadline)
          throw new Error("browser_receipt_store_busy");
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
      }
    }
    try {
      return operation();
    } finally {
      rmSync(this.lock, { recursive: true, force: true });
    }
  }

  private save(value: ReceiptFile): void {
    const temp = join(
      this.directory,
      `browser-action-receipts-${crypto.randomUUID()}.tmp`,
    );
    try {
      writeFileSync(temp, JSON.stringify(value), { mode: 0o600, flag: "wx" });
      renameSync(temp, this.file);
    } catch {
      try {
        unlinkSync(temp);
      } catch {}
      throw new Error("browser_receipt_store_unavailable");
    }
  }

  begin(
    grantId: string,
    requestSha256: string,
  ): SafeBrowserActionReceipt | null {
    return this.withLock(() => this.beginLocked(grantId, requestSha256));
  }

  private beginLocked(
    grantId: string,
    requestSha256: string,
  ): SafeBrowserActionReceipt | null {
    const file = loadFile(this.file);
    const existing = file.records[grantId];
    if (existing) {
      if (existing.requestSha256 !== requestSha256)
        throw new Error("browser_grant_replayed");
      if (existing.state === "completed" && exactReceipt(existing.receipt))
        return existing.receipt;
      if (existing.state === "started" || existing.state === "unknown")
        throw new Error("browser_action_outcome_unknown");
      throw new Error("browser_grant_replayed");
    }
    if (Object.keys(file.records).length >= 1000)
      throw new Error("browser_receipt_store_full");
    file.records[grantId] = {
      requestSha256,
      state: "started",
      updatedAt: Date.now(),
    };
    this.save(file);
    return null;
  }

  finish(
    grantId: string,
    requestSha256: string,
    receipt: SafeBrowserActionReceipt,
  ): void {
    this.withLock(() => this.finishLocked(grantId, requestSha256, receipt));
  }

  private finishLocked(
    grantId: string,
    requestSha256: string,
    receipt: SafeBrowserActionReceipt,
  ): void {
    if (!exactReceipt(receipt) || receipt.grantId !== grantId)
      throw new Error("browser_receipt_invalid");
    const file = loadFile(this.file);
    const current = file.records[grantId];
    if (
      !current ||
      current.requestSha256 !== requestSha256 ||
      current.state !== "started"
    )
      throw new Error("browser_action_outcome_unknown");
    file.records[grantId] = {
      requestSha256,
      state: "completed",
      updatedAt: Date.now(),
      receipt,
    };
    this.save(file);
  }

  reject(grantId: string, requestSha256: string): void {
    this.withLock(() =>
      this.transitionLocked(grantId, requestSha256, "rejected"),
    );
  }

  markUnknown(grantId: string, requestSha256: string): void {
    this.withLock(() =>
      this.transitionLocked(grantId, requestSha256, "unknown"),
    );
  }

  private transitionLocked(
    grantId: string,
    requestSha256: string,
    state: "rejected" | "unknown",
  ): void {
    const file = loadFile(this.file);
    const current = file.records[grantId];
    if (
      !current ||
      current.requestSha256 !== requestSha256 ||
      current.state !== "started"
    )
      return;
    file.records[grantId] = {
      requestSha256,
      state,
      updatedAt: Date.now(),
    };
    this.save(file);
  }
}
