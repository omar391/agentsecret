import { execFileSync } from "node:child_process";
import { executorSigningPair, type ExecutorIdentityRecord } from "./executor";

export interface ExecutorBackend {
  read(): string | undefined;
  write(value: string): void;
  delete(): void;
}

export class ExecutorStoreError extends Error {
  constructor(
    readonly code:
      | "executor_store_corrupt"
      | "executor_store_invalid"
      | "executor_store_unavailable",
  ) {
    super(code);
  }
}

function decode(value: string): ExecutorIdentityRecord {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
  } catch {
    throw new ExecutorStoreError("executor_store_corrupt");
  }
  const record = parsed as Partial<ExecutorIdentityRecord>;
  if (
    !record ||
    record.version !== 1 ||
    typeof record.executorId !== "string" ||
    !record.privateJwk ||
    !record.publicJwk
  )
    throw new ExecutorStoreError("executor_store_corrupt");
  return record as ExecutorIdentityRecord;
}

/** Executor identities live under their own key and never share agent state. */
export class ExecutorStore {
  constructor(private readonly backend: ExecutorBackend) {}

  async load(): Promise<ExecutorIdentityRecord | undefined> {
    let raw: string | undefined;
    try {
      raw = this.backend.read();
    } catch {
      throw new ExecutorStoreError("executor_store_unavailable");
    }
    if (raw === undefined) return undefined;
    const record = decode(raw);
    try {
      await executorSigningPair(record);
    } catch {
      throw new ExecutorStoreError("executor_store_corrupt");
    }
    return record;
  }

  async save(record: ExecutorIdentityRecord): Promise<void> {
    try {
      await executorSigningPair(record);
    } catch {
      throw new ExecutorStoreError("executor_store_invalid");
    }
    try {
      this.backend.write(
        Buffer.from(JSON.stringify(record), "utf8").toString("base64url"),
      );
    } catch {
      throw new ExecutorStoreError("executor_store_unavailable");
    }
  }

  remove(): void {
    try {
      this.backend.delete();
    } catch {
      throw new ExecutorStoreError("executor_store_unavailable");
    }
  }
}

/** macOS first-release backend; the executor key never falls back to a file. */
export function macOsExecutorBackend(): ExecutorBackend {
  if (process.platform !== "darwin")
    throw new ExecutorStoreError("executor_store_unavailable");
  const service = "AgentSecret-executor-v1";
  const account = "primary";
  return {
    read() {
      try {
        return execFileSync(
          "/usr/bin/security",
          ["find-generic-password", "-a", account, "-s", service, "-w"],
          { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
        ).trim();
      } catch (error) {
        if (
          error &&
          typeof error === "object" &&
          "status" in error &&
          error.status === 44
        )
          return undefined;
        throw new ExecutorStoreError("executor_store_unavailable");
      }
    },
    write(value) {
      try {
        execFileSync("/usr/bin/security", ["-i"], {
          input: `add-generic-password -U -a "${account}" -s "${service}" -w "${value}"\n`,
          stdio: ["pipe", "ignore", "pipe"],
        });
      } catch {
        throw new ExecutorStoreError("executor_store_unavailable");
      }
    },
    delete() {
      try {
        execFileSync(
          "/usr/bin/security",
          ["delete-generic-password", "-a", account, "-s", service],
          { stdio: "ignore" },
        );
      } catch (error) {
        if (
          error &&
          typeof error === "object" &&
          "status" in error &&
          error.status === 44
        )
          return;
        throw new ExecutorStoreError("executor_store_unavailable");
      }
    },
  };
}
