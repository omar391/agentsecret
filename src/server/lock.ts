import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { join } from "node:path";

function isSqliteBusy(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const sqliteError = error as Error & { errcode?: number };
  return (
    sqliteError.errcode === 5 ||
    sqliteError.errcode === 6 ||
    /database is (?:locked|busy)/i.test(error.message)
  );
}

/**
 * Hold a SQLite write transaction for the lifetime of the server. SQLite's
 * cross-process lock is the arbiter; a dead process releases it automatically,
 * so stale owner observations never remove a replacement lock.
 */
export function acquireServerLock(dataDir: string): () => void {
  mkdirSync(dataDir, { recursive: true });
  const db = new DatabaseSync(join(dataDir, "server.lock.sqlite"));
  const token = randomUUID();
  let transactionOpen = false;

  try {
    db.exec("PRAGMA busy_timeout = 0");
    db.exec("BEGIN IMMEDIATE");
    transactionOpen = true;
    db.exec(
      "CREATE TABLE IF NOT EXISTS server_lock (" +
        "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), " +
        "pid INTEGER NOT NULL, token TEXT NOT NULL) STRICT",
    );
    db.prepare(
      "INSERT INTO server_lock (singleton, pid, token) VALUES (1, ?, ?) " +
        "ON CONFLICT(singleton) DO UPDATE SET pid = excluded.pid, token = excluded.token",
    ).run(process.pid, token);
  } catch (error) {
    if (transactionOpen) {
      try {
        db.exec("ROLLBACK");
      } catch {
        // The connection may already have rolled the transaction back.
      }
    }
    try {
      db.close();
    } catch {
      // Best-effort cleanup after a failed acquisition.
    }
    if (isSqliteBusy(error))
      throw new Error(
        "agentsecret server is already running for this data directory",
      );
    throw error;
  }

  let released = false;
  return () => {
    if (released) return;
    released = true;
    try {
      db.prepare(
        "DELETE FROM server_lock WHERE singleton = 1 AND pid = ? AND token = ?",
      ).run(process.pid, token);
      db.exec("COMMIT");
    } catch {
      try {
        db.exec("ROLLBACK");
      } catch {
        // Best-effort release; closing the connection also drops its lock.
      }
    } finally {
      try {
        db.close();
      } catch {
        // Best-effort release.
      }
    }
  };
}
