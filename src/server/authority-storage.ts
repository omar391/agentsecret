import { DatabaseSync } from "node:sqlite";
import type { AuthorityCursor, AuthorityStorage } from "../state/storage";
import { SqliteAuthorityCursor } from "./sqlite-cursor";

/**
 * The AuthorityStorage port over a local synchronous SQLite database.
 *
 * One database file backs one tenant authority, mirroring the one-Durable-
 * Object-per-tenant model: the file is the durable record store, an
 * `authority_alarm` row is the durable scheduler, and `transactionSync` is
 * a real SQLite transaction. Scheduled recovery therefore survives a process
 * restart exactly as it does across Durable Object hibernation.
 */
export class SqliteAuthorityStorage implements AuthorityStorage {
  private transactionDepth = 0;

  constructor(
    private readonly db: DatabaseSync,
    private readonly onAlarmChanged?: () => void,
  ) {
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS authority_alarm (id INTEGER PRIMARY KEY CHECK (id = 1), alarm_at INTEGER NOT NULL)",
    );
  }

  exec<T>(query: string, ...params: unknown[]): AuthorityCursor<T> {
    const statement = this.db.prepare(query);
    const rows = statement.all(...(params as never[])) as T[];
    return new SqliteAuthorityCursor<T>(rows);
  }

  transactionSync<T>(work: () => T): T {
    if (this.transactionDepth > 0)
      throw new Error("sqlite_authority_nested_transaction");
    this.transactionDepth += 1;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = work();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        // The original failure is the one that matters; a rollback error is
        // surfaced only when there was no original failure.
      }
      throw error;
    } finally {
      this.transactionDepth -= 1;
    }
  }

  async setAlarm(when: number): Promise<void> {
    this.db
      .prepare(
        "INSERT OR REPLACE INTO authority_alarm (id, alarm_at) VALUES (1, ?)",
      )
      .run(when);
    this.onAlarmChanged?.();
  }

  async deleteAlarm(): Promise<void> {
    this.db.prepare("DELETE FROM authority_alarm WHERE id = 1").run();
    this.onAlarmChanged?.();
  }

  async getAlarm(): Promise<number | null> {
    const row = this.db
      .prepare("SELECT alarm_at FROM authority_alarm WHERE id = 1")
      .get() as { alarm_at: number } | undefined;
    return row ? row.alarm_at : null;
  }

  /** The persisted alarm instant for host-side scheduling, or null. */
  alarmAt(): number | null {
    const row = this.db
      .prepare("SELECT alarm_at FROM authority_alarm WHERE id = 1")
      .get() as { alarm_at: number } | undefined;
    return row ? row.alarm_at : null;
  }

  close(): void {
    this.db.close();
  }
}
