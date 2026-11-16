import type { AuthorityCursor } from "../state/storage";

/**
 * An array-backed AuthorityCursor. The authority's record helpers only ever
 * need the full result set, a single row, or iteration, so materialising the
 * rows once is both correct and simple for a local synchronous SQLite driver.
 */
export class SqliteAuthorityCursor<T> implements AuthorityCursor<T> {
  constructor(private readonly rows: readonly T[]) {}

  toArray(): T[] {
    return [...this.rows];
  }

  one(): T {
    const row = this.rows[0];
    if (row === undefined) throw new Error("sqlite_cursor_empty");
    return row;
  }

  *[Symbol.iterator](): Iterator<T> {
    yield* this.rows;
  }
}
