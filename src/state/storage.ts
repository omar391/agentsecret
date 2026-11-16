/**
 * The storage port the account authority's business logic depends on.
 *
 * SecurityAuthority used to reach Durable Object storage directly through its
 * execution context, which made every business decision in that class depend on
 * the Cloudflare runtime. This interface is the whole of what those decisions
 * actually need: a synchronous key/value store with expiry, a synchronous
 * transaction scope, and a durable scheduler. A Cloudflare Durable Object
 * provides it from its storage; a Node host provides it from local SQLite. The
 * business rules live above this seam and are identical either way.
 */
/** A synchronous result cursor: rows, a single row, or iteration. */
export interface AuthorityCursor<T> extends Iterable<T> {
  toArray(): T[];
  one(): T;
}

export interface AuthorityStorage {
  /** Synchronous query execution, used by the record read/write helpers. */
  exec<T>(query: string, ...params: unknown[]): AuthorityCursor<T>;
  /** Run one synchronous transaction over this store. */
  transactionSync<T>(work: () => T): T;
  /** Durable scheduled recovery work. */
  setAlarm(when: number): Promise<void>;
  /** Remove the current alarm after successful work with no replacement. */
  deleteAlarm(): Promise<void>;
  /** The scheduled alarm instant, or null when none is scheduled. */
  getAlarm(): Promise<number | null>;
}
