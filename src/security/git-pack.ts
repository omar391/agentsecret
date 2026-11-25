/** Bounded, in-memory inspection of Git pack objects before binary delivery.
 * This gate never rewrites a pack, returns object contents, or writes to disk.
 * Format: https://git-scm.com/docs/gitformat-pack
 */
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { inflateSync } from "node:zlib";
import { scrubSecretsFromPayload } from "./sanitizer";

const MAX_PACK = 512 * 1024;
const MAX_OBJECT = 8 * 1024 * 1024;
const MAX_DECODED = 16 * 1024 * 1024;
const MAX_OBJECTS = 1024;
const MAX_DEPTH = 32;
type ObjectKind = "commit" | "tree" | "blob" | "tag";
type Resolved = { kind: ObjectKind; data: Buffer; depth: number };
type Entry = {
  offset: number;
  data: Buffer;
  kind?: ObjectKind;
  base?: number | string;
  resolved?: Resolved;
};
const KINDS: Record<number, ObjectKind | undefined> = {
  1: "commit",
  2: "tree",
  3: "blob",
  4: "tag",
};

export class GitPackError extends Error {
  constructor(
    readonly code:
      | "git_pack_invalid"
      | "git_pack_limit_exceeded"
      | "git_pack_missing_base"
      | "git_pack_credential_reflection",
  ) {
    super(code);
    this.name = "GitPackError";
  }
}
function invalid(): never {
  throw new GitPackError("git_pack_invalid");
}
function limit(): never {
  throw new GitPackError("git_pack_limit_exceeded");
}

/** Known-credential inspection only; never returns or rewrites payload data. */
export function assertNoGitCredentialReflection(
  data: Uint8Array,
  secrets: readonly string[],
): void {
  if (
    !Array.isArray(secrets) ||
    !secrets.length ||
    secrets.length > 8 ||
    secrets.some(
      (secret) => typeof secret !== "string" || !secret || secret.length > 8192,
    )
  )
    invalid();
  const text = Buffer.from(data).toString("utf8");
  let value: unknown = text;
  try {
    value = JSON.parse(text);
  } catch {
    /* not JSON */
  }
  const result = scrubSecretsFromPayload(
    value,
    [...secrets],
    false,
    typeof value === "string" && value === text ? undefined : text,
  );
  if (result.redactionsCount)
    throw new GitPackError("git_pack_credential_reflection");
}

function applyDelta(
  base: Buffer,
  instructions: Buffer,
  budget: number,
): Buffer {
  let at = 0;
  const byte = () => {
    if (at >= instructions.length) invalid();
    return instructions[at++];
  };
  const size = () => {
    let result = 0,
      shift = 0,
      next;
    do {
      next = byte();
      result += (next & 127) * 2 ** shift;
      shift += 7;
      if (!Number.isSafeInteger(result) || result > MAX_OBJECT || shift > 49)
        limit();
    } while (next & 128);
    return result;
  };
  if (size() !== base.length) invalid();
  const outputSize = size();
  if (outputSize > budget) limit();
  const output = Buffer.alloc(outputSize);
  let written = 0;
  while (at < instructions.length) {
    const op = byte();
    if (op & 128) {
      let offset = 0,
        length = 0;
      for (let n = 0; n < 4; n++)
        if (op & (1 << n)) offset += byte() * 2 ** (8 * n);
      for (let n = 0; n < 3; n++)
        if (op & (1 << (n + 4))) length += byte() * 2 ** (8 * n);
      if (!length) length = 65536;
      if (offset + length > base.length || written + length > output.length)
        invalid();
      output.set(base.subarray(offset, offset + length), written);
      written += length;
    } else {
      if (!op || at + op > instructions.length || written + op > output.length)
        invalid();
      output.set(instructions.subarray(at, at + op), written);
      at += op;
      written += op;
    }
  }
  if (written !== output.length) invalid();
  return output;
}

/** Inspect complete SHA-1 or SHA-256 packs without altering any original bytes.
 * Missing thin-pack bases are refused, never treated as inspected. The caller
 * must supply the known credential/redaction targets inside its trusted boundary.
 * This is a known-credential reflection gate, not arbitrary information-flow proof.
 */
export function inspectGitPack(
  input: Uint8Array,
  secrets: readonly string[],
  algorithm: "sha1" | "sha256" = "sha1",
): { objectCount: number; deltaObjects: number; decodedBytes: number } {
  try {
    if (algorithm !== "sha1" && algorithm !== "sha256") invalid();
    if (
      !Array.isArray(secrets) ||
      !secrets.length ||
      secrets.length > 8 ||
      secrets.some(
        (secret) =>
          typeof secret !== "string" || !secret || secret.length > 8192,
      )
    )
      invalid();
    if (input.byteLength > MAX_PACK) limit();
    const pack = Buffer.from(input);
    const hashLength = algorithm === "sha1" ? 20 : 32;
    const end = pack.length - hashLength;
    if (
      end < 12 ||
      pack.subarray(0, 4).toString("ascii") !== "PACK" ||
      ![2, 3].includes(pack.readUInt32BE(4))
    )
      invalid();
    if (
      !createHash(algorithm)
        .update(pack.subarray(0, end))
        .digest()
        .equals(pack.subarray(end))
    )
      invalid();
    const count = pack.readUInt32BE(8);
    if (count > MAX_OBJECTS) limit();
    let decodedBytes = 0;
    const charge = (size: number) => {
      decodedBytes += size;
      if (decodedBytes > MAX_DECODED) limit();
    };
    const scan = (data: Buffer) =>
      assertNoGitCredentialReflection(data, secrets);
    scan(pack);
    let at = 12;
    const byte = () => {
      if (at >= end) invalid();
      return pack[at++];
    };
    const entries: Entry[] = [];
    const offsets = new Map<number, Entry>();
    for (let n = 0; n < count; n++) {
      const offset = at;
      let head = byte();
      const type = (head >> 4) & 7;
      let length = head & 15,
        shift = 4;
      while (head & 128) {
        head = byte();
        length += (head & 127) * 2 ** shift;
        shift += 7;
        if (!Number.isSafeInteger(length) || length > MAX_OBJECT || shift > 49)
          limit();
      }
      if (length > MAX_OBJECT) limit();
      let base: number | string | undefined;
      if (type === 6) {
        let b = byte(),
          distance = b & 127;
        while (b & 128) {
          b = byte();
          distance = (distance + 1) * 128 + (b & 127);
          if (!Number.isSafeInteger(distance) || distance > offset) invalid();
        }
        if (!distance || distance > offset) invalid();
        base = offset - distance;
      } else if (type === 7) {
        if (at + hashLength > end) invalid();
        base = pack.subarray(at, at + hashLength).toString("hex");
        at += hashLength;
      } else if (!KINDS[type]) invalid();
      if (length > MAX_DECODED - decodedBytes) limit();
      const expanded = inflateSync(pack.subarray(at, end), {
        info: true,
        maxOutputLength: Math.max(1, length),
      }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
      const used = expanded.engine.bytesWritten;
      if (
        !Number.isSafeInteger(used) ||
        used <= 0 ||
        at + used > end ||
        expanded.buffer.length !== length
      )
        invalid();
      at += used;
      charge(length);
      scan(expanded.buffer);
      const entry: Entry = {
        offset,
        data: expanded.buffer,
        kind: KINDS[type],
        base,
      };
      entries.push(entry);
      offsets.set(offset, entry);
    }
    if (at !== end) invalid();
    const ids = new Map<string, Resolved>();
    const register = (entry: Entry, object: Resolved) => {
      scan(object.data);
      entry.resolved = object;
      const id = createHash(algorithm)
        .update(`${object.kind} ${object.data.length}\0`)
        .update(object.data)
        .digest("hex");
      ids.set(id, object);
    };
    for (const entry of entries)
      if (entry.kind)
        register(entry, { kind: entry.kind, data: entry.data, depth: 0 });
    for (let pass = 0; pass < MAX_DEPTH; pass++) {
      let progress = false;
      for (const entry of entries) {
        if (entry.resolved) continue;
        const base =
          typeof entry.base === "number"
            ? offsets.get(entry.base)?.resolved
            : typeof entry.base === "string"
              ? ids.get(entry.base)
              : undefined;
        if (!base) continue;
        if (base.depth >= MAX_DEPTH) limit();
        const data = applyDelta(
          base.data,
          entry.data,
          MAX_DECODED - decodedBytes,
        );
        charge(data.length);
        register(entry, { kind: base.kind, data, depth: base.depth + 1 });
        progress = true;
      }
      if (entries.every((entry) => entry.resolved))
        return {
          objectCount: count,
          deltaObjects: entries.filter((entry) => entry.base !== undefined)
            .length,
          decodedBytes,
        };
      if (!progress) break;
    }
    throw new GitPackError("git_pack_missing_base");
  } catch (error) {
    if (error instanceof GitPackError) throw error;
    throw new GitPackError("git_pack_invalid");
  }
}
