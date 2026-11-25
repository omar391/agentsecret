/** In-memory gate for complete Git smart-HTTP response bodies. */
import { Buffer } from "node:buffer";
import {
  assertNoGitCredentialReflection,
  GitPackError,
  inspectGitPack,
} from "./git-pack";

const MAX_BODY = 512 * 1024,
  MAX_FRAMES = 4096,
  MAX_PACKET = 65520;
const PHASES: Record<
  string,
  "advertisement" | "upload" | "receive" | undefined
> = {
  "application/x-git-upload-pack-advertisement": "advertisement",
  "application/x-git-receive-pack-advertisement": "advertisement",
  "application/x-git-upload-pack-result": "upload",
  "application/x-git-receive-pack-result": "receive",
};
export class GitHttpError extends Error {
  constructor(
    readonly code:
      "git_http_invalid" | "git_http_limit_exceeded" | "git_http_unsupported",
  ) {
    super(code);
    this.name = "GitHttpError";
  }
}
function invalid(): never {
  throw new GitHttpError("git_http_invalid");
}

/**
 * Deframe pkt-lines and sidebands for inspection, leaving original bytes intact.
 * Supports v0 raw/sideband packs and v2 packfile/sideband-all sections. Thin
 * packs and external packfile URIs fail closed. Input must be identity-encoded.
 * This is bounded known-value inspection, not arbitrary information-flow proof.
 */
export function inspectGitHttpResponse(
  input: Uint8Array,
  contentType: string,
  secrets: readonly string[],
  objectFormat: "sha1" | "sha256" = "sha1",
): {
  packetCount: number;
  packBytes: number;
  objectCount: number;
  deltaObjects: number;
} {
  try {
    if (input.byteLength > MAX_BODY)
      throw new GitHttpError("git_http_limit_exceeded");
    if (objectFormat !== "sha1" && objectFormat !== "sha256") invalid();
    const phase = PHASES[contentType.split(";", 1)[0].trim().toLowerCase()];
    if (!phase) throw new GitHttpError("git_http_unsupported");
    const body = Buffer.from(input);
    if (body.length < 4) invalid();
    assertNoGitCredentialReflection(body, secrets);
    const texts: Buffer[][] = [[], [], [], []],
      allText: Buffer[] = [],
      pack: Buffer[] = [];
    let at = 0,
      count = 0,
      packStarted = false,
      packExpected = false,
      rawPack = false;
    const text = (data: Buffer, channel = 0) => {
      // A UTF-8 character may cross sideband records. Decode joined channels,
      // not individual fragments; no inspection decoding changes wire bytes.
      texts[channel].push(data);
      allText.push(data);
    };
    const payload = (data: Buffer, sideband: boolean) => {
      if (packStarted) {
        if (!sideband || rawPack) invalid();
        pack.push(data);
        return;
      }
      if (data.equals(Buffer.from("packfile-uris\n")))
        throw new GitHttpError("git_http_unsupported");
      if (data.equals(Buffer.from("packfile\n"))) {
        if (phase !== "upload" || packExpected) invalid();
        packExpected = true;
        text(data, sideband ? 1 : 0);
        return;
      }
      const prefix = data.subarray(0, Math.min(4, data.length));
      const startsPack =
        prefix.length > 0 &&
        Buffer.from("PACK").subarray(0, prefix.length).equals(prefix);
      if (sideband && (packExpected || startsPack)) {
        if (phase !== "upload") invalid();
        if (!data.length) return;
        packStarted = true;
        pack.push(data);
        return;
      }
      text(data, sideband ? 1 : 0);
    };
    while (at < body.length) {
      if (body.subarray(at, at + 4).equals(Buffer.from("PACK"))) {
        if (phase !== "upload" || packStarted) invalid();
        rawPack = true;
        packStarted = true;
        pack.push(body.subarray(at));
        at = body.length;
        break;
      }
      if (++count > MAX_FRAMES)
        throw new GitHttpError("git_http_limit_exceeded");
      if (at + 4 > body.length) invalid();
      const header = body.subarray(at, at + 4).toString("ascii");
      if (!/^[0-9a-fA-F]{4}$/.test(header)) invalid();
      const length = Number.parseInt(header, 16);
      at += 4;
      if (length === 0 || length === 1) continue;
      if (length === 2) {
        if (at !== body.length) invalid();
        break;
      }
      if (length < 4 || length > MAX_PACKET || at + length - 4 > body.length)
        invalid();
      const data = body.subarray(at, at + length - 4);
      at += length - 4;
      const channel = data[0];
      if (channel >= 1 && channel <= 3) {
        if (phase === "advertisement") invalid();
        if (channel === 1) payload(data.subarray(1), true);
        else text(data.subarray(1), channel);
      } else payload(data, false);
    }
    if (packExpected && !packStarted) invalid();
    for (let channel = 0; channel < texts.length; channel++) {
      const joined = Buffer.concat(texts[channel]);
      try {
        new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(
          joined,
        );
      } catch {
        invalid();
      }
      assertNoGitCredentialReflection(joined, secrets);
      // receive-pack sideband 1 can contain a second layer of status pkt-lines.
      if (
        phase === "receive" &&
        channel === 1 &&
        /^[0-9a-fA-F]{4}$/.test(joined.subarray(0, 4).toString("ascii"))
      ) {
        const status: Buffer[] = [];
        let offset = 0;
        while (offset < joined.length) {
          if (++count > MAX_FRAMES)
            throw new GitHttpError("git_http_limit_exceeded");
          if (offset + 4 > joined.length) invalid();
          const header = joined.subarray(offset, offset + 4).toString("ascii");
          if (!/^[0-9a-fA-F]{4}$/.test(header)) invalid();
          const size = Number.parseInt(header, 16);
          offset += 4;
          if (size === 0 || size === 1) continue;
          if (size === 2) {
            if (offset !== joined.length) invalid();
            break;
          }
          if (
            size < 4 ||
            size > MAX_PACKET ||
            offset + size - 4 > joined.length
          )
            invalid();
          const part = joined.subarray(offset, offset + size - 4);
          if (part.subarray(0, 4).equals(Buffer.from("PACK"))) invalid();
          status.push(part);
          offset += size - 4;
        }
        const flattened = Buffer.concat(status);
        try {
          new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(
            flattened,
          );
        } catch {
          invalid();
        }
        assertNoGitCredentialReflection(flattened, secrets);
      }
    }
    assertNoGitCredentialReflection(Buffer.concat(allText), secrets);
    const bytes = Buffer.concat(pack);
    const result = bytes.length
      ? inspectGitPack(bytes, secrets, objectFormat)
      : { objectCount: 0, deltaObjects: 0 };
    return {
      packetCount: count,
      packBytes: bytes.length,
      objectCount: result.objectCount,
      deltaObjects: result.deltaObjects,
    };
  } catch (error) {
    if (error instanceof GitHttpError || error instanceof GitPackError)
      throw error;
    invalid();
  }
}
