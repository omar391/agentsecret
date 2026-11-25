import { execFileSync } from "node:child_process";
import type { Stats } from "node:fs";
import { lstatSync, readdirSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, relative, resolve } from "node:path";
import {
  AccountBoundProviderCredentials,
  type ProviderCredentialBinding,
} from "../provider-credentials";

const PROFILE_SCHEMA = "agentsecret/lastpass-profile/v1" as const;
const ITEM_ID = /^[1-9][0-9]{0,19}$/;
const EMAIL = /^[^\s@]{1,128}@[a-z0-9.-]{1,253}$/i;
const MAX_ITEM_JSON = 1024 * 1024;

interface LastPassProfile {
  schema: typeof PROFILE_SCHEMA;
  home: string;
  userEmail: string;
}

export interface LastPassRunner {
  status(profileHome: string): Promise<string>;
  showItem(profileHome: string, itemId: string): Promise<string>;
  listItems(profileHome: string): Promise<string>;
  createItem(profileHome: string, name: string, value: string): Promise<string>;
  updateField(
    profileHome: string,
    itemId: string,
    field: "password" | "username" | "note",
    value: string,
  ): Promise<void>;
}

export interface LastPassSafeReceipt {
  status: "created" | "updated" | "unchanged";
  reference: string;
  verified: true;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function validEmail(value: string): boolean {
  return EMAIL.test(value) && !/[\u0000-\u001f\u007f]/.test(value);
}

function validateProfileHome(value: string): string {
  if (typeof value !== "string" || !isAbsolute(value) || value.length > 2048)
    throw new Error("lastpass_profile_invalid");
  let actual: string;
  let info: Stats;
  try {
    actual = realpathSync(value);
    info = lstatSync(actual);
  } catch {
    throw new Error("lastpass_profile_invalid");
  }
  const expectedRoot = resolve(homedir(), ".local/share/agentsecret/lastpass");
  const rel = relative(expectedRoot, actual);
  if (
    actual !== value ||
    !info.isDirectory() ||
    (info.mode & 0o077) !== 0 ||
    (typeof process.getuid === "function" && info.uid !== process.getuid()) ||
    !rel ||
    rel === ".." ||
    rel.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) ||
    isAbsolute(rel)
  )
    throw new Error("lastpass_profile_invalid");
  return actual;
}

function assertSafeProfileConfiguration(profileHome: string): void {
  let entries: string[];
  try {
    entries = readdirSync(profileHome);
  } catch {
    throw new Error("lastpass_profile_invalid");
  }
  if (entries.some((entry) => entry === "env" || entry.startsWith("alias.")))
    throw new Error("lastpass_profile_unsafe_configuration");
}

export function serializeLastPassProfile(
  profileHome: string,
  userEmail: string,
): string {
  if (!validEmail(userEmail)) throw new Error("lastpass_profile_invalid");
  return JSON.stringify({
    schema: PROFILE_SCHEMA,
    home: validateProfileHome(profileHome),
    userEmail: userEmail.toLowerCase(),
  } satisfies LastPassProfile);
}

function parseProfile(value: string): LastPassProfile {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("lastpass_profile_unconfigured");
  }
  if (
    !isRecord(parsed) ||
    Object.keys(parsed).sort().join(",") !== "home,schema,userEmail" ||
    parsed.schema !== PROFILE_SCHEMA ||
    typeof parsed.home !== "string" ||
    typeof parsed.userEmail !== "string" ||
    !validEmail(parsed.userEmail)
  )
    throw new Error("lastpass_profile_unconfigured");
  const home = validateProfileHome(parsed.home);
  if (home !== parsed.home) throw new Error("lastpass_profile_unconfigured");
  return parsed as unknown as LastPassProfile;
}

function parseReference(reference: string): {
  itemId: string;
  field: "password" | "username" | "note";
} {
  if (
    typeof reference !== "string" ||
    reference.length > 128 ||
    /[\u0000-\u001f\u007f]/.test(reference)
  )
    throw new Error("lastpass_reference_invalid");
  const match = /^(\d{1,20})#\/(password|username|note)$/.exec(reference);
  if (!match || !ITEM_ID.test(match[1]!))
    throw new Error("lastpass_reference_invalid");
  return {
    itemId: match[1]!,
    field: match[2] as "password" | "username" | "note",
  };
}

function parseItem(json: string, expectedId: string): Record<string, unknown> {
  if (
    typeof json !== "string" ||
    Buffer.byteLength(json, "utf8") > MAX_ITEM_JSON
  )
    throw new Error("lastpass_item_invalid");
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error("lastpass_item_invalid");
  }
  if (!Array.isArray(parsed) || parsed.length !== 1 || !isRecord(parsed[0]))
    throw new Error("lastpass_item_invalid");
  if (String(parsed[0].id) !== expectedId)
    throw new Error("lastpass_item_mismatch");
  return parsed[0];
}

function parseCreatedItemId(output: string): string {
  if (typeof output !== "string" || output.length > 4096 || output.trim())
    throw new Error("lastpass_create_outcome_unknown");
  return "";
}

interface ListedLastPassItem {
  id: string;
}

function parseCreatedItemFromListing(
  listing: string,
  expectedName: string,
  excludeIds?: ReadonlySet<string>,
): ListedLastPassItem | undefined {
  if (typeof listing !== "string" || listing.length > 4 * 1024 * 1024)
    throw new Error("lastpass_create_outcome_unknown");
  const ids: string[] = [];
  for (const line of listing.split(/[\r\n]+/)) {
    const match = /\[id:\s*([0-9]{1,20})\]/.exec(line);
    if (!match) continue;
    if (excludeIds && excludeIds.has(match[1]!)) continue;
    let title = line.slice(0, match.index).trimEnd();
    title = title.replace(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2} /, "");
    const separator = title.indexOf("/");
    if (separator >= 0) title = title.slice(separator + 1);
    if (title === expectedName && ITEM_ID.test(match[1]!)) ids.push(match[1]!);
  }
  if (ids.length === 0) return undefined;
  if (ids.length !== 1) throw new Error("lastpass_create_outcome_unknown");
  return { id: ids[0]! };
}

function parseListedItemIds(listing: string): Set<string> {
  const ids = new Set<string>();
  if (typeof listing !== "string" || listing.length > 4 * 1024 * 1024)
    return ids;
  for (const line of listing.split(/[\r\n]+/)) {
    const match = /\[id:\s*([0-9]{1,20})\]/.exec(line);
    if (match && ITEM_ID.test(match[1]!)) ids.add(match[1]!);
  }
  return ids;
}

const sleep = (milliseconds: number) =>
  new Promise<void>((resolve) => {
    setTimeout(resolve, milliseconds);
  });

function assertWritableValue(value: string): void {
  if (
    typeof value !== "string" ||
    !value ||
    Buffer.byteLength(value, "utf8") > 8192
  )
    throw new Error("lastpass_update_invalid");
}

function sameUntouchedFields(
  before: Record<string, unknown>,
  after: Record<string, unknown>,
  field: "password" | "username" | "note",
): boolean {
  // LastPass advances both server-managed timestamps whenever an item is
  // edited. They are not sibling data, but every other value stays checked.
  const managedTimestamps = new Set(["last_modified_gmt", "last_touch"]);
  const normalize = (item: Record<string, unknown>) => {
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(item).sort()) {
      if (key === field || managedTimestamps.has(key)) continue;
      result[key] = item[key];
    }
    return result;
  };
  return JSON.stringify(normalize(before)) === JSON.stringify(normalize(after));
}

function sessionEmail(status: string): string {
  if (typeof status !== "string" || Buffer.byteLength(status, "utf8") > 4096)
    throw new Error("lastpass_session_unavailable");
  const match = /^Logged in as ([^\s]+)\.$/m.exec(status.trim());
  if (!match || !validEmail(match[1]!))
    throw new Error("lastpass_session_unavailable");
  return match[1]!.toLowerCase();
}

const LASTPASS_ENV = {
  PATH: "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
  HOME: process.env.HOME,
  LPASS_AGENT_TIMEOUT: "60",
  LPASS_DISABLE_PINENTRY: "1",
} satisfies NodeJS.ProcessEnv;

const CREATE_ID_RESOLUTION_ATTEMPTS = 8;
const CREATE_ID_RESOLUTION_DELAY_MS = 1_000;

function runLastPass(
  profileHome: string,
  args: string[],
  maxBuffer = 16 * 1024 * 1024,
  input = "",
): string {
  try {
    return execFileSync("lpass", args, {
      encoding: "utf8",
      timeout: 20_000,
      maxBuffer,
      input,
      env: { ...LASTPASS_ENV, LPASS_HOME: profileHome },
    });
  } catch {
    throw new Error("lastpass_cli_failed");
  }
}

const systemRunner: LastPassRunner = {
  async status(profileHome) {
    return runLastPass(profileHome, ["status", "--color=never"], 4096);
  },
  async showItem(profileHome, itemId) {
    return runLastPass(profileHome, [
      "show",
      "--json",
      "--sync=now",
      "--color=never",
      itemId,
    ]);
  },
  async listItems(profileHome) {
    return runLastPass(
      profileHome,
      ["ls", "--sync=now", "--long", "--color=never"],
      4 * 1024 * 1024,
    );
  },
  async createItem(profileHome, name, value) {
    return runLastPass(
      profileHome,
      [
        "add",
        "--sync=now",
        "--non-interactive",
        "--color=never",
        "--password",
        "--",
        name,
      ],
      4096,
      value,
    );
  },
  async updateField(profileHome, itemId, field, value) {
    const selector = field === "note" ? "--notes" : "--" + field;
    runLastPass(
      profileHome,
      [
        "edit",
        "--sync=now",
        "--non-interactive",
        "--color=never",
        selector,
        itemId,
      ],
      16 * 1024 * 1024,
      value,
    );
  },
};

/**
 * Local exact-field reader for a dedicated, owner-bound LastPass CLI profile.
 * The profile is restricted to AgentSecret's private LastPass directory and
 * the CLI's full decrypted JSON remains in this process.
 */
export class LastPassAdapter {
  constructor(
    private readonly binding: ProviderCredentialBinding,
    private readonly credentials: AccountBoundProviderCredentials,
    private readonly runner: LastPassRunner = systemRunner,
  ) {
    if (binding.providerMode !== "lastpass")
      throw new Error("lastpass_binding_invalid");
  }

  async verifySession(): Promise<true> {
    const profile = await this.profile();
    assertSafeProfileConfiguration(profile.home);
    const email = sessionEmail(await this.runner.status(profile.home));
    if (email !== profile.userEmail)
      throw new Error("lastpass_profile_mismatch");
    return true;
  }

  async withResolvedField<T>(
    reference: string,
    consume: (value: string) => Promise<T>,
  ): Promise<T> {
    const { itemId, field } = parseReference(reference);
    try {
      const profile = await this.profile();
      assertSafeProfileConfiguration(profile.home);
      const email = sessionEmail(await this.runner.status(profile.home));
      if (email !== profile.userEmail)
        throw new Error("lastpass_profile_mismatch");
      const item = parseItem(
        await this.runner.showItem(profile.home, itemId),
        itemId,
      );
      const value = item[field];
      if (typeof value !== "string" || !value)
        throw new Error("lastpass_field_unavailable");
      return await consume(value);
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("lastpass_"))
        throw error;
      throw new Error("lastpass_read_failed");
    }
  }

  /**
   * Noninteractive, stdin-only create/update/ensure inside the dedicated
   * AgentSecret LPASS_HOME. Delete remains out of scope; ambiguous CLI or
   * read-back results are reported as *_outcome_unknown for reconciliation.
   */
  async createSecret(
    title: string,
    value: string,
  ): Promise<LastPassSafeReceipt> {
    const normalTitle = title.trim();
    if (
      typeof title !== "string" ||
      title !== normalTitle ||
      !normalTitle ||
      normalTitle.length > 128 ||
      /[\\/#\u0000-\u001f\u007f]/.test(normalTitle)
    )
      throw new Error("lastpass_create_invalid");
    if (
      typeof value !== "string" ||
      !value ||
      Buffer.byteLength(value, "utf8") > 8192 ||
      /[\r\n]/.test(value)
    )
      throw new Error("lastpass_create_invalid");
    const profile = await this.profile();
    assertSafeProfileConfiguration(profile.home);
    await this.verifySession();
    let itemId: string;
    try {
      const beforeIds = parseListedItemIds(
        await this.runner.listItems(profile.home),
      );
      itemId = parseCreatedItemId(
        await this.runner.createItem(profile.home, normalTitle, value),
      );
      for (
        let attempt = 0;
        !itemId && attempt < CREATE_ID_RESOLUTION_ATTEMPTS;
        attempt++
      ) {
        if (attempt > 0) await sleep(CREATE_ID_RESOLUTION_DELAY_MS);
        const listed = parseCreatedItemFromListing(
          await this.runner.listItems(profile.home),
          normalTitle,
          beforeIds,
        );
        if (listed) itemId = listed.id;
      }
      if (itemId && beforeIds.has(itemId))
        throw new Error("lastpass_create_outcome_unknown");
      if (!itemId) throw new Error("lastpass_create_outcome_unknown");
    } catch {
      throw new Error("lastpass_create_outcome_unknown");
    }
    const reference = itemId + "#/password";
    try {
      const observed = parseItem(
        await this.runner.showItem(profile.home, itemId),
        itemId,
      );
      if (
        String(observed.id) !== itemId ||
        String(observed.name ?? "") !== normalTitle ||
        observed.password !== value
      )
        throw new Error("verification mismatch");
    } catch {
      throw new Error("lastpass_create_outcome_unknown");
    }
    return { status: "created", reference, verified: true };
  }

  async updateField(
    reference: string,
    value: string,
  ): Promise<LastPassSafeReceipt> {
    assertWritableValue(value);
    const { itemId, field } = parseReference(reference);
    const profile = await this.profile();
    await this.verifySession();
    const before = parseItem(
      await this.runner.showItem(profile.home, itemId),
      itemId,
    );
    if (typeof before[field] !== "string")
      throw new Error("lastpass_field_unavailable");
    try {
      await this.runner.updateField(profile.home, itemId, field, value);
    } catch {
      throw new Error("lastpass_update_outcome_unknown");
    }
    try {
      const observed = parseItem(
        await this.runner.showItem(profile.home, itemId),
        itemId,
      );
      if (
        observed[field] !== value ||
        !sameUntouchedFields(before, observed, field)
      )
        throw new Error("verification mismatch");
    } catch {
      throw new Error("lastpass_update_outcome_unknown");
    }
    return { status: "updated", reference, verified: true };
  }

  async ensureField(
    reference: string,
    value: string,
  ): Promise<LastPassSafeReceipt> {
    assertWritableValue(value);
    let current = "";
    await this.withResolvedField(reference, async (observed) => {
      current = observed;
    });
    if (current === value)
      return { status: "unchanged", reference, verified: true };
    const updated = await this.updateField(reference, value);
    return { ...updated, status: "updated" };
  }

  private async profile(): Promise<LastPassProfile> {
    const stored = await this.credentials.get(this.binding);
    if (!stored) throw new Error("lastpass_profile_unconfigured");
    return parseProfile(stored);
  }
}
