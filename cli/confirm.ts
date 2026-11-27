import { createHash } from "node:crypto";
import { join } from "node:path";

/** Hint appended to every default-yes question so the expected answer is explicit. */
export const YES_NO_HINT =
  "Press Enter or type y to confirm, n to cancel [Y/n]: ";

/** Default-yes answer for `[Y/n]` prompts: empty, `y` or `yes` (any case) confirm; anything else cancels. */
export function isAffirmative(answer: string): boolean {
  return /^(y(es)?)?$/i.test(answer.trim());
}

export interface QuestionInterface {
  question(query: string, callback: (answer: string) => void): void;
}

/**
 * Ask a default-yes question. The full question is passed to `question` so a
 * terminal readline keeps it on screen while waiting (writing it separately and
 * then calling `question("")` lets readline redraw over it).
 */
export function askYesNo(
  input: QuestionInterface,
  question: string,
): Promise<boolean> {
  return new Promise((resolve) => {
    input.question(`${question} ${YES_NO_HINT}`, (answer) =>
      resolve(isAffirmative(answer)),
    );
  });
}

/** Unix socket paths are limited to 104 bytes (including NUL) on macOS. */
export const MAX_UNIX_SOCKET_PATH_BYTES = 103;

/**
 * Per-binding LPASS_HOME. lpass keeps its agent socket (`agent.sock`) inside
 * LPASS_HOME, so the directory name is a short digest and the resulting socket
 * path is checked against the platform limit.
 */
export function lastPassProfileHome(
  profileRoot: string,
  binding: unknown,
): string {
  const profileKey = createHash("sha256")
    .update(JSON.stringify(binding))
    .digest("hex")
    .slice(0, 16);
  const profileHome = join(profileRoot, profileKey);
  if (
    Buffer.byteLength(join(profileHome, "agent.sock"), "utf8") >
    MAX_UNIX_SOCKET_PATH_BYTES
  )
    throw new Error("lastpass_profile_path_too_long");
  return profileHome;
}
