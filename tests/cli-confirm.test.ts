import assert from "node:assert/strict";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { createInterface } from "node:readline";
import { test } from "node:test";
import {
  askYesNo,
  isAffirmative,
  lastPassProfileHome,
  MAX_UNIX_SOCKET_PATH_BYTES,
  YES_NO_HINT,
} from "../cli/confirm";

test("default-yes answers: Enter, y and yes in any case confirm; anything else cancels", () => {
  for (const answer of ["", "  ", "y", "Y", "yes", "YES", "Yes", " yes \n"])
    assert.equal(isAffirmative(answer), true, JSON.stringify(answer));
  for (const answer of ["n", "N", "no", "NO", "ye", "yess", "yes please", "1"])
    assert.equal(isAffirmative(answer), false, JSON.stringify(answer));
});

test("askYesNo passes the full question and its answer hint to readline", async () => {
  const asked: string[] = [];
  const confirmed = await askYesNo(
    {
      question(query, callback) {
        asked.push(query);
        callback("");
      },
    },
    "Bind it to alias X?",
  );
  assert.equal(confirmed, true);
  assert.deepEqual(asked, [`Bind it to alias X? ${YES_NO_HINT}`]);
  assert.match(YES_NO_HINT, /Enter/);
  assert.match(YES_NO_HINT, /\[Y\/n\]/);
});

test("askYesNo keeps the question visible on a terminal readline", async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  let rendered = "";
  output.on("data", (chunk) => (rendered += chunk.toString("utf8")));
  const rl = createInterface({ input, output, terminal: true });
  try {
    const pending = askYesNo(rl, "Bind it to alias X?");
    input.write("n\r");
    assert.equal(await pending, false);
  } finally {
    rl.close();
  }
  // Strip ANSI cursor/erase sequences; the last render must still hold the question.
  const lastLine = rendered
    .replace(/\x1b\[[0-9;]*[A-Za-z]/g, "")
    .split(/\r?\n/)
    .filter((line) => line.trim())
    .at(-1);
  assert.equal(lastLine, `Bind it to alias X? ${YES_NO_HINT}n`);
});

test("LastPass profile home keeps lpass's agent socket within the Unix socket limit", () => {
  const binding = {
    server: "https://agentsecret.example.test",
    tenant: "acc_synthetic",
    connectionId: "connection-synthetic",
    connectionRevision: 1,
    providerMode: "lastpass",
  };
  const root = "/Users/a-typical-user-name/.local/share/agentsecret/lastpass";
  const home = lastPassProfileHome(root, binding);
  assert.equal(home, lastPassProfileHome(root, binding), "deterministic");
  assert.match(home.slice(root.length + 1), /^[0-9a-f]{16}$/);
  assert.ok(
    Buffer.byteLength(join(home, "agent.sock")) <= MAX_UNIX_SOCKET_PATH_BYTES,
  );
  assert.notEqual(
    home,
    lastPassProfileHome(root, { ...binding, connectionRevision: 2 }),
  );
  // Regression: the former 64-hex directory name overflowed the socket limit
  // for this ordinary home directory.
  assert.ok(
    Buffer.byteLength(join(root, "f".repeat(64), "agent.sock")) >
      MAX_UNIX_SOCKET_PATH_BYTES,
  );
  assert.throws(
    () => lastPassProfileHome(`/Users/${"x".repeat(80)}/lastpass`, binding),
    /lastpass_profile_path_too_long/,
  );
});
