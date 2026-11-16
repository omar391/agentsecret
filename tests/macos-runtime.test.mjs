import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import {
  existsSync,
  closeSync,
  chmodSync,
  openSync,
  linkSync,
  mkdtempSync,
  mkdirSync,
  readlinkSync,
  realpathSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import childProcess, { spawn, spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { syncBuiltinESMExports } from "node:module";
import { createServer as createNetServer } from "node:net";
import { fileURLToPath, pathToFileURL } from "node:url";
import { unit } from "./unit-helpers.mjs";

test("macOS sandbox preflight rejects hard-linked files before launch", (t) => {
  const root = mkdtempSync(path.join(tmpdir(), "agentsecret-hardlink-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const allowed = path.join(root, "allowed");
  const nested = path.join(allowed, "nested");
  mkdirSync(nested, { recursive: true });
  writeFileSync(path.join(nested, "ordinary.txt"), "synthetic");
  assert.doesNotThrow(() => unit.assertNoHardLinksInRoots([allowed]));

  const outside = path.join(root, "outside-secret.txt");
  const linked = path.join(nested, "linked.txt");
  writeFileSync(outside, "synthetic outside data");
  linkSync(outside, linked);
  assert.throws(
    () => unit.assertNoHardLinksInRoots([allowed]),
    /must not contain hard-linked files/,
  );
});

test(
  "macOS runner preserves argv, fences filesystem and network, and cleans up on cancellation",
  { skip: process.platform !== "darwin" },
  async (t) => {
    const verifiedRuntime = unit.verifyMacSandboxRuntime();
    assert.equal(verifiedRuntime.executable, "/usr/bin/sandbox-exec");
    assert.equal(verifiedRuntime.identifier, "com.apple.sandbox-exec");
    assert.match(verifiedRuntime.cdhash, /^[a-f0-9]{40}$/);
    assert.match(verifiedRuntime.osVersion, /^\d+(?:\.\d+){1,3}$/);
    assert.match(verifiedRuntime.osBuild, /^[A-Za-z0-9._-]{1,64}$/);
    assert.throws(
      () =>
        unit.parseMacSandboxRuntimeIdentity(
          `Identifier=untrusted.helper\nCDHash=${"a".repeat(40)}`,
          verifiedRuntime.osVersion,
          verifiedRuntime.osBuild,
        ),
      /Unexpected system runtime identity/,
    );
    assert.throws(
      () =>
        unit.parseMacSandboxRuntimeIdentity(
          `Identifier=com.apple.sandbox-exec\nCDHash=${"a".repeat(40)}\nAuthority=Developer ID Application`,
          verifiedRuntime.osVersion,
          verifiedRuntime.osBuild,
        ),
      /Unexpected system runtime identity/,
    );
    const root = mkdtempSync(
      path.join(tmpdir(), "agentsecret-macos-runtime-test-"),
    );
    const project = path.join(
      root,
      'project") (allow file-write* (subpath "/")) ("',
    );
    mkdirSync(project, { recursive: true });
    t.after(() => rmSync(root, { recursive: true, force: true }));

    const inside = path.join(project, "inside.txt");
    const outside = path.join(root, "outside.txt");
    writeFileSync(inside, "inside-only");
    writeFileSync(outside, "outside-denied");

    const cat = unit.prepareMacSandbox({
      executable: "/bin/cat",
      args: [inside],
      cwd: project,
    });
    try {
      assert.deepEqual(cat.runtimeIdentity, verifiedRuntime);
      const result = spawnSync(cat.command, cat.args, {
        cwd: cat.cwd,
        env: cat.env,
        encoding: "utf8",
        timeout: 5000,
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, "inside-only");
    } finally {
      cat.cleanup();
    }

    const createdHardlink = path.join(project, "sandbox-created-hardlink.txt");
    const denyHardlinkCreation = unit.prepareMacSandbox({
      executable: "/bin/ln",
      args: [inside, createdHardlink],
      cwd: project,
    });
    try {
      const result = spawnSync(
        denyHardlinkCreation.command,
        denyHardlinkCreation.args,
        {
          cwd: denyHardlinkCreation.cwd,
          env: denyHardlinkCreation.env,
          encoding: "utf8",
          timeout: 5000,
        },
      );
      assert.notEqual(result.status, 0);
      assert.equal(existsSync(createdHardlink), false);
    } finally {
      denyHardlinkCreation.cleanup();
    }

    const outsideHardlink = path.join(project, "outside-hardlink.txt");
    linkSync(outside, outsideHardlink);
    assert.throws(
      () =>
        unit.prepareMacSandbox({
          executable: "/bin/cat",
          args: [outsideHardlink],
          cwd: project,
        }),
      /must not contain hard-linked files/,
    );
    unlinkSync(outsideHardlink);

    const deniedRead = unit.prepareMacSandbox({
      executable: "/bin/cat",
      args: [outside],
      cwd: project,
    });
    try {
      const result = spawnSync(deniedRead.command, deniedRead.args, {
        cwd: deniedRead.cwd,
        env: deniedRead.env,
        encoding: "utf8",
        timeout: 5000,
      });
      assert.notEqual(result.status, 0);
      assert.doesNotMatch(result.stdout, /outside-denied/);
    } finally {
      deniedRead.cleanup();
    }

    const outsideReadLink = path.join(project, "outside-read-link.txt");
    symlinkSync(outside, outsideReadLink);
    const deniedSymlinkRead = unit.prepareMacSandbox({
      executable: "/bin/cat",
      args: [outsideReadLink],
      cwd: project,
    });
    try {
      const result = spawnSync(
        deniedSymlinkRead.command,
        deniedSymlinkRead.args,
        {
          cwd: deniedSymlinkRead.cwd,
          env: deniedSymlinkRead.env,
          encoding: "utf8",
          timeout: 5000,
        },
      );
      assert.notEqual(result.status, 0);
      assert.doesNotMatch(result.stdout, /outside-denied/);
    } finally {
      deniedSymlinkRead.cleanup();
    }

    const marker = path.join(project, "written.txt");
    const touchInside = unit.prepareMacSandbox({
      executable: "/usr/bin/touch",
      args: [marker],
      cwd: project,
    });
    try {
      const result = spawnSync(touchInside.command, touchInside.args, {
        cwd: touchInside.cwd,
        env: touchInside.env,
        encoding: "utf8",
        timeout: 5000,
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(readFileSync(marker, "utf8"), "");
    } finally {
      touchInside.cleanup();
    }

    const outsideWrite = path.join(root, "escaped.txt");
    const touchOutside = unit.prepareMacSandbox({
      executable: "/usr/bin/touch",
      args: [outsideWrite],
      cwd: project,
    });
    try {
      const result = spawnSync(touchOutside.command, touchOutside.args, {
        cwd: touchOutside.cwd,
        env: touchOutside.env,
        encoding: "utf8",
        timeout: 5000,
      });
      assert.notEqual(result.status, 0);
    } finally {
      touchOutside.cleanup();
    }
    assert.throws(() => readFileSync(outsideWrite));

    const symlinkWriteTarget = path.join(root, "symlink-write-target.txt");
    const symlinkWrite = path.join(project, "outside-write-link.txt");
    writeFileSync(symlinkWriteTarget, "unchanged");
    symlinkSync(symlinkWriteTarget, symlinkWrite);
    const deniedSymlinkWrite = unit.prepareMacSandbox({
      executable: "/usr/bin/tee",
      args: [symlinkWrite],
      cwd: project,
    });
    try {
      const result = spawnSync(
        deniedSymlinkWrite.command,
        deniedSymlinkWrite.args,
        {
          cwd: deniedSymlinkWrite.cwd,
          env: deniedSymlinkWrite.env,
          encoding: "utf8",
          input: "escaped-write",
          timeout: 5000,
        },
      );
      assert.notEqual(result.status, 0);
      assert.equal(readFileSync(symlinkWriteTarget, "utf8"), "unchanged");
    } finally {
      deniedSymlinkWrite.cleanup();
    }

    const cli = fileURLToPath(new URL("../dist/cli.mjs", import.meta.url));
    const isolatedConfigDir = path.join(root, "agentsecret-macos-gate");
    rmSync(isolatedConfigDir, { recursive: true, force: true });
    mkdirSync(isolatedConfigDir, { recursive: true });
    t.after(() => rmSync(isolatedConfigDir, { recursive: true, force: true }));
    const cliRun = spawnSync(
      process.execPath,
      [
        cli,
        "run",
        "--cwd",
        project,
        "--",
        "/usr/bin/printf",
        "%s|%s",
        "two words",
        "; touch " + outsideWrite,
      ],
      {
        cwd: project,
        encoding: "utf8",
        timeout: 5000,
        env: { ...process.env, AGENTSECRET_CONFIG_DIR: isolatedConfigDir },
      },
    );
    assert.equal(cliRun.status, 1);
    assert.deepEqual(JSON.parse(cliRun.stdout), {
      status: "runtime_not_qualified",
      reason: "macos_runtime_and_strict_credential_mediation_required",
    });
    assert.equal(cliRun.stderr, "");
    assert.throws(() => readFileSync(outsideWrite));

    const printf = unit.prepareMacSandbox({
      executable: "/usr/bin/printf",
      args: ["%s|%s", "two words", "; touch " + outsideWrite],
      cwd: project,
    });
    try {
      const result = spawnSync(printf.command, printf.args, {
        cwd: printf.cwd,
        env: printf.env,
        encoding: "utf8",
        timeout: 5000,
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, "two words|; touch " + outsideWrite);
    } finally {
      printf.cleanup();
    }
    assert.throws(() => readFileSync(outsideWrite));

    const stdinFile = path.join(project, "stdin.txt");
    const stdoutFile = path.join(project, "stdout.txt");
    writeFileSync(stdinFile, "synthetic stdin payload\n");
    const stdinFd = openSync(stdinFile, "r");
    const stdoutFd = openSync(stdoutFile, "w");
    try {
      const result = await unit.runMacSandbox(
        { executable: "/bin/cat", args: [], cwd: project },
        new AbortController().signal,
        [stdinFd, stdoutFd, "ignore"],
      );
      assert.equal(result, 0);
    } finally {
      closeSync(stdinFd);
      closeSync(stdoutFd);
    }
    assert.equal(readFileSync(stdoutFile, "utf8"), "synthetic stdin payload\n");

    const nonzeroExit = await unit.runMacSandbox(
      { executable: "/bin/sh", args: ["-c", "exit 37"], cwd: project },
      new AbortController().signal,
      "ignore",
    );
    assert.equal(nonzeroExit, 37);

    const requests = [];
    const fixture = createServer((_request, response) => {
      requests.push("request");
      response.end("unexpected");
    });
    await new Promise((resolve) => fixture.listen(0, "127.0.0.1", resolve));
    const address = fixture.address();
    const curl = unit.prepareMacSandbox({
      executable: "/usr/bin/curl",
      args: ["--max-time", "2", `http://127.0.0.1:${address.port}/`],
      cwd: project,
    });
    try {
      const execute = (command, args, options = {}) =>
        new Promise((resolve, reject) => {
          const child = spawn(command, args, { ...options, stdio: "ignore" });
          child.once("error", reject);
          child.once("close", resolve);
        });
      assert.equal(
        await execute("/usr/bin/curl", [
          "--max-time",
          "2",
          `http://127.0.0.1:${address.port}/`,
        ]),
        0,
      );
      assert.equal(requests.length, 1);
      assert.notEqual(
        await execute(curl.command, curl.args, {
          cwd: curl.cwd,
          env: curl.env,
        }),
        0,
      );
      assert.equal(requests.length, 1);
    } finally {
      curl.cleanup();
      await new Promise((resolve) => fixture.close(resolve));
    }

    const externalRunner = path.join(root, "runner.sh");
    writeFileSync(
      externalRunner,
      `#!/bin/sh\necho started\ncat '${outside}'\n`,
      { mode: 0o755 },
    );
    const external = unit.prepareMacSandbox({
      executable: externalRunner,
      args: [],
      cwd: project,
    });
    try {
      const result = spawnSync(external.command, external.args, {
        cwd: external.cwd,
        env: external.env,
        encoding: "utf8",
        timeout: 5000,
      });
      assert.notEqual(result.status, 0);
      assert.match(result.stdout, /started/);
      assert.doesNotMatch(result.stdout, /outside-denied/);
    } finally {
      external.cleanup();
    }

    const pidFile = path.join(project, "child.pid");
    const stubbornController = new AbortController();
    const stubborn = unit.runMacSandbox(
      {
        executable: "/bin/sh",
        args: [
          "-c",
          `sh -c 'trap "" TERM; echo $$ > child.pid; exec sleep 30' & wait`,
        ],
        cwd: project,
      },
      stubbornController.signal,
      "ignore",
    );
    for (let i = 0; i < 100; i++) {
      try {
        readFileSync(pidFile);
        break;
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
    }
    const descendant = Number(readFileSync(pidFile, "utf8"));
    stubbornController.abort();
    await stubborn;
    assert.throws(() => process.kill(descendant, 0), { code: "ESRCH" });

    const backgroundPidFile = path.join(project, "background.pid");
    assert.equal(
      await unit.runMacSandbox(
        {
          executable: "/bin/sh",
          args: ["-c", "sleep 30 & echo $! > background.pid; exit 0"],
          cwd: project,
        },
        new AbortController().signal,
        "ignore",
      ),
      0,
    );
    const backgroundPid = Number(readFileSync(backgroundPidFile, "utf8"));
    assert.throws(() => process.kill(backgroundPid, 0), { code: "ESRCH" });

    const controller = new AbortController();
    const running = unit.runMacSandbox(
      { executable: "/bin/sleep", args: ["30"], cwd: project },
      controller.signal,
      "ignore",
    );
    setTimeout(() => controller.abort(), 150);
    assert.equal(await running, 130);
  },
);

test(
  "macOS Seatbelt runner stages a file and reads its Git index with the active Command Line Tools Git",
  { skip: process.platform !== "darwin" },
  async (t) => {
    const root = mkdtempSync(
      path.join(process.cwd(), "tmp/agentsecret-git-test-"),
    );
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const developerDirResult = spawnSync("/usr/bin/xcode-select", ["-p"], {
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(developerDirResult.status, 0, developerDirResult.stderr);
    const developerDir = developerDirResult.stdout.trim();
    const gitBin = path.join(developerDir, "usr/bin");
    const gitExecutable = path.join(gitBin, "git");
    const gitCore = path.join(developerDir, "usr/libexec/git-core");
    const gitShare = path.join(developerDir, "usr/share/git-core");
    const gitProject = path.join(root, "project");
    mkdirSync(gitProject);
    const gitEnvironment = {
      GIT_EXEC_PATH: gitCore,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_TEMPLATE_DIR: "/dev/null",
    };
    const runSandboxedGit = (args) => {
      const invocation = unit.prepareMacSandbox({
        executable: "/usr/bin/git",
        args,
        cwd: gitProject,
        readPaths: [gitBin, gitCore, gitShare],
      });
      try {
        return spawnSync(invocation.command, invocation.args, {
          cwd: invocation.cwd,
          env: { ...invocation.env, ...gitEnvironment },
          encoding: "utf8",
          timeout: 10_000,
        });
      } finally {
        invocation.cleanup();
      }
    };
    const runSandboxedGitAsFixture = (args) =>
      runSandboxedGit([
        "-c",
        "user.name=AgentSecret Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "core.hooksPath=/dev/null",
        ...args,
      ]);
    const readGitHead = () => {
      const result = spawnSync(gitExecutable, ["rev-parse", "HEAD"], {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      });
      assert.equal(result.status, 0, result.stderr);
      return result.stdout.trim();
    };
    const gitInit = spawnSync(gitExecutable, ["init", "--quiet"], {
      cwd: gitProject,
      env: { ...process.env, ...gitEnvironment },
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(gitInit.status, 0, gitInit.stderr);
    const gitShimStatus = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: ["status", "--short"],
      cwd: gitProject,
    });
    try {
      assert.equal(gitShimStatus.env.GIT_EXEC_PATH, gitCore);
      assert.deepEqual(gitShimStatus.args.slice(-3), [
        gitExecutable,
        "status",
        "--short",
      ]);
      const result = spawnSync(gitShimStatus.command, gitShimStatus.args, {
        cwd: gitShimStatus.cwd,
        env: {
          ...gitShimStatus.env,
          GIT_CONFIG_GLOBAL: "/dev/null",
          GIT_CONFIG_NOSYSTEM: "1",
        },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, "");
    } finally {
      gitShimStatus.cleanup();
    }
    writeFileSync(
      path.join(gitProject, "sample.txt"),
      "synthetic git payload\n",
    );
    const externalTarget = path.join(root, "outside-project-secret.txt");
    writeFileSync(externalTarget, "synthetic outside target contents\n");
    const externalLink = path.join(gitProject, "external-link");
    symlinkSync("../outside-project-secret.txt", externalLink);
    const symlinkRead = unit.prepareMacSandbox({
      executable: "/bin/cat",
      args: [externalLink],
      cwd: gitProject,
    });
    try {
      const result = spawnSync(symlinkRead.command, symlinkRead.args, {
        cwd: symlinkRead.cwd,
        env: symlinkRead.env,
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.notEqual(
        result.status,
        0,
        "sandboxed cat read a symlink target outside the project",
      );
      assert.equal(result.stdout, "");
      assert.doesNotMatch(result.stderr, /synthetic outside target contents/);
    } finally {
      symlinkRead.cleanup();
    }
    const gitAdd = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: ["add", "sample.txt", "external-link"],
      cwd: gitProject,
      readPaths: [gitBin, gitCore, gitShare],
    });
    try {
      const result = spawnSync(gitAdd.command, gitAdd.args, {
        cwd: gitAdd.cwd,
        env: { ...gitAdd.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 0, result.stderr);
    } finally {
      gitAdd.cleanup();
    }
    const gitStatus = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: ["status", "--short"],
      cwd: gitProject,
      readPaths: [gitBin, gitCore, gitShare],
    });
    try {
      const result = spawnSync(gitStatus.command, gitStatus.args, {
        cwd: gitStatus.cwd,
        env: { ...gitStatus.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout.trim(), "A  external-link\nA  sample.txt");
    } finally {
      gitStatus.cleanup();
    }
    const stagedFiles = spawnSync(
      gitExecutable,
      ["diff", "--cached", "--name-only"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(stagedFiles.status, 0, stagedFiles.stderr);
    assert.equal(stagedFiles.stdout.trim(), "external-link\nsample.txt");

    const stagedLinkMode = spawnSync(
      gitExecutable,
      ["ls-files", "--stage", "--", "external-link"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(stagedLinkMode.status, 0, stagedLinkMode.stderr);
    assert.match(
      stagedLinkMode.stdout,
      /^120000 [a-f0-9]{40} 0\texternal-link\n$/,
    );
    const stagedLinkContents = spawnSync(
      gitExecutable,
      ["show", ":external-link"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(stagedLinkContents.status, 0, stagedLinkContents.stderr);
    assert.equal(stagedLinkContents.stdout, "../outside-project-secret.txt");
    assert.doesNotMatch(
      stagedLinkContents.stdout,
      /synthetic outside target contents/,
    );

    const gitCommit = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: [
        "-c",
        "user.name=AgentSecret Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "core.hooksPath=/dev/null",
        "commit",
        "--quiet",
        "-m",
        "synthetic sandboxed commit",
      ],
      cwd: gitProject,
      readPaths: [gitBin, gitCore, gitShare],
    });
    try {
      const result = spawnSync(gitCommit.command, gitCommit.args, {
        cwd: gitCommit.cwd,
        env: { ...gitCommit.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 0, result.stderr);
    } finally {
      gitCommit.cleanup();
    }
    const committedSubject = spawnSync(
      gitExecutable,
      ["log", "-1", "--format=%s"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(committedSubject.status, 0, committedSubject.stderr);
    assert.equal(committedSubject.stdout.trim(), "synthetic sandboxed commit");

    const baseCommit = spawnSync(gitExecutable, ["rev-parse", "HEAD"], {
      cwd: gitProject,
      env: { ...process.env, ...gitEnvironment },
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(baseCommit.status, 0, baseCommit.stderr);
    const baseBranch = spawnSync(gitExecutable, ["branch", "--show-current"], {
      cwd: gitProject,
      env: { ...process.env, ...gitEnvironment },
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(baseBranch.status, 0, baseBranch.stderr);
    assert.ok(baseBranch.stdout.trim());
    const featureBranch = runSandboxedGit([
      "switch",
      "-c",
      "synthetic-cherry-pick",
    ]);
    assert.equal(featureBranch.status, 0, featureBranch.stderr);
    const cherryPickPath = path.join(gitProject, "cherry-pick.txt");
    writeFileSync(cherryPickPath, "synthetic cherry-pick payload\n");
    const cherryPickStage = runSandboxedGit(["add", "--", "cherry-pick.txt"]);
    assert.equal(cherryPickStage.status, 0, cherryPickStage.stderr);
    const cherryPickCommit = runSandboxedGit([
      "-c",
      "user.name=AgentSecret Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "-c",
      "commit.gpgsign=false",
      "-c",
      "core.hooksPath=/dev/null",
      "commit",
      "--quiet",
      "-m",
      "synthetic topic change",
    ]);
    assert.equal(cherryPickCommit.status, 0, cherryPickCommit.stderr);
    const featureCommit = spawnSync(gitExecutable, ["rev-parse", "HEAD"], {
      cwd: gitProject,
      env: { ...process.env, ...gitEnvironment },
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(featureCommit.status, 0, featureCommit.stderr);
    assert.notEqual(featureCommit.stdout.trim(), baseCommit.stdout.trim());
    const returnToBase = runSandboxedGit(["switch", baseBranch.stdout.trim()]);
    assert.equal(returnToBase.status, 0, returnToBase.stderr);
    const cherryPick = runSandboxedGit([
      "cherry-pick",
      "--no-edit",
      featureCommit.stdout.trim(),
    ]);
    assert.equal(cherryPick.status, 0, cherryPick.stderr);
    assert.equal(
      readFileSync(cherryPickPath, "utf8"),
      "synthetic cherry-pick payload\n",
    );
    const cherryPickedSubject = spawnSync(
      gitExecutable,
      ["log", "-1", "--format=%s"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(cherryPickedSubject.status, 0, cherryPickedSubject.stderr);
    assert.equal(cherryPickedSubject.stdout.trim(), "synthetic topic change");

    const tagCommit = spawnSync(gitExecutable, ["rev-parse", "HEAD"], {
      cwd: gitProject,
      env: { ...process.env, ...gitEnvironment },
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(tagCommit.status, 0, tagCommit.stderr);
    const tagCommitId = tagCommit.stdout.trim();
    const lightweightTag = runSandboxedGit([
      "tag",
      "synthetic-lightweight-tag",
      tagCommitId,
    ]);
    assert.equal(lightweightTag.status, 0, lightweightTag.stderr);
    const annotatedTag = runSandboxedGit([
      "-c",
      "user.name=AgentSecret Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "-c",
      "tag.gpgsign=false",
      "tag",
      "--annotate",
      "synthetic-annotated-tag",
      "--message",
      "synthetic tag metadata",
      tagCommitId,
    ]);
    assert.equal(annotatedTag.status, 0, annotatedTag.stderr);
    const tagList = runSandboxedGit(["tag", "--list", "synthetic-*-tag"]);
    assert.equal(tagList.status, 0, tagList.stderr);
    assert.deepEqual(tagList.stdout.trim().split("\n").sort(), [
      "synthetic-annotated-tag",
      "synthetic-lightweight-tag",
    ]);
    const lightweightObjectType = spawnSync(
      gitExecutable,
      ["cat-file", "-t", "refs/tags/synthetic-lightweight-tag"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(lightweightObjectType.status, 0, lightweightObjectType.stderr);
    assert.equal(lightweightObjectType.stdout.trim(), "commit");
    const annotatedObjectType = spawnSync(
      gitExecutable,
      ["cat-file", "-t", "refs/tags/synthetic-annotated-tag"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(annotatedObjectType.status, 0, annotatedObjectType.stderr);
    assert.equal(annotatedObjectType.stdout.trim(), "tag");
    const annotatedTagTarget = spawnSync(
      gitExecutable,
      ["rev-parse", "synthetic-annotated-tag^{}"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(annotatedTagTarget.status, 0, annotatedTagTarget.stderr);
    assert.equal(annotatedTagTarget.stdout.trim(), tagCommitId);
    const annotatedTagContents = spawnSync(
      gitExecutable,
      ["cat-file", "-p", "refs/tags/synthetic-annotated-tag"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(annotatedTagContents.status, 0, annotatedTagContents.stderr);
    assert.match(annotatedTagContents.stdout, /synthetic tag metadata/);
    const deleteAnnotatedTag = runSandboxedGit([
      "tag",
      "--delete",
      "synthetic-annotated-tag",
    ]);
    assert.equal(deleteAnnotatedTag.status, 0, deleteAnnotatedTag.stderr);
    const deleteLightweightTag = runSandboxedGit([
      "tag",
      "--delete",
      "synthetic-lightweight-tag",
    ]);
    assert.equal(deleteLightweightTag.status, 0, deleteLightweightTag.stderr);
    for (const name of [
      "synthetic-annotated-tag",
      "synthetic-lightweight-tag",
    ]) {
      const deletedTag = spawnSync(
        gitExecutable,
        ["show-ref", "--verify", "--quiet", `refs/tags/${name}`],
        {
          cwd: gitProject,
          env: { ...process.env, ...gitEnvironment },
          encoding: "utf8",
          timeout: 5000,
        },
      );
      assert.equal(deletedTag.status, 1, deletedTag.stderr);
    }

    const revertTestBranch = runSandboxedGit([
      "switch",
      "-c",
      "synthetic-revert-tests",
    ]);
    assert.equal(revertTestBranch.status, 0, revertTestBranch.stderr);
    const revertPath = path.join(gitProject, "revert-target.txt");
    writeFileSync(revertPath, "synthetic revert target\n");
    const revertTargetCommit = runSandboxedGit([
      "add",
      "--",
      "revert-target.txt",
    ]);
    assert.equal(revertTargetCommit.status, 0, revertTargetCommit.stderr);
    const revertTargetCreate = runSandboxedGitAsFixture([
      "commit",
      "--quiet",
      "-m",
      "synthetic revert target",
    ]);
    assert.equal(revertTargetCreate.status, 0, revertTargetCreate.stderr);
    const revertTargetId = readGitHead();
    const cleanRevert = runSandboxedGitAsFixture([
      "revert",
      "--no-edit",
      revertTargetId,
    ]);
    assert.equal(cleanRevert.status, 0, cleanRevert.stderr);
    assert.equal(existsSync(revertPath), false);
    const cleanRevertSubject = spawnSync(
      gitExecutable,
      ["log", "-1", "--format=%s"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(cleanRevertSubject.status, 0, cleanRevertSubject.stderr);
    assert.equal(
      cleanRevertSubject.stdout.trim(),
      'Revert "synthetic revert target"',
    );

    const revertConflictBase = "synthetic-revert-base";
    const revertConflictTopic = "synthetic-revert-topic";
    const revertConflictCurrent = "synthetic-revert-current";
    const revertConflictPath = path.join(gitProject, "revert-conflict.txt");
    const baseBranchForRevert = runSandboxedGit([
      "switch",
      "-c",
      revertConflictBase,
    ]);
    assert.equal(baseBranchForRevert.status, 0, baseBranchForRevert.stderr);
    writeFileSync(revertConflictPath, "base version\n");
    const stageRevertBase = runSandboxedGit([
      "add",
      "--",
      "revert-conflict.txt",
    ]);
    assert.equal(stageRevertBase.status, 0, stageRevertBase.stderr);
    const commitRevertBase = runSandboxedGitAsFixture([
      "commit",
      "--quiet",
      "-m",
      "synthetic revert conflict base",
    ]);
    assert.equal(commitRevertBase.status, 0, commitRevertBase.stderr);
    const revertBaseId = readGitHead();
    const topicBranchForRevert = runSandboxedGit([
      "switch",
      "-c",
      revertConflictTopic,
    ]);
    assert.equal(topicBranchForRevert.status, 0, topicBranchForRevert.stderr);
    writeFileSync(revertConflictPath, "topic version\n");
    const stageRevertTopic = runSandboxedGit([
      "add",
      "--",
      "revert-conflict.txt",
    ]);
    assert.equal(stageRevertTopic.status, 0, stageRevertTopic.stderr);
    const commitRevertTopic = runSandboxedGitAsFixture([
      "commit",
      "--quiet",
      "-m",
      "synthetic revert conflict topic",
    ]);
    assert.equal(commitRevertTopic.status, 0, commitRevertTopic.stderr);
    const revertTopicId = readGitHead();
    const currentBranchForRevert = runSandboxedGit([
      "switch",
      "-c",
      revertConflictCurrent,
      revertBaseId,
    ]);
    assert.equal(
      currentBranchForRevert.status,
      0,
      currentBranchForRevert.stderr,
    );
    writeFileSync(revertConflictPath, "current version\n");
    const stageRevertCurrent = runSandboxedGit([
      "add",
      "--",
      "revert-conflict.txt",
    ]);
    assert.equal(stageRevertCurrent.status, 0, stageRevertCurrent.stderr);
    const commitRevertCurrent = runSandboxedGitAsFixture([
      "commit",
      "--quiet",
      "-m",
      "synthetic revert conflict current",
    ]);
    assert.equal(commitRevertCurrent.status, 0, commitRevertCurrent.stderr);
    const currentCommitId = readGitHead();
    const conflictingRevert = runSandboxedGitAsFixture([
      "revert",
      "--no-edit",
      revertTopicId,
    ]);
    assert.notEqual(conflictingRevert.status, 0);
    const revertConflictStatus = runSandboxedGit(["status", "--short"]);
    assert.equal(revertConflictStatus.status, 0, revertConflictStatus.stderr);
    assert.match(revertConflictStatus.stdout, /UU revert-conflict\.txt/);
    const conflictContents = readFileSync(revertConflictPath, "utf8");
    assert.match(conflictContents, /^<<<<<<< HEAD\ncurrent version\n/m);
    assert.match(conflictContents, /^=======\nbase version\n>>>>>>>/m);
    const abortRevert = runSandboxedGit(["revert", "--abort"]);
    assert.equal(abortRevert.status, 0, abortRevert.stderr);
    assert.equal(readFileSync(revertConflictPath, "utf8"), "current version\n");
    const afterAbortRevert = runSandboxedGit(["status", "--short"]);
    assert.equal(afterAbortRevert.status, 0, afterAbortRevert.stderr);
    assert.equal(afterAbortRevert.stdout, "");
    assert.equal(readGitHead(), currentCommitId);
    const returnToBaseAfterRevert = runSandboxedGit([
      "switch",
      baseBranch.stdout.trim(),
    ]);
    assert.equal(
      returnToBaseAfterRevert.status,
      0,
      returnToBaseAfterRevert.stderr,
    );

    const resetBranch = runSandboxedGit([
      "switch",
      "-c",
      "synthetic-reset-tests",
    ]);
    assert.equal(resetBranch.status, 0, resetBranch.stderr);
    const resetBaseCommit = readGitHead();
    const resetSamplePath = path.join(gitProject, "sample.txt");
    writeFileSync(resetSamplePath, "synthetic reset commit payload\n");
    const stageResetSample = runSandboxedGit(["add", "--", "sample.txt"]);
    assert.equal(stageResetSample.status, 0, stageResetSample.stderr);
    const createResetCommit = runSandboxedGitAsFixture([
      "commit",
      "--quiet",
      "-m",
      "synthetic reset commit",
    ]);
    assert.equal(createResetCommit.status, 0, createResetCommit.stderr);
    assert.notEqual(readGitHead(), resetBaseCommit);

    const softReset = runSandboxedGit(["reset", "--soft", resetBaseCommit]);
    assert.equal(softReset.status, 0, softReset.stderr);
    assert.equal(readGitHead(), resetBaseCommit);
    assert.equal(
      readFileSync(resetSamplePath, "utf8"),
      "synthetic reset commit payload\n",
    );
    const afterSoftReset = runSandboxedGit(["status", "--short"]);
    assert.equal(afterSoftReset.status, 0, afterSoftReset.stderr);
    assert.equal(afterSoftReset.stdout, "M  sample.txt\n");
    const softResetDiff = spawnSync(
      gitExecutable,
      ["diff", "--cached", "--no-ext-diff", "--no-color", "--", "sample.txt"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(softResetDiff.status, 0, softResetDiff.stderr);
    assert.match(softResetDiff.stdout, /\+synthetic reset commit payload/);

    const mixedReset = runSandboxedGit(["reset", "--mixed", resetBaseCommit]);
    assert.equal(mixedReset.status, 0, mixedReset.stderr);
    assert.equal(readGitHead(), resetBaseCommit);
    const afterMixedReset = runSandboxedGit(["status", "--short"]);
    assert.equal(afterMixedReset.status, 0, afterMixedReset.stderr);
    assert.equal(afterMixedReset.stdout, " M sample.txt\n");
    const mixedResetDiff = spawnSync(
      gitExecutable,
      ["diff", "--cached", "--no-ext-diff", "--no-color", "--", "sample.txt"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(mixedResetDiff.status, 0, mixedResetDiff.stderr);
    assert.equal(mixedResetDiff.stdout, "");

    const restageResetSample = runSandboxedGit(["add", "--", "sample.txt"]);
    assert.equal(restageResetSample.status, 0, restageResetSample.stderr);
    const hardReset = runSandboxedGit(["reset", "--hard", resetBaseCommit]);
    assert.equal(hardReset.status, 0, hardReset.stderr);
    assert.equal(readGitHead(), resetBaseCommit);
    assert.equal(
      readFileSync(resetSamplePath, "utf8"),
      "synthetic git payload\n",
    );
    const afterHardReset = runSandboxedGit(["status", "--short"]);
    assert.equal(afterHardReset.status, 0, afterHardReset.stderr);
    assert.equal(afterHardReset.stdout, "");
    assert.equal(
      readFileSync(externalTarget, "utf8"),
      "synthetic outside target contents\n",
    );
    const returnToBaseAfterReset = runSandboxedGit([
      "switch",
      baseBranch.stdout.trim(),
    ]);
    assert.equal(
      returnToBaseAfterReset.status,
      0,
      returnToBaseAfterReset.stderr,
    );

    const cleanUntrackedPath = path.join(gitProject, "clean-untracked.txt");
    const cleanOutsideLink = path.join(gitProject, "clean-outside-link");
    writeFileSync(cleanUntrackedPath, "synthetic untracked cleanup\n");
    symlinkSync("../outside-project-secret.txt", cleanOutsideLink);
    const cleanPreview = runSandboxedGit([
      "clean",
      "--dry-run",
      "-fd",
      "--",
      "clean-untracked.txt",
      "clean-outside-link",
    ]);
    assert.equal(cleanPreview.status, 0, cleanPreview.stderr);
    assert.deepEqual(cleanPreview.stdout.trim().split("\n").sort(), [
      "Would remove clean-outside-link",
      "Would remove clean-untracked.txt",
    ]);
    const cleanUntracked = runSandboxedGit([
      "clean",
      "-fd",
      "--",
      "clean-untracked.txt",
      "clean-outside-link",
    ]);
    assert.equal(cleanUntracked.status, 0, cleanUntracked.stderr);
    assert.equal(existsSync(cleanUntrackedPath), false);
    assert.equal(existsSync(cleanOutsideLink), false);
    assert.equal(readlinkSync(externalLink), "../outside-project-secret.txt");
    assert.equal(
      readFileSync(externalTarget, "utf8"),
      "synthetic outside target contents\n",
    );
    const afterClean = runSandboxedGit(["status", "--short"]);
    assert.equal(afterClean.status, 0, afterClean.stderr);
    assert.equal(afterClean.stdout, "");

    const unmergedBranchName = "synthetic-unmerged-delete";
    const deleteBaseCommit = readGitHead();
    const createUnmergedBranch = runSandboxedGit([
      "switch",
      "-c",
      unmergedBranchName,
    ]);
    assert.equal(createUnmergedBranch.status, 0, createUnmergedBranch.stderr);
    writeFileSync(resetSamplePath, "unmerged branch payload\n");
    const stageUnmergedBranch = runSandboxedGit(["add", "--", "sample.txt"]);
    assert.equal(stageUnmergedBranch.status, 0, stageUnmergedBranch.stderr);
    const commitUnmergedBranch = runSandboxedGitAsFixture([
      "commit",
      "--quiet",
      "-m",
      "synthetic unmerged branch commit",
    ]);
    assert.equal(commitUnmergedBranch.status, 0, commitUnmergedBranch.stderr);
    assert.notEqual(readGitHead(), deleteBaseCommit);
    const returnToDeleteBase = runSandboxedGit([
      "switch",
      baseBranch.stdout.trim(),
    ]);
    assert.equal(returnToDeleteBase.status, 0, returnToDeleteBase.stderr);

    const refuseUnmergedDelete = runSandboxedGit([
      "branch",
      "-d",
      unmergedBranchName,
    ]);
    assert.notEqual(refuseUnmergedDelete.status, 0);
    assert.match(refuseUnmergedDelete.stderr, /not fully merged/);
    const retainedBranch = spawnSync(
      gitExecutable,
      ["show-ref", "--verify", "--quiet", `refs/heads/${unmergedBranchName}`],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(retainedBranch.status, 0, retainedBranch.stderr);

    const forceDeleteUnmerged = runSandboxedGit([
      "branch",
      "-D",
      unmergedBranchName,
    ]);
    assert.equal(forceDeleteUnmerged.status, 0, forceDeleteUnmerged.stderr);
    const deletedBranch = spawnSync(
      gitExecutable,
      ["show-ref", "--verify", "--quiet", `refs/heads/${unmergedBranchName}`],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(deletedBranch.status, 1, deletedBranch.stderr);
    assert.equal(readGitHead(), deleteBaseCommit);
    assert.equal(
      readFileSync(resetSamplePath, "utf8"),
      "synthetic git payload\n",
    );
    const afterBranchDelete = runSandboxedGit(["status", "--short"]);
    assert.equal(afterBranchDelete.status, 0, afterBranchDelete.stderr);
    assert.equal(afterBranchDelete.stdout, "");

    const rebaseBaseBranch = "synthetic-rebase-base";
    const rebaseTopicBranch = "synthetic-rebase-topic";
    const rebaseCurrentBranch = "synthetic-rebase-current";
    const rebaseConflictPath = path.join(gitProject, "rebase-conflict.txt");
    const createRebaseBase = runSandboxedGit([
      "switch",
      "-c",
      rebaseBaseBranch,
    ]);
    assert.equal(createRebaseBase.status, 0, createRebaseBase.stderr);
    writeFileSync(rebaseConflictPath, "rebase base version\n");
    const stageRebaseBase = runSandboxedGit([
      "add",
      "--",
      "rebase-conflict.txt",
    ]);
    assert.equal(stageRebaseBase.status, 0, stageRebaseBase.stderr);
    const commitRebaseBase = runSandboxedGitAsFixture([
      "commit",
      "--quiet",
      "-m",
      "synthetic rebase base",
    ]);
    assert.equal(commitRebaseBase.status, 0, commitRebaseBase.stderr);

    const createRebaseTopic = runSandboxedGit([
      "switch",
      "-c",
      rebaseTopicBranch,
    ]);
    assert.equal(createRebaseTopic.status, 0, createRebaseTopic.stderr);
    writeFileSync(rebaseConflictPath, "rebase topic version\n");
    const stageRebaseTopic = runSandboxedGit([
      "add",
      "--",
      "rebase-conflict.txt",
    ]);
    assert.equal(stageRebaseTopic.status, 0, stageRebaseTopic.stderr);
    const commitRebaseTopic = runSandboxedGitAsFixture([
      "commit",
      "--quiet",
      "-m",
      "synthetic rebase topic",
    ]);
    assert.equal(commitRebaseTopic.status, 0, commitRebaseTopic.stderr);
    const rebaseTopicCommit = readGitHead();

    const returnToRebaseBase = runSandboxedGit(["switch", rebaseBaseBranch]);
    assert.equal(returnToRebaseBase.status, 0, returnToRebaseBase.stderr);
    const createRebaseCurrent = runSandboxedGit([
      "switch",
      "-c",
      rebaseCurrentBranch,
    ]);
    assert.equal(createRebaseCurrent.status, 0, createRebaseCurrent.stderr);
    writeFileSync(rebaseConflictPath, "rebase current version\n");
    const stageRebaseCurrent = runSandboxedGit([
      "add",
      "--",
      "rebase-conflict.txt",
    ]);
    assert.equal(stageRebaseCurrent.status, 0, stageRebaseCurrent.stderr);
    const commitRebaseCurrent = runSandboxedGitAsFixture([
      "commit",
      "--quiet",
      "-m",
      "synthetic rebase current",
    ]);
    assert.equal(commitRebaseCurrent.status, 0, commitRebaseCurrent.stderr);
    const rebaseCurrentCommit = readGitHead();

    const returnToRebaseTopic = runSandboxedGit(["switch", rebaseTopicBranch]);
    assert.equal(returnToRebaseTopic.status, 0, returnToRebaseTopic.stderr);
    const conflictingRebase = runSandboxedGitAsFixture([
      "rebase",
      rebaseCurrentBranch,
    ]);
    assert.notEqual(conflictingRebase.status, 0);
    assert.match(conflictingRebase.stderr, /could not apply/);
    const rebaseConflictStatus = runSandboxedGit(["status", "--short"]);
    assert.equal(rebaseConflictStatus.status, 0, rebaseConflictStatus.stderr);
    assert.match(rebaseConflictStatus.stdout, /UU rebase-conflict\.txt/);
    const rebaseConflictContents = readFileSync(rebaseConflictPath, "utf8");
    assert.match(
      rebaseConflictContents,
      /^<<<<<<< HEAD\nrebase current version\n/m,
    );
    assert.match(
      rebaseConflictContents,
      /^=======\nrebase topic version\n>>>>>>>/m,
    );

    const abortRebase = runSandboxedGit(["rebase", "--abort"]);
    assert.equal(abortRebase.status, 0, abortRebase.stderr);
    assert.equal(readGitHead(), rebaseTopicCommit);
    assert.equal(
      readFileSync(rebaseConflictPath, "utf8"),
      "rebase topic version\n",
    );
    const afterRebaseAbort = runSandboxedGit(["status", "--short"]);
    assert.equal(afterRebaseAbort.status, 0, afterRebaseAbort.stderr);
    assert.equal(afterRebaseAbort.stdout, "");
    assert.equal(
      existsSync(path.join(gitProject, ".git", "rebase-merge")),
      false,
    );
    assert.equal(
      existsSync(path.join(gitProject, ".git", "rebase-apply")),
      false,
    );
    const verifyRebaseCurrent = spawnSync(
      gitExecutable,
      ["rev-parse", rebaseCurrentBranch],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(verifyRebaseCurrent.status, 0, verifyRebaseCurrent.stderr);
    assert.equal(verifyRebaseCurrent.stdout.trim(), rebaseCurrentCommit);
    const returnToOriginalBase = runSandboxedGit([
      "switch",
      baseBranch.stdout.trim(),
    ]);
    assert.equal(returnToOriginalBase.status, 0, returnToOriginalBase.stderr);

    const mergeBaseBranch = "synthetic-merge-base";
    const mergeTopicBranch = "synthetic-merge-topic";
    const mergeCurrentBranch = "synthetic-merge-current";
    const mergeConflictPath = path.join(gitProject, "merge-resolved.txt");
    const createMergeBase = runSandboxedGit(["switch", "-c", mergeBaseBranch]);
    assert.equal(createMergeBase.status, 0, createMergeBase.stderr);
    writeFileSync(mergeConflictPath, "merge base version\n");
    const stageMergeBase = runSandboxedGit(["add", "--", "merge-resolved.txt"]);
    assert.equal(stageMergeBase.status, 0, stageMergeBase.stderr);
    const commitMergeBase = runSandboxedGitAsFixture([
      "commit",
      "--quiet",
      "-m",
      "synthetic merge base",
    ]);
    assert.equal(commitMergeBase.status, 0, commitMergeBase.stderr);

    const createMergeTopic = runSandboxedGit([
      "switch",
      "-c",
      mergeTopicBranch,
    ]);
    assert.equal(createMergeTopic.status, 0, createMergeTopic.stderr);
    writeFileSync(mergeConflictPath, "merge topic version\n");
    const stageMergeTopic = runSandboxedGit([
      "add",
      "--",
      "merge-resolved.txt",
    ]);
    assert.equal(stageMergeTopic.status, 0, stageMergeTopic.stderr);
    const commitMergeTopic = runSandboxedGitAsFixture([
      "commit",
      "--quiet",
      "-m",
      "synthetic merge topic",
    ]);
    assert.equal(commitMergeTopic.status, 0, commitMergeTopic.stderr);
    const mergeTopicCommit = readGitHead();

    const returnToMergeBase = runSandboxedGit(["switch", mergeBaseBranch]);
    assert.equal(returnToMergeBase.status, 0, returnToMergeBase.stderr);
    const createMergeCurrent = runSandboxedGit([
      "switch",
      "-c",
      mergeCurrentBranch,
    ]);
    assert.equal(createMergeCurrent.status, 0, createMergeCurrent.stderr);
    writeFileSync(mergeConflictPath, "merge current version\n");
    const stageMergeCurrent = runSandboxedGit([
      "add",
      "--",
      "merge-resolved.txt",
    ]);
    assert.equal(stageMergeCurrent.status, 0, stageMergeCurrent.stderr);
    const commitMergeCurrent = runSandboxedGitAsFixture([
      "commit",
      "--quiet",
      "-m",
      "synthetic merge current",
    ]);
    assert.equal(commitMergeCurrent.status, 0, commitMergeCurrent.stderr);
    const mergeCurrentCommit = readGitHead();

    const returnToMergeTopic = runSandboxedGit(["switch", mergeTopicBranch]);
    assert.equal(returnToMergeTopic.status, 0, returnToMergeTopic.stderr);
    const conflictingMerge = runSandboxedGit(["merge", mergeCurrentBranch]);
    assert.notEqual(conflictingMerge.status, 0);
    assert.match(conflictingMerge.stdout + conflictingMerge.stderr, /CONFLICT/);
    const mergeConflictStatus = runSandboxedGit(["status", "--short"]);
    assert.equal(mergeConflictStatus.status, 0, mergeConflictStatus.stderr);
    assert.match(mergeConflictStatus.stdout, /UU merge-resolved\.txt/);

    writeFileSync(mergeConflictPath, "synthetic merge resolution\n");
    const stageMergeResolution = runSandboxedGit([
      "add",
      "--",
      "merge-resolved.txt",
    ]);
    assert.equal(stageMergeResolution.status, 0, stageMergeResolution.stderr);
    const continueMerge = runSandboxedGitAsFixture([
      "-c",
      "core.editor=true",
      "merge",
      "--continue",
    ]);
    assert.equal(continueMerge.status, 0, continueMerge.stderr);
    assert.equal(
      readFileSync(mergeConflictPath, "utf8"),
      "synthetic merge resolution\n",
    );
    const afterMergeContinue = runSandboxedGit(["status", "--short"]);
    assert.equal(afterMergeContinue.status, 0, afterMergeContinue.stderr);
    assert.equal(afterMergeContinue.stdout, "");
    const mergeParents = spawnSync(
      gitExecutable,
      ["rev-list", "--parents", "-n", "1", "HEAD"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(mergeParents.status, 0, mergeParents.stderr);
    assert.deepEqual(mergeParents.stdout.trim().split(" ").slice(1), [
      mergeTopicCommit,
      mergeCurrentCommit,
    ]);
    const returnToOriginalBaseAfterMerge = runSandboxedGit([
      "switch",
      baseBranch.stdout.trim(),
    ]);
    assert.equal(
      returnToOriginalBaseAfterMerge.status,
      0,
      returnToOriginalBaseAfterMerge.stderr,
    );

    const amendBranchName = "synthetic-amend-tests";
    const createAmendBranch = runSandboxedGit([
      "switch",
      "-c",
      amendBranchName,
    ]);
    assert.equal(createAmendBranch.status, 0, createAmendBranch.stderr);
    const amendBaseCommit = readGitHead();
    const statusBeforeAmend = runSandboxedGit(["status", "--short"]);
    assert.equal(statusBeforeAmend.status, 0, statusBeforeAmend.stderr);

    const amendSamplePath = path.join(gitProject, "sample.txt");
    writeFileSync(amendSamplePath, "synthetic amend original payload\n");
    const stageOriginalAmend = runSandboxedGit(["add", "--", "sample.txt"]);
    assert.equal(stageOriginalAmend.status, 0, stageOriginalAmend.stderr);
    const originalAmend = runSandboxedGitAsFixture([
      "commit",
      "--quiet",
      "-m",
      "synthetic amend subject",
    ]);
    assert.equal(originalAmend.status, 0, originalAmend.stderr);
    const originalAmendCommit = readGitHead();
    assert.notEqual(originalAmendCommit, amendBaseCommit);

    writeFileSync(amendSamplePath, "synthetic amend replacement payload\n");
    const stageAmendReplacement = runSandboxedGit(["add", "--", "sample.txt"]);
    assert.equal(stageAmendReplacement.status, 0, stageAmendReplacement.stderr);
    const amendCommit = runSandboxedGitAsFixture([
      "commit",
      "--amend",
      "--no-edit",
      "--quiet",
    ]);
    assert.equal(amendCommit.status, 0, amendCommit.stderr);
    const amendedCommit = readGitHead();
    assert.notEqual(amendedCommit, originalAmendCommit);
    assert.equal(
      readFileSync(amendSamplePath, "utf8"),
      "synthetic amend replacement payload\n",
    );
    const amendedParent = spawnSync(gitExecutable, ["rev-parse", "HEAD^"], {
      cwd: gitProject,
      env: { ...process.env, ...gitEnvironment },
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(amendedParent.status, 0, amendedParent.stderr);
    assert.equal(amendedParent.stdout.trim(), amendBaseCommit);
    const amendedSubject = spawnSync(
      gitExecutable,
      ["log", "-1", "--format=%s"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(amendedSubject.status, 0, amendedSubject.stderr);
    assert.equal(amendedSubject.stdout.trim(), "synthetic amend subject");
    const statusAfterAmend = runSandboxedGit(["status", "--short"]);
    assert.equal(statusAfterAmend.status, 0, statusAfterAmend.stderr);
    assert.equal(statusAfterAmend.stdout, statusBeforeAmend.stdout);

    const returnToOriginalBaseAfterAmend = runSandboxedGit([
      "switch",
      baseBranch.stdout.trim(),
    ]);
    assert.equal(
      returnToOriginalBaseAfterAmend.status,
      0,
      returnToOriginalBaseAfterAmend.stderr,
    );

    const originalMainHead = readGitHead();
    const cherryContinueBaseBranch = "synthetic-cherry-continue-base";
    const cherryContinueTopicBranch = "synthetic-cherry-continue-topic";
    const cherryContinueCurrentBranch = "synthetic-cherry-continue-current";
    const cherryContinuePath = path.join(
      gitProject,
      "cherry-continue-conflict.txt",
    );
    const createCherryContinueBase = runSandboxedGit([
      "switch",
      "-c",
      cherryContinueBaseBranch,
    ]);
    assert.equal(
      createCherryContinueBase.status,
      0,
      createCherryContinueBase.stderr,
    );
    writeFileSync(cherryContinuePath, "cherry-continue base version\n");
    const stageCherryContinueBase = runSandboxedGit([
      "add",
      "--",
      "cherry-continue-conflict.txt",
    ]);
    assert.equal(
      stageCherryContinueBase.status,
      0,
      stageCherryContinueBase.stderr,
    );
    const commitCherryContinueBase = runSandboxedGitAsFixture([
      "commit",
      "--quiet",
      "-m",
      "synthetic cherry-continue base",
    ]);
    assert.equal(
      commitCherryContinueBase.status,
      0,
      commitCherryContinueBase.stderr,
    );

    const createCherryContinueTopic = runSandboxedGit([
      "switch",
      "-c",
      cherryContinueTopicBranch,
    ]);
    assert.equal(
      createCherryContinueTopic.status,
      0,
      createCherryContinueTopic.stderr,
    );
    writeFileSync(cherryContinuePath, "cherry-continue topic version\n");
    const stageCherryContinueTopic = runSandboxedGit([
      "add",
      "--",
      "cherry-continue-conflict.txt",
    ]);
    assert.equal(
      stageCherryContinueTopic.status,
      0,
      stageCherryContinueTopic.stderr,
    );
    const commitCherryContinueTopic = runSandboxedGitAsFixture([
      "commit",
      "--quiet",
      "-m",
      "synthetic cherry-continue topic",
    ]);
    assert.equal(
      commitCherryContinueTopic.status,
      0,
      commitCherryContinueTopic.stderr,
    );
    const cherryContinueTopicCommit = readGitHead();

    const returnToCherryContinueBase = runSandboxedGit([
      "switch",
      cherryContinueBaseBranch,
    ]);
    assert.equal(
      returnToCherryContinueBase.status,
      0,
      returnToCherryContinueBase.stderr,
    );
    const createCherryContinueCurrent = runSandboxedGit([
      "switch",
      "-c",
      cherryContinueCurrentBranch,
    ]);
    assert.equal(
      createCherryContinueCurrent.status,
      0,
      createCherryContinueCurrent.stderr,
    );
    writeFileSync(cherryContinuePath, "cherry-continue current version\n");
    const stageCherryContinueCurrent = runSandboxedGit([
      "add",
      "--",
      "cherry-continue-conflict.txt",
    ]);
    assert.equal(
      stageCherryContinueCurrent.status,
      0,
      stageCherryContinueCurrent.stderr,
    );
    const commitCherryContinueCurrent = runSandboxedGitAsFixture([
      "commit",
      "--quiet",
      "-m",
      "synthetic cherry-continue current",
    ]);
    assert.equal(
      commitCherryContinueCurrent.status,
      0,
      commitCherryContinueCurrent.stderr,
    );
    const cherryContinueCurrentCommit = readGitHead();

    const returnToCherryContinueTopic = runSandboxedGit([
      "switch",
      cherryContinueTopicBranch,
    ]);
    assert.equal(
      returnToCherryContinueTopic.status,
      0,
      returnToCherryContinueTopic.stderr,
    );
    const statusBeforeCherryContinue = runSandboxedGit(["status", "--short"]);
    assert.equal(
      statusBeforeCherryContinue.status,
      0,
      statusBeforeCherryContinue.stderr,
    );
    const conflictingCherryContinue = runSandboxedGit([
      "cherry-pick",
      cherryContinueCurrentCommit,
    ]);
    assert.notEqual(conflictingCherryContinue.status, 0);
    assert.match(
      conflictingCherryContinue.stdout + conflictingCherryContinue.stderr,
      /CONFLICT/,
    );
    const cherryContinueConflictStatus = runSandboxedGit(["status", "--short"]);
    assert.equal(
      cherryContinueConflictStatus.status,
      0,
      cherryContinueConflictStatus.stderr,
    );
    assert.match(
      cherryContinueConflictStatus.stdout,
      /UU cherry-continue-conflict\.txt/,
    );
    writeFileSync(cherryContinuePath, "synthetic cherry-continue resolution\n");
    const stageCherryContinueResolution = runSandboxedGit([
      "add",
      "--",
      "cherry-continue-conflict.txt",
    ]);
    assert.equal(
      stageCherryContinueResolution.status,
      0,
      stageCherryContinueResolution.stderr,
    );
    const continueCherryPick = runSandboxedGitAsFixture([
      "-c",
      "core.editor=true",
      "cherry-pick",
      "--continue",
    ]);
    assert.equal(continueCherryPick.status, 0, continueCherryPick.stderr);
    const completedCherryPick = readGitHead();
    assert.notEqual(completedCherryPick, cherryContinueTopicCommit);
    assert.equal(
      readFileSync(cherryContinuePath, "utf8"),
      "synthetic cherry-continue resolution\n",
    );
    const cherryContinueParent = spawnSync(
      gitExecutable,
      ["rev-parse", "HEAD^"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(cherryContinueParent.status, 0, cherryContinueParent.stderr);
    assert.equal(cherryContinueParent.stdout.trim(), cherryContinueTopicCommit);
    const cherryContinueSubject = spawnSync(
      gitExecutable,
      ["log", "-1", "--format=%s"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(cherryContinueSubject.status, 0, cherryContinueSubject.stderr);
    assert.equal(
      cherryContinueSubject.stdout.trim(),
      "synthetic cherry-continue current",
    );
    const statusAfterCherryContinue = runSandboxedGit(["status", "--short"]);
    assert.equal(
      statusAfterCherryContinue.status,
      0,
      statusAfterCherryContinue.stderr,
    );
    assert.equal(
      statusAfterCherryContinue.stdout,
      statusBeforeCherryContinue.stdout,
    );
    const returnToOriginalBaseAfterCherryContinue = runSandboxedGit([
      "switch",
      baseBranch.stdout.trim(),
    ]);
    assert.equal(
      returnToOriginalBaseAfterCherryContinue.status,
      0,
      returnToOriginalBaseAfterCherryContinue.stderr,
    );
    assert.equal(readGitHead(), originalMainHead);

    const originalHeadBeforeRebaseContinue = readGitHead();
    const switchToRebaseTopicForContinue = runSandboxedGit([
      "switch",
      rebaseTopicBranch,
    ]);
    assert.equal(
      switchToRebaseTopicForContinue.status,
      0,
      switchToRebaseTopicForContinue.stderr,
    );
    const statusBeforeRebaseContinue = runSandboxedGit(["status", "--short"]);
    assert.equal(
      statusBeforeRebaseContinue.status,
      0,
      statusBeforeRebaseContinue.stderr,
    );
    const conflictForRebaseContinue = runSandboxedGitAsFixture([
      "rebase",
      rebaseCurrentBranch,
    ]);
    assert.notEqual(conflictForRebaseContinue.status, 0);
    assert.match(
      conflictForRebaseContinue.stdout + conflictForRebaseContinue.stderr,
      /could not apply/,
    );
    const rebaseContinueConflictStatus = runSandboxedGit(["status", "--short"]);
    assert.equal(
      rebaseContinueConflictStatus.status,
      0,
      rebaseContinueConflictStatus.stderr,
    );
    assert.match(
      rebaseContinueConflictStatus.stdout,
      /UU rebase-conflict\.txt/,
    );
    writeFileSync(
      rebaseConflictPath,
      "synthetic rebase continuation resolution\n",
    );
    const stageRebaseContinueResolution = runSandboxedGit([
      "add",
      "--",
      "rebase-conflict.txt",
    ]);
    assert.equal(
      stageRebaseContinueResolution.status,
      0,
      stageRebaseContinueResolution.stderr,
    );
    const continueRebase = runSandboxedGitAsFixture([
      "-c",
      "core.editor=true",
      "rebase",
      "--continue",
    ]);
    assert.equal(continueRebase.status, 0, continueRebase.stderr);
    assert.notEqual(readGitHead(), rebaseTopicCommit);
    assert.equal(
      readFileSync(rebaseConflictPath, "utf8"),
      "synthetic rebase continuation resolution\n",
    );
    const rebaseContinueParent = spawnSync(
      gitExecutable,
      ["rev-parse", "HEAD^"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(rebaseContinueParent.status, 0, rebaseContinueParent.stderr);
    assert.equal(rebaseContinueParent.stdout.trim(), rebaseCurrentCommit);
    const rebasedTopicSubject = spawnSync(
      gitExecutable,
      ["log", "-1", "--format=%s"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(rebasedTopicSubject.status, 0, rebasedTopicSubject.stderr);
    assert.equal(rebasedTopicSubject.stdout.trim(), "synthetic rebase topic");
    const statusAfterRebaseContinue = runSandboxedGit(["status", "--short"]);
    assert.equal(
      statusAfterRebaseContinue.status,
      0,
      statusAfterRebaseContinue.stderr,
    );
    assert.equal(
      statusAfterRebaseContinue.stdout,
      statusBeforeRebaseContinue.stdout,
    );
    assert.equal(
      existsSync(path.join(gitProject, ".git", "rebase-merge")),
      false,
    );
    const returnToOriginalBaseAfterRebaseContinue = runSandboxedGit([
      "switch",
      baseBranch.stdout.trim(),
    ]);
    assert.equal(
      returnToOriginalBaseAfterRebaseContinue.status,
      0,
      returnToOriginalBaseAfterRebaseContinue.stderr,
    );
    assert.equal(readGitHead(), originalHeadBeforeRebaseContinue);

    const linkedWorktree = path.join(gitProject, "approved-linked-worktree");
    const gitWorktreeAdd = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: ["worktree", "add", "--detach", linkedWorktree, "HEAD"],
      cwd: gitProject,
      readPaths: [gitBin, gitCore, gitShare],
    });
    try {
      const result = spawnSync(gitWorktreeAdd.command, gitWorktreeAdd.args, {
        cwd: gitWorktreeAdd.cwd,
        env: { ...gitWorktreeAdd.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 0, result.stderr);
    } finally {
      gitWorktreeAdd.cleanup();
    }
    assert.equal(existsSync(path.join(linkedWorktree, ".git")), true);
    const gitWorktreeList = spawnSync(
      gitExecutable,
      ["worktree", "list", "--porcelain"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(gitWorktreeList.status, 0, gitWorktreeList.stderr);
    assert.equal(gitWorktreeList.stdout.trim().split("\n\n").length, 2);
    assert.match(
      gitWorktreeList.stdout,
      new RegExp(`^worktree ${linkedWorktree}$`, "m"),
    );
    const originalHeadBeforeLinkedCommit = readGitHead();
    const linkedBranch = runSandboxedGitAsFixture([
      "-C",
      linkedWorktree,
      "switch",
      "-c",
      "worktree-lifecycle-topic",
    ]);
    assert.equal(linkedBranch.status, 0, linkedBranch.stderr);
    writeFileSync(
      path.join(linkedWorktree, "sample.txt"),
      "linked worktree lifecycle change\n",
    );
    const linkedCommit = runSandboxedGitAsFixture([
      "-C",
      linkedWorktree,
      "commit",
      "-am",
      "synthetic linked worktree change",
    ]);
    assert.equal(linkedCommit.status, 0, linkedCommit.stderr);
    assert.equal(readGitHead(), originalHeadBeforeLinkedCommit);
    assert.equal(
      readFileSync(path.join(gitProject, "sample.txt"), "utf8"),
      "synthetic git payload\n",
    );
    const linkedHead = spawnSync(gitExecutable, ["rev-parse", "HEAD"], {
      cwd: linkedWorktree,
      env: { ...process.env, ...gitEnvironment },
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(linkedHead.status, 0, linkedHead.stderr);
    assert.notEqual(linkedHead.stdout.trim(), originalHeadBeforeLinkedCommit);

    const lockedWorktree = runSandboxedGit([
      "worktree",
      "lock",
      "--reason",
      "synthetic lifecycle lock",
      linkedWorktree,
    ]);
    assert.equal(lockedWorktree.status, 0, lockedWorktree.stderr);
    const lockedList = runSandboxedGit(["worktree", "list", "--porcelain"]);
    assert.equal(lockedList.status, 0, lockedList.stderr);
    assert.match(lockedList.stdout, /^locked synthetic lifecycle lock$/m);
    const refusedLockedRemoval = runSandboxedGit([
      "worktree",
      "remove",
      linkedWorktree,
    ]);
    assert.notEqual(refusedLockedRemoval.status, 0);
    assert.equal(existsSync(path.join(linkedWorktree, ".git")), true);
    const registrationAfterRefusal = runSandboxedGit([
      "worktree",
      "list",
      "--porcelain",
    ]);
    assert.equal(
      registrationAfterRefusal.status,
      0,
      registrationAfterRefusal.stderr,
    );
    assert.match(
      registrationAfterRefusal.stdout,
      new RegExp(`^worktree ${linkedWorktree}$`, "m"),
    );
    const unlockedWorktree = runSandboxedGit([
      "worktree",
      "unlock",
      linkedWorktree,
    ]);
    assert.equal(unlockedWorktree.status, 0, unlockedWorktree.stderr);

    const movedWorktree = path.join(gitProject, "renamed-linked-worktree");
    const moveWorktree = runSandboxedGit([
      "worktree",
      "move",
      linkedWorktree,
      movedWorktree,
    ]);
    assert.equal(moveWorktree.status, 0, moveWorktree.stderr);
    assert.equal(existsSync(linkedWorktree), false);
    assert.equal(existsSync(path.join(movedWorktree, ".git")), true);
    const movedList = runSandboxedGit(["worktree", "list", "--porcelain"]);
    assert.equal(movedList.status, 0, movedList.stderr);
    assert.match(
      movedList.stdout,
      new RegExp(`^worktree ${movedWorktree}$`, "m"),
    );
    const removeWorktree = runSandboxedGit([
      "worktree",
      "remove",
      movedWorktree,
    ]);
    assert.equal(removeWorktree.status, 0, removeWorktree.stderr);
    assert.equal(existsSync(movedWorktree), false);
    const pruneWorktrees = runSandboxedGit(["worktree", "prune"]);
    assert.equal(pruneWorktrees.status, 0, pruneWorktrees.stderr);
    const finalWorktreeList = runSandboxedGit([
      "worktree",
      "list",
      "--porcelain",
    ]);
    assert.equal(finalWorktreeList.status, 0, finalWorktreeList.stderr);
    assert.equal(finalWorktreeList.stdout.trim().split("\n\n").length, 1);
    const retainedLifecycleBranch = runSandboxedGit([
      "branch",
      "--list",
      "worktree-lifecycle-topic",
    ]);
    assert.equal(
      retainedLifecycleBranch.status,
      0,
      retainedLifecycleBranch.stderr,
    );
    assert.equal(
      retainedLifecycleBranch.stdout.trim(),
      "worktree-lifecycle-topic",
    );

    const repairWorktree = path.join(gitProject, "repair-worktree-original");
    const addRepairWorktree = runSandboxedGitAsFixture([
      "worktree",
      "add",
      "-b",
      "worktree-repair-topic",
      repairWorktree,
      "HEAD",
    ]);
    assert.equal(addRepairWorktree.status, 0, addRepairWorktree.stderr);
    const manuallyMovedWorktree = path.join(
      gitProject,
      "repair-worktree-manually-moved",
    );
    renameSync(repairWorktree, manuallyMovedWorktree);
    const repairWorktreePointer = runSandboxedGit([
      "worktree",
      "repair",
      manuallyMovedWorktree,
    ]);
    assert.equal(repairWorktreePointer.status, 0, repairWorktreePointer.stderr);
    assert.equal(existsSync(path.join(manuallyMovedWorktree, ".git")), true);
    const repairedWorktreeList = runSandboxedGit([
      "worktree",
      "list",
      "--porcelain",
    ]);
    assert.equal(repairedWorktreeList.status, 0, repairedWorktreeList.stderr);
    assert.match(
      repairedWorktreeList.stdout,
      new RegExp(`^worktree ${manuallyMovedWorktree}$`, "m"),
    );
    const repairedWorktreeStatus = runSandboxedGit([
      "-C",
      manuallyMovedWorktree,
      "status",
      "--short",
    ]);
    assert.equal(
      repairedWorktreeStatus.status,
      0,
      repairedWorktreeStatus.stderr,
    );
    assert.equal(repairedWorktreeStatus.stdout, "");
    const removeRepairedWorktree = runSandboxedGit([
      "worktree",
      "remove",
      manuallyMovedWorktree,
    ]);
    assert.equal(
      removeRepairedWorktree.status,
      0,
      removeRepairedWorktree.stderr,
    );
    assert.equal(existsSync(manuallyMovedWorktree), false);

    const dirtyWorktree = path.join(gitProject, "dirty-worktree-refusal");
    const addDirtyWorktree = runSandboxedGitAsFixture([
      "worktree",
      "add",
      "--detach",
      dirtyWorktree,
      "HEAD",
    ]);
    assert.equal(addDirtyWorktree.status, 0, addDirtyWorktree.stderr);
    const dirtyTarget = path.join(dirtyWorktree, "sample.txt");
    writeFileSync(dirtyTarget, "dirty worktree edit\n");
    const untrackedTarget = path.join(dirtyWorktree, "untracked.txt");
    writeFileSync(untrackedTarget, "untracked worktree file\n");
    const refusedDirtyRemoval = runSandboxedGit([
      "worktree",
      "remove",
      dirtyWorktree,
    ]);
    assert.notEqual(refusedDirtyRemoval.status, 0);
    assert.equal(readFileSync(dirtyTarget, "utf8"), "dirty worktree edit\n");
    assert.equal(
      readFileSync(untrackedTarget, "utf8"),
      "untracked worktree file\n",
    );
    const dirtyRegistration = runSandboxedGit([
      "worktree",
      "list",
      "--porcelain",
    ]);
    assert.equal(dirtyRegistration.status, 0, dirtyRegistration.stderr);
    assert.match(
      dirtyRegistration.stdout,
      new RegExp(`^worktree ${dirtyWorktree}$`, "m"),
    );
    const forcedDirtyRemoval = runSandboxedGit([
      "worktree",
      "remove",
      "--force",
      dirtyWorktree,
    ]);
    assert.equal(forcedDirtyRemoval.status, 0, forcedDirtyRemoval.stderr);
    assert.equal(existsSync(dirtyWorktree), false);
    const forcedDirtyList = runSandboxedGit([
      "worktree",
      "list",
      "--porcelain",
    ]);
    assert.equal(forcedDirtyList.status, 0, forcedDirtyList.stderr);
    assert.doesNotMatch(
      forcedDirtyList.stdout,
      new RegExp(`^worktree ${dirtyWorktree}$`, "m"),
    );
    const nonInteractiveWorktree = path.join(
      gitProject,
      "noninteractive-worktree",
    );
    const nonInteractiveAdd = runSandboxedGitAsFixture([
      "worktree",
      "add",
      "-b",
      "worktree-noninteractive-topic",
      nonInteractiveWorktree,
      "HEAD",
    ]);
    assert.equal(nonInteractiveAdd.status, 0, nonInteractiveAdd.stderr);
    const nonInteractiveList = runSandboxedGit([
      "worktree",
      "list",
      "--porcelain",
    ]);
    assert.equal(nonInteractiveList.status, 0, nonInteractiveList.stderr);
    assert.match(
      nonInteractiveList.stdout,
      new RegExp(`^worktree ${nonInteractiveWorktree}$`, "m"),
    );
    const removedNonInteractive = runSandboxedGit([
      "worktree",
      "remove",
      nonInteractiveWorktree,
    ]);
    assert.equal(removedNonInteractive.status, 0, removedNonInteractive.stderr);
    assert.equal(existsSync(nonInteractiveWorktree), false);
    const committedWorktree = path.join(gitProject, "committed-worktree");
    const committedAdd = runSandboxedGitAsFixture([
      "worktree",
      "add",
      "-b",
      "worktree-committed-topic",
      committedWorktree,
      "HEAD",
    ]);
    assert.equal(committedAdd.status, 0, committedAdd.stderr);
    const previousHead = readGitHead();
    writeFileSync(
      path.join(committedWorktree, "sample.txt"),
      "committed worktree observation\n",
    );
    const committedCommit = runSandboxedGitAsFixture([
      "-C",
      committedWorktree,
      "commit",
      "-am",
      "synthetic committed worktree change",
    ]);
    assert.equal(committedCommit.status, 0, committedCommit.stderr);
    assert.equal(readGitHead(), previousHead);
    const committedHead = spawnSync(gitExecutable, ["rev-parse", "HEAD"], {
      cwd: committedWorktree,
      env: { ...process.env, ...gitEnvironment },
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(committedHead.status, 0, committedHead.stderr);
    assert.notEqual(committedHead.stdout.trim(), previousHead);
    const committedWorktreeSubject = spawnSync(
      gitExecutable,
      ["log", "-1", "--format=%s", "HEAD"],
      {
        cwd: committedWorktree,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(
      committedWorktreeSubject.status,
      0,
      committedWorktreeSubject.stderr,
    );
    assert.equal(
      committedWorktreeSubject.stdout.trim(),
      "synthetic committed worktree change",
    );
    const stashLinkedWorktree = path.join(gitProject, "stash-linked-worktree");
    const stashAdd = runSandboxedGitAsFixture([
      "worktree",
      "add",
      "-b",
      "worktree-stash-topic",
      stashLinkedWorktree,
      "HEAD",
    ]);
    assert.equal(stashAdd.status, 0, stashAdd.stderr);
    writeFileSync(
      path.join(stashLinkedWorktree, "sample.txt"),
      "linked worktree stash edit\n",
    );
    const linkedStashUntracked = path.join(
      stashLinkedWorktree,
      "stash-untracked.txt",
    );
    writeFileSync(linkedStashUntracked, "linked worktree stash untracked\n");
    const linkedStashPush = runSandboxedGitAsFixture([
      "-C",
      stashLinkedWorktree,
      "stash",
      "push",
      "--include-untracked",
      "-m",
      "synthetic linked worktree stash",
    ]);
    assert.equal(linkedStashPush.status, 0, linkedStashPush.stderr);
    assert.equal(
      readFileSync(path.join(stashLinkedWorktree, "sample.txt"), "utf8"),
      "synthetic git payload\n",
    );
    assert.equal(existsSync(linkedStashUntracked), false);
    const linkedStashApply = runSandboxedGitAsFixture([
      "-C",
      stashLinkedWorktree,
      "stash",
      "apply",
      "--index",
    ]);
    assert.equal(linkedStashApply.status, 0, linkedStashApply.stderr);
    assert.equal(
      readFileSync(path.join(stashLinkedWorktree, "sample.txt"), "utf8"),
      "linked worktree stash edit\n",
    );
    assert.equal(
      readFileSync(linkedStashUntracked, "utf8"),
      "linked worktree stash untracked\n",
    );
    const linkedStashDrop = runSandboxedGitAsFixture([
      "-C",
      stashLinkedWorktree,
      "stash",
      "drop",
    ]);
    assert.equal(linkedStashDrop.status, 0, linkedStashDrop.stderr);
    const linkedStashList = runSandboxedGit([
      "-C",
      stashLinkedWorktree,
      "stash",
      "list",
    ]);
    assert.equal(linkedStashList.status, 0, linkedStashList.stderr);
    assert.equal(linkedStashList.stdout, "");

    const checkoutWorktree = path.join(gitProject, "checkout-worktree");
    const checkoutAdd = runSandboxedGitAsFixture([
      "worktree",
      "add",
      "-b",
      "worktree-checkout-topic",
      checkoutWorktree,
      "HEAD",
    ]);
    assert.equal(checkoutAdd.status, 0, checkoutAdd.stderr);
    const checkoutSwitch = runSandboxedGitAsFixture([
      "-C",
      checkoutWorktree,
      "switch",
      "--orphan",
      "worktree-checkout-orphan",
    ]);
    assert.equal(checkoutSwitch.status, 0, checkoutSwitch.stderr);
    const checkoutBranch = runSandboxedGit([
      "-C",
      checkoutWorktree,
      "branch",
      "--show-current",
    ]);
    assert.equal(checkoutBranch.status, 0, checkoutBranch.stderr);
    assert.equal(checkoutBranch.stdout.trim(), "worktree-checkout-orphan");
    const checkoutSwitchBack = runSandboxedGitAsFixture([
      "-C",
      checkoutWorktree,
      "switch",
      "worktree-checkout-topic",
    ]);
    assert.equal(checkoutSwitchBack.status, 0, checkoutSwitchBack.stderr);
    const checkoutHead = spawnSync(gitExecutable, ["rev-parse", "HEAD"], {
      cwd: checkoutWorktree,
      env: { ...process.env, ...gitEnvironment },
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(checkoutHead.status, 0, checkoutHead.stderr);
    assert.equal(checkoutHead.stdout.trim(), readGitHead());

    const bisectWorktree = path.join(gitProject, "bisect-worktree");
    const bisectAdd = runSandboxedGitAsFixture([
      "worktree",
      "add",
      "-b",
      "worktree-bisect-topic",
      bisectWorktree,
      "HEAD",
    ]);
    assert.equal(bisectAdd.status, 0, bisectAdd.stderr);
    const originalBisectHead = spawnSync(gitExecutable, ["rev-parse", "HEAD"], {
      cwd: bisectWorktree,
      env: { ...process.env, ...gitEnvironment },
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(originalBisectHead.status, 0, originalBisectHead.stderr);
    const bisectStart = runSandboxedGit([
      "-C",
      bisectWorktree,
      "bisect",
      "start",
      originalBisectHead.stdout.trim(),
      "HEAD^",
    ]);
    assert.equal(bisectStart.status, 0, bisectStart.stderr);
    const bisectStatus = spawnSync(gitExecutable, ["bisect", "log"], {
      cwd: bisectWorktree,
      env: { ...process.env, ...gitEnvironment },
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(bisectStatus.status, 0, bisectStatus.stderr);
    assert.match(bisectStatus.stdout, /^git bisect start /m);
    const bisectReset = runSandboxedGit([
      "-C",
      bisectWorktree,
      "bisect",
      "reset",
    ]);
    assert.equal(bisectReset.status, 0, bisectReset.stderr);
    const bisectResetHead = spawnSync(gitExecutable, ["rev-parse", "HEAD"], {
      cwd: bisectWorktree,
      env: { ...process.env, ...gitEnvironment },
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(bisectResetHead.status, 0, bisectResetHead.stderr);
    assert.equal(
      bisectResetHead.stdout.trim(),
      originalBisectHead.stdout.trim(),
    );
    assert.equal(
      existsSync(path.join(bisectWorktree, ".git", "BISECT_LOG")),
      false,
    );

    const conflictStashWorktree = path.join(
      gitProject,
      "conflict-stash-linked-worktree",
    );
    const conflictStashAdd = runSandboxedGitAsFixture([
      "worktree",
      "add",
      "-b",
      "worktree-conflict-stash-topic",
      conflictStashWorktree,
      "HEAD",
    ]);
    assert.equal(conflictStashAdd.status, 0, conflictStashAdd.stderr);
    writeFileSync(
      path.join(conflictStashWorktree, "sample.txt"),
      "linked worktree conflict source edit\n",
    );
    const conflictStashPush = runSandboxedGitAsFixture([
      "-C",
      conflictStashWorktree,
      "stash",
      "push",
      "-m",
      "synthetic linked worktree conflict stash",
    ]);
    assert.equal(conflictStashPush.status, 0, conflictStashPush.stderr);
    const conflictSourceEdit = runSandboxedGitAsFixture([
      "-C",
      conflictStashWorktree,
      "commit",
      "--allow-empty",
      "-m",
      "synthetic conflict source commit",
    ]);
    assert.equal(conflictSourceEdit.status, 0, conflictSourceEdit.stderr);
    writeFileSync(
      path.join(conflictStashWorktree, "sample.txt"),
      "linked worktree conflict head edit\n",
    );
    const conflictHeadCommit = runSandboxedGitAsFixture([
      "-C",
      conflictStashWorktree,
      "commit",
      "-am",
      "synthetic conflict head commit",
    ]);
    assert.equal(conflictHeadCommit.status, 0, conflictHeadCommit.stderr);
    const conflictStashApply = runSandboxedGitAsFixture([
      "-C",
      conflictStashWorktree,
      "stash",
      "apply",
    ]);
    assert.notEqual(conflictStashApply.status, 0);
    const conflictApplyStatus = runSandboxedGit([
      "-C",
      conflictStashWorktree,
      "status",
      "--short",
    ]);
    assert.equal(conflictApplyStatus.status, 0, conflictApplyStatus.stderr);
    assert.match(conflictApplyStatus.stdout, /^UU sample\.txt$/m);
    const conflictRestore = runSandboxedGitAsFixture([
      "-C",
      conflictStashWorktree,
      "restore",
      "--source=stash@{0}",
      "--staged",
      "--worktree",
      "--",
      "sample.txt",
    ]);
    assert.equal(conflictRestore.status, 0, conflictRestore.stderr);
    const conflictStashDrop = runSandboxedGitAsFixture([
      "-C",
      conflictStashWorktree,
      "stash",
      "drop",
    ]);
    assert.equal(conflictStashDrop.status, 0, conflictStashDrop.stderr);
    const conflictStashList = runSandboxedGit([
      "-C",
      conflictStashWorktree,
      "stash",
      "list",
    ]);
    assert.equal(conflictStashList.status, 0, conflictStashList.stderr);
    assert.equal(conflictStashList.stdout, "");
    const conflictResolve = runSandboxedGitAsFixture([
      "-C",
      conflictStashWorktree,
      "checkout",
      "--ours",
      "--",
      "sample.txt",
    ]);
    assert.equal(conflictResolve.status, 0, conflictResolve.stderr);

    const prunableWorktree = path.join(gitProject, "prunable-worktree");
    const addPrunableWorktree = runSandboxedGitAsFixture([
      "worktree",
      "add",
      "-b",
      "worktree-prune-topic",
      prunableWorktree,
      "HEAD",
    ]);
    assert.equal(addPrunableWorktree.status, 0, addPrunableWorktree.stderr);
    rmSync(prunableWorktree, { recursive: true, force: true });
    const staleWorktreeList = runSandboxedGit([
      "worktree",
      "list",
      "--porcelain",
    ]);
    assert.equal(staleWorktreeList.status, 0, staleWorktreeList.stderr);
    assert.match(
      staleWorktreeList.stdout,
      new RegExp(`^worktree ${prunableWorktree}$`, "m"),
    );
    assert.match(staleWorktreeList.stdout, /^prunable /m);
    const pruneStaleWorktree = runSandboxedGit(["worktree", "prune"]);
    assert.equal(pruneStaleWorktree.status, 0, pruneStaleWorktree.stderr);
    const prunedWorktreeList = runSandboxedGit([
      "worktree",
      "list",
      "--porcelain",
    ]);
    assert.equal(prunedWorktreeList.status, 0, prunedWorktreeList.stderr);
    assert.doesNotMatch(
      prunedWorktreeList.stdout,
      new RegExp(`^worktree ${prunableWorktree}$`, "m"),
    );
    const prunedBranch = runSandboxedGit([
      "branch",
      "--list",
      "worktree-prune-topic",
    ]);
    assert.equal(prunedBranch.status, 0, prunedBranch.stderr);
    assert.equal(prunedBranch.stdout.trim(), "worktree-prune-topic");

    writeFileSync(
      path.join(gitProject, "sample.txt"),
      "modified worktree data\n",
    );
    unlinkSync(externalLink);
    const gitDiff = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: ["diff", "--no-ext-diff", "--no-color", "--", "sample.txt"],
      cwd: gitProject,
      readPaths: [gitBin, gitCore, gitShare],
    });
    try {
      const result = spawnSync(gitDiff.command, gitDiff.args, {
        cwd: gitDiff.cwd,
        env: { ...gitDiff.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 0, result.stderr);
      assert.match(
        result.stdout,
        /^diff --git a\/sample\.txt b\/sample\.txt\n/,
      );
      assert.match(
        result.stdout,
        /^-synthetic git payload\n\+modified worktree data$/m,
      );
    } finally {
      gitDiff.cleanup();
    }
    const gitRestore = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: [
        "restore",
        "--source=HEAD",
        "--worktree",
        "--",
        "sample.txt",
        "external-link",
      ],
      cwd: gitProject,
      readPaths: [gitBin, gitCore, gitShare],
    });
    try {
      const result = spawnSync(gitRestore.command, gitRestore.args, {
        cwd: gitRestore.cwd,
        env: { ...gitRestore.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 0, result.stderr);
    } finally {
      gitRestore.cleanup();
    }
    assert.equal(
      readFileSync(path.join(gitProject, "sample.txt"), "utf8"),
      "synthetic git payload\n",
    );
    assert.equal(readlinkSync(externalLink), "../outside-project-secret.txt");
    assert.equal(
      readFileSync(externalTarget, "utf8"),
      "synthetic outside target contents\n",
    );

    writeFileSync(
      path.join(gitProject, "sample.txt"),
      "stashed tracked edit\n",
    );
    const stashUntracked = path.join(gitProject, "stash-untracked.txt");
    writeFileSync(stashUntracked, "stashed untracked content\n");
    const stashPush = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: [
        "stash",
        "push",
        "--include-untracked",
        "-m",
        "synthetic stash roundtrip",
      ],
      cwd: gitProject,
      readPaths: [gitBin, gitCore, gitShare],
    });
    try {
      const result = spawnSync(stashPush.command, stashPush.args, {
        cwd: stashPush.cwd,
        env: { ...stashPush.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 0, result.stderr);
    } finally {
      stashPush.cleanup();
    }
    assert.equal(
      readFileSync(path.join(gitProject, "sample.txt"), "utf8"),
      "synthetic git payload\n",
    );
    assert.equal(existsSync(stashUntracked), false);

    const stashApply = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: ["stash", "apply", "--index", "stash@{0}"],
      cwd: gitProject,
      readPaths: [gitBin, gitCore, gitShare],
    });
    try {
      const result = spawnSync(stashApply.command, stashApply.args, {
        cwd: stashApply.cwd,
        env: { ...stashApply.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 0, result.stderr);
    } finally {
      stashApply.cleanup();
    }
    assert.equal(
      readFileSync(path.join(gitProject, "sample.txt"), "utf8"),
      "stashed tracked edit\n",
    );
    assert.equal(
      readFileSync(stashUntracked, "utf8"),
      "stashed untracked content\n",
    );

    const stashDrop = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: ["stash", "drop", "stash@{0}"],
      cwd: gitProject,
      readPaths: [gitBin, gitCore, gitShare],
    });
    try {
      const result = spawnSync(stashDrop.command, stashDrop.args, {
        cwd: stashDrop.cwd,
        env: { ...stashDrop.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 0, result.stderr);
    } finally {
      stashDrop.cleanup();
    }
    const stashList = spawnSync(gitExecutable, ["stash", "list"], {
      cwd: gitProject,
      env: { ...process.env, ...gitEnvironment },
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(stashList.status, 0, stashList.stderr);
    assert.equal(stashList.stdout, "");

    const bundlePath = path.join(gitProject, "synthetic.bundle");
    const bundleCreate = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: ["bundle", "create", bundlePath, "--all"],
      cwd: gitProject,
      readPaths: [gitBin, gitCore, gitShare],
    });
    try {
      const result = spawnSync(bundleCreate.command, bundleCreate.args, {
        cwd: bundleCreate.cwd,
        env: { ...bundleCreate.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 0, result.stderr);
      assert.ok(existsSync(bundlePath));
    } finally {
      bundleCreate.cleanup();
    }
    const bundleVerify = spawnSync(
      gitExecutable,
      ["bundle", "verify", bundlePath],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(bundleVerify.status, 0, bundleVerify.stderr);

    const receiverProject = path.join(root, "receiver");
    mkdirSync(receiverProject);
    const receiverInit = spawnSync(gitExecutable, ["init", "--quiet"], {
      cwd: receiverProject,
      env: { ...process.env, ...gitEnvironment },
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(receiverInit.status, 0, receiverInit.stderr);
    const bundleFetch = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: ["fetch", "--no-tags", bundlePath, "HEAD:refs/heads/from-bundle"],
      cwd: receiverProject,
      readPaths: [gitBin, gitCore, gitShare, gitProject],
    });
    try {
      const result = spawnSync(bundleFetch.command, bundleFetch.args, {
        cwd: bundleFetch.cwd,
        env: { ...bundleFetch.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 0, result.stderr);
    } finally {
      bundleFetch.cleanup();
    }
    const receivedSubject = spawnSync(
      gitExecutable,
      ["log", "-1", "--format=%s", "refs/heads/from-bundle"],
      {
        cwd: receiverProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(receivedSubject.status, 0, receivedSubject.stderr);
    assert.equal(receivedSubject.stdout.trim(), "synthetic topic change");

    const helperPath = path.join(
      gitProject,
      ".git",
      "agentsecret-credential-helper",
    );
    const helperLog = path.join(gitProject, ".git", "agentsecret-helper.log");
    const helperSecret = "synthetic-git-helper-only-value";
    writeFileSync(
      helperPath,
      `#!/bin/sh
case "$1" in
  get)
    input="$(cat)"
    case "$input" in *protocol=https*host=example.invalid*) ;; *) exit 2 ;; esac
    printf 'get\\n' >> .git/agentsecret-helper.log
    printf 'protocol=https\\nhost=example.invalid\\nusername=fixture-user\\npassword=${helperSecret}\\n\\n'
    ;;
  store)
    input="$(cat)"
    case "$input" in *password=${helperSecret}*) ;; *) exit 3 ;; esac
    printf 'store\\n' >> .git/agentsecret-helper.log
    ;;
  *) exit 4 ;;
esac
`,
      { mode: 0o700 },
    );
    const shellQuotedHelper = `'${helperPath.replaceAll("'", "'\\''")}'`;
    const helperConfig = spawnSync(
      gitExecutable,
      ["config", "--local", "credential.helper", `!${shellQuotedHelper}`],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(helperConfig.status, 0, helperConfig.stderr);
    const credentialPipeline = [
      "printf 'protocol=https\\nhost=example.invalid\\n\\n'",
      `| '${gitExecutable}' credential fill`,
      `| '${gitExecutable}' credential approve`,
    ].join(" ");
    const credentialUse = unit.prepareMacSandbox({
      executable: "/bin/sh",
      args: ["-c", credentialPipeline],
      cwd: gitProject,
      readPaths: [gitBin, gitCore, gitShare],
    });
    try {
      const result = spawnSync(credentialUse.command, credentialUse.args, {
        cwd: credentialUse.cwd,
        env: { ...credentialUse.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, "");
      assert.equal(result.stdout.includes(helperSecret), false);
      assert.equal(result.stderr.includes(helperSecret), false);
    } finally {
      credentialUse.cleanup();
    }
    assert.equal(readFileSync(helperLog, "utf8"), "get\nstore\n");

    const remoteRoot = path.join(root, "remote");
    const remoteGit = path.join(remoteRoot, "repository.git");
    mkdirSync(remoteRoot);
    const remoteInit = spawnSync(
      gitExecutable,
      ["init", "--bare", "--quiet", "--initial-branch=main", remoteGit],
      {
        cwd: root,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(remoteInit.status, 0, remoteInit.stderr);
    const localPush = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: ["push", "--quiet", remoteGit, "HEAD:refs/heads/main"],
      cwd: gitProject,
      readPaths: [gitBin, gitCore, gitShare, remoteGit],
      writePaths: [remoteGit],
    });
    try {
      const result = spawnSync(localPush.command, localPush.args, {
        cwd: localPush.cwd,
        env: { ...localPush.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 0, result.stderr);
    } finally {
      localPush.cleanup();
    }
    const pushedSubject = spawnSync(
      gitExecutable,
      ["--git-dir", remoteGit, "log", "-1", "--format=%s", "refs/heads/main"],
      {
        cwd: root,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(pushedSubject.status, 0, pushedSubject.stderr);
    assert.equal(pushedSubject.stdout.trim(), "synthetic topic change");

    const cloneParent = path.join(root, "clone parent with spaces");
    const clonedProject = path.join(cloneParent, "cloned repository");
    mkdirSync(clonedProject, { recursive: true });
    const cloneInit = spawnSync(
      gitExecutable,
      ["init", "--quiet", "--initial-branch=main"],
      {
        cwd: clonedProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(cloneInit.status, 0, cloneInit.stderr);
    const remoteUrl = pathToFileURL(remoteGit).href;
    const remoteAdd = spawnSync(
      gitExecutable,
      ["remote", "add", "origin", remoteUrl],
      {
        cwd: clonedProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(remoteAdd.status, 0, remoteAdd.stderr);
    const sandboxedFetch = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: ["fetch", "--quiet", "--no-tags", "origin"],
      cwd: clonedProject,
      readPaths: [gitBin, gitCore, gitShare, remoteGit],
    });
    try {
      const result = spawnSync(sandboxedFetch.command, sandboxedFetch.args, {
        cwd: sandboxedFetch.cwd,
        env: { ...sandboxedFetch.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, "");
    } finally {
      sandboxedFetch.cleanup();
    }
    const sandboxedCheckout = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: ["checkout", "--quiet", "--track", "-B", "main", "origin/main"],
      cwd: clonedProject,
      readPaths: [gitBin, gitCore, gitShare],
    });
    try {
      const result = spawnSync(
        sandboxedCheckout.command,
        sandboxedCheckout.args,
        {
          cwd: sandboxedCheckout.cwd,
          env: { ...sandboxedCheckout.env, ...gitEnvironment },
          encoding: "utf8",
          timeout: 10_000,
        },
      );
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, "");
    } finally {
      sandboxedCheckout.cleanup();
    }
    const readCheckoutGit = (args) => {
      const result = spawnSync(gitExecutable, args, {
        cwd: clonedProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      });
      assert.equal(result.status, 0, result.stderr);
      return result.stdout;
    };
    assert.equal(
      readCheckoutGit(["status", "--porcelain=v1", "--untracked-files=all"]),
      "",
    );
    assert.equal(
      readCheckoutGit(["ls-files"]),
      "cherry-pick.txt\nexternal-link\nsample.txt\n",
    );
    assert.equal(
      readCheckoutGit(["remote", "get-url", "origin"]).trim(),
      remoteUrl,
    );
    assert.equal(
      readCheckoutGit(["config", "branch.main.remote"]).trim(),
      "origin",
    );
    assert.equal(
      readCheckoutGit(["config", "branch.main.merge"]).trim(),
      "refs/heads/main",
    );
    const clonedBranch = spawnSync(
      gitExecutable,
      ["symbolic-ref", "--short", "HEAD"],
      {
        cwd: clonedProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(clonedBranch.status, 0, clonedBranch.stderr);
    assert.equal(clonedBranch.stdout.trim(), "main");
    const clonedSubject = spawnSync(
      gitExecutable,
      ["log", "-1", "--format=%s", "HEAD"],
      {
        cwd: clonedProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(clonedSubject.status, 0, clonedSubject.stderr);
    assert.equal(clonedSubject.stdout.trim(), "synthetic topic change");
    assert.equal(
      readFileSync(path.join(clonedProject, "sample.txt"), "utf8"),
      "synthetic git payload\n",
    );
    assert.equal(
      readlinkSync(path.join(clonedProject, "external-link")),
      "../outside-project-secret.txt",
    );

    // sandboxed git clone file:// into a space-containing path.
    // Clone canonicalizes the remote URL path component-by-component, which
    // requires literal metadata access to ancestor directories above every
    // granted subtree. This acceptance proves the ancestor-metadata grant
    // enables clone without exposing directory entries or outside-file data.
    const w40Parent = path.join(root, "w40 clone parent with spaces");
    const w40Dest = path.join(w40Parent, "w40 cloned repository");
    mkdirSync(w40Parent, { recursive: true });
    const w40Clone = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: ["clone", "--quiet", remoteUrl, "w40 cloned repository"],
      cwd: w40Parent,
      readPaths: [remoteGit],
    });
    try {
      const result = spawnSync(w40Clone.command, w40Clone.args, {
        cwd: w40Clone.cwd,
        env: { ...w40Clone.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, "");
    } finally {
      w40Clone.cleanup();
    }
    assert.equal(existsSync(path.join(w40Dest, ".git")), true);
    assert.equal(
      readFileSync(path.join(w40Dest, "sample.txt"), "utf8"),
      "synthetic git payload\n",
    );
    assert.equal(
      readlinkSync(path.join(w40Dest, "external-link")),
      "../outside-project-secret.txt",
    );
    {
      const w40Status = spawnSync(
        gitExecutable,
        ["status", "--porcelain=v1", "--untracked-files=all"],
        {
          cwd: w40Dest,
          env: { ...process.env, ...gitEnvironment },
          encoding: "utf8",
          timeout: 5000,
        },
      );
      assert.equal(w40Status.status, 0, w40Status.stderr);
      assert.equal(w40Status.stdout, "");
    }
    {
      const w40Origin = spawnSync(
        gitExecutable,
        ["remote", "get-url", "origin"],
        {
          cwd: w40Dest,
          env: { ...process.env, ...gitEnvironment },
          encoding: "utf8",
          timeout: 5000,
        },
      );
      assert.equal(w40Origin.status, 0, w40Origin.stderr);
      assert.equal(w40Origin.stdout.trim(), remoteUrl);
    }
    // Outside-file containment: ancestor metadata access must not let a
    // sandboxed child read a sibling file outside every granted subtree.
    {
      const w40Outside = path.join(root, "w40 outside secret.txt");
      writeFileSync(w40Outside, "synthetic w40 outside contents\n");
      const w40Cat = unit.prepareMacSandbox({
        executable: "/bin/cat",
        args: [w40Outside],
        cwd: w40Parent,
        readPaths: [remoteGit],
      });
      try {
        const result = spawnSync(w40Cat.command, w40Cat.args, {
          cwd: w40Cat.cwd,
          env: w40Cat.env,
          encoding: "utf8",
          timeout: 10_000,
        });
        assert.notEqual(result.status, 0);
        assert.equal(result.stdout, "");
        assert.doesNotMatch(result.stderr, /synthetic w40 outside contents/);
      } finally {
        w40Cat.cleanup();
      }
      const w40Stat = unit.prepareMacSandbox({
        executable: "/usr/bin/stat",
        args: ["-f", "%N %z", w40Outside],
        cwd: w40Parent,
        readPaths: [remoteGit],
      });
      try {
        const result = spawnSync(w40Stat.command, w40Stat.args, {
          cwd: w40Stat.cwd,
          env: w40Stat.env,
          encoding: "utf8",
          timeout: 10_000,
        });
        assert.notEqual(result.status, 0);
        assert.equal(result.stdout, "");
        assert.match(result.stderr, /Operation not permitted/);
      } finally {
        w40Stat.cleanup();
      }
    }
    // Ancestor grants must not expose directory entries, either. `ls` on
    // an ancestor needs directory-read access, which should remain denied.
    {
      const w40List = unit.prepareMacSandbox({
        executable: "/bin/ls",
        args: ["-1", "/private"],
        cwd: w40Parent,
        readPaths: [remoteGit],
      });
      try {
        const result = spawnSync(w40List.command, w40List.args, {
          cwd: w40List.cwd,
          env: w40List.env,
          encoding: "utf8",
          timeout: 10_000,
        });
        assert.notEqual(result.status, 0);
        assert.equal(result.stdout, "");
        assert.match(result.stderr, /Operation not permitted/);
      } finally {
        w40List.cleanup();
      }
    }

    const preCommitHook = path.join(gitProject, ".git", "hooks", "pre-commit");
    mkdirSync(path.dirname(preCommitHook), { recursive: true });
    writeFileSync(
      preCommitHook,
      `#!/bin/sh
if /usr/bin/touch ../outside-hook-write 2>/dev/null; then exit 91; fi
if /bin/cat '${externalTarget.replaceAll("'", "'\\''")}' >/dev/null 2>&1; then
  /usr/bin/touch .git/outside-read-succeeded
else
  printf 'outside read denied\\n' > .git/outside-read-denied
fi
printf 'synthetic hook ran\\n' > .git/pre-commit-ran
`,
    );
    chmodSync(preCommitHook, 0o700);
    const hookedCommit = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: [
        "-c",
        "user.name=AgentSecret Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--allow-empty",
        "--quiet",
        "-m",
        "synthetic hooked commit",
      ],
      cwd: gitProject,
      readPaths: [gitBin, gitCore, gitShare],
    });
    try {
      const result = spawnSync(hookedCommit.command, hookedCommit.args, {
        cwd: hookedCommit.cwd,
        env: { ...hookedCommit.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 0, result.stderr);
    } finally {
      hookedCommit.cleanup();
    }
    assert.equal(
      readFileSync(path.join(gitProject, ".git", "pre-commit-ran"), "utf8"),
      "synthetic hook ran\n",
    );
    assert.equal(existsSync(path.join(root, "outside-hook-write")), false);
    assert.equal(
      existsSync(path.join(gitProject, ".git", "outside-read-succeeded")),
      false,
    );
    assert.equal(
      readFileSync(
        path.join(gitProject, ".git", "outside-read-denied"),
        "utf8",
      ),
      "outside read denied\n",
    );

    writeFileSync(preCommitHook, "#!/bin/sh\nexit 73\n");
    const refusedCommit = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: [
        "-c",
        "user.name=AgentSecret Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--allow-empty",
        "--quiet",
        "-m",
        "must not commit after hook refusal",
      ],
      cwd: gitProject,
      readPaths: [gitBin, gitCore, gitShare],
    });
    try {
      const result = spawnSync(refusedCommit.command, refusedCommit.args, {
        cwd: refusedCommit.cwd,
        env: { ...refusedCommit.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.notEqual(result.status, 0);
      assert.equal(result.stdout, "");
    } finally {
      refusedCommit.cleanup();
    }
    const refusedSubject = spawnSync(
      gitExecutable,
      ["log", "-1", "--format=%s"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(refusedSubject.status, 0, refusedSubject.stderr);
    assert.equal(refusedSubject.stdout.trim(), "synthetic hooked commit");

    const hookChildPidFile = path.join(gitProject, ".git", "hook-child.pid");
    writeFileSync(
      preCommitHook,
      "#!/bin/sh\n/bin/sleep 30 &\necho $! > .git/hook-child.pid\nwait\n",
    );
    const cancelController = new AbortController();
    const canceledCommit = unit.runMacSandbox(
      {
        executable: "/usr/bin/git",
        args: [
          "-c",
          "user.name=AgentSecret Fixture",
          "-c",
          "user.email=fixture@example.invalid",
          "-c",
          "commit.gpgsign=false",
          "commit",
          "--allow-empty",
          "--quiet",
          "-m",
          "must not commit after cancellation",
        ],
        cwd: gitProject,
        readPaths: [gitBin, gitCore, gitShare],
      },
      cancelController.signal,
      "ignore",
    );
    let hookChildPid = 0;
    const hookPidDeadline = Date.now() + 3000;
    while (!hookChildPid && Date.now() < hookPidDeadline) {
      try {
        const candidate = readFileSync(hookChildPidFile, "utf8").trim();
        if (/^\d+$/.test(candidate)) {
          const pid = Number(candidate);
          if (Number.isSafeInteger(pid) && pid > 0) hookChildPid = pid;
        }
      } catch {}
      if (!hookChildPid)
        await new Promise((resolve) => setTimeout(resolve, 10));
    }
    cancelController.abort();
    const canceledStatus = await canceledCommit;
    assert.equal(existsSync(hookChildPidFile), true);
    assert.equal(canceledStatus, 130);
    assert.ok(hookChildPid > 0, "hook child PID witness was not fully written");
    assert.throws(() => process.kill(hookChildPid, 0), { code: "ESRCH" });
    const finalSubject = spawnSync(
      gitExecutable,
      ["log", "-1", "--format=%s"],
      {
        cwd: gitProject,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(finalSubject.status, 0, finalSubject.stderr);
    assert.equal(finalSubject.stdout.trim(), "synthetic hooked commit");
  },
);

test(
  "macOS Seatbelt Git recovers from merge and cherry-pick conflicts",
  { skip: process.platform !== "darwin" },
  (t) => {
    const root = mkdtempSync(
      path.join(tmpdir(), "agentsecret-git-merge-test-"),
    );
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const developerDir = spawnSync("/usr/bin/xcode-select", ["-p"], {
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(developerDir.status, 0, developerDir.stderr);
    const developerPath = developerDir.stdout.trim();
    const gitBin = path.join(developerPath, "usr/bin");
    const gitExecutable = path.join(gitBin, "git");
    const gitCore = path.join(developerPath, "usr/libexec/git-core");
    const gitShare = path.join(developerPath, "usr/share/git-core");
    const project = path.join(root, "project");
    mkdirSync(project);
    const gitEnvironment = {
      GIT_EXEC_PATH: gitCore,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_TEMPLATE_DIR: "/dev/null",
    };
    const hostGit = (args) =>
      spawnSync(gitExecutable, args, {
        cwd: project,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      });
    const runHostGit = (args) => {
      const result = hostGit(args);
      assert.equal(result.status, 0, result.stderr);
      return result;
    };
    runHostGit(["init", "--quiet", "--initial-branch=main"]);
    runHostGit(["config", "user.name", "AgentSecret Fixture"]);
    runHostGit(["config", "user.email", "fixture@example.invalid"]);
    const conflictFile = path.join(project, "conflict.txt");
    writeFileSync(conflictFile, "base\n");
    runHostGit(["add", "conflict.txt"]);
    runHostGit(["commit", "--quiet", "-m", "base"]);
    const baseCommit = runHostGit(["rev-parse", "HEAD"]).stdout.trim();
    runHostGit(["branch", "side"]);
    runHostGit(["checkout", "--quiet", "side"]);
    writeFileSync(conflictFile, "side change\n");
    runHostGit(["commit", "--quiet", "-am", "side change"]);
    runHostGit(["checkout", "--quiet", "main"]);
    writeFileSync(conflictFile, "main change\n");
    runHostGit(["commit", "--quiet", "-am", "main change"]);

    const merge = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: ["merge", "--no-edit", "side"],
      cwd: project,
      readPaths: [gitBin, gitCore, gitShare],
    });
    try {
      const result = spawnSync(merge.command, merge.args, {
        cwd: merge.cwd,
        env: { ...merge.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 1, result.stderr);
      assert.match(result.stdout + result.stderr, /CONFLICT/);
    } finally {
      merge.cleanup();
    }
    assert.match(readFileSync(conflictFile, "utf8"), /^<<<<<<< HEAD/m);
    const conflictedStatus = runHostGit(["status", "--short"]);
    assert.equal(conflictedStatus.stdout, "UU conflict.txt\n");

    const abort = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: ["merge", "--abort"],
      cwd: project,
      readPaths: [gitBin, gitCore, gitShare],
    });
    try {
      const result = spawnSync(abort.command, abort.args, {
        cwd: abort.cwd,
        env: { ...abort.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 0, result.stderr);
    } finally {
      abort.cleanup();
    }
    assert.equal(readFileSync(conflictFile, "utf8"), "main change\n");
    assert.equal(runHostGit(["status", "--porcelain"]).stdout, "");
    assert.equal(runHostGit(["branch", "--show-current"]).stdout, "main\n");

    runHostGit(["branch", "cherry-topic", baseCommit]);
    runHostGit(["checkout", "--quiet", "cherry-topic"]);
    writeFileSync(conflictFile, "topic change\n");
    runHostGit(["commit", "--quiet", "-am", "topic change"]);
    runHostGit(["checkout", "--quiet", "main"]);

    const cherryPick = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: ["cherry-pick", "cherry-topic"],
      cwd: project,
      readPaths: [gitBin, gitCore, gitShare],
    });
    try {
      const result = spawnSync(cherryPick.command, cherryPick.args, {
        cwd: cherryPick.cwd,
        env: { ...cherryPick.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 1, result.stderr);
      assert.match(result.stdout + result.stderr, /CONFLICT/);
    } finally {
      cherryPick.cleanup();
    }
    assert.match(readFileSync(conflictFile, "utf8"), /^<<<<<<< HEAD/m);
    assert.equal(runHostGit(["status", "--short"]).stdout, "UU conflict.txt\n");

    const cherryPickAbort = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: ["cherry-pick", "--abort"],
      cwd: project,
      readPaths: [gitBin, gitCore, gitShare],
    });
    try {
      const result = spawnSync(cherryPickAbort.command, cherryPickAbort.args, {
        cwd: cherryPickAbort.cwd,
        env: { ...cherryPickAbort.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.status, 0, result.stderr);
    } finally {
      cherryPickAbort.cleanup();
    }
    assert.equal(readFileSync(conflictFile, "utf8"), "main change\n");
    assert.equal(runHostGit(["status", "--porcelain"]).stdout, "");
    assert.equal(runHostGit(["branch", "--show-current"]).stdout, "main\n");
  },
);

test(
  "macOS Seatbelt Git cannot read a config include outside the project",
  { skip: process.platform !== "darwin" },
  (t) => {
    const root = mkdtempSync(
      path.join(tmpdir(), "agentsecret-git-config-test-"),
    );
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const developerDir = spawnSync("/usr/bin/xcode-select", ["-p"], {
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(developerDir.status, 0, developerDir.stderr);
    const developerPath = developerDir.stdout.trim();
    const gitBin = path.join(developerPath, "usr/bin");
    const gitExecutable = path.join(gitBin, "git");
    const gitCore = path.join(developerPath, "usr/libexec/git-core");
    const gitShare = path.join(developerPath, "usr/share/git-core");
    const project = path.join(root, "project");
    const outsideConfig = path.join(root, "outside.gitconfig");
    mkdirSync(project);
    const gitEnvironment = {
      GIT_EXEC_PATH: gitCore,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_TEMPLATE_DIR: "/dev/null",
    };
    const init = spawnSync(gitExecutable, ["init", "--quiet"], {
      cwd: project,
      env: { ...process.env, ...gitEnvironment },
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(init.status, 0, init.stderr);
    const privateCanary = "outside-project-git-config-canary";
    writeFileSync(outsideConfig, `[agentsecret]\ncanary = ${privateCanary}\n`);
    const localConfig = path.join(project, ".git", "config");
    writeFileSync(
      localConfig,
      `${readFileSync(localConfig, "utf8")}\n[include]\npath = ${outsideConfig}\n`,
    );
    const hostRead = spawnSync(
      gitExecutable,
      ["config", "--get", "agentsecret.canary"],
      {
        cwd: project,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(hostRead.status, 0, hostRead.stderr);
    assert.equal(hostRead.stdout, `${privateCanary}\n`);

    const readConfig = unit.prepareMacSandbox({
      executable: "/usr/bin/git",
      args: ["config", "--get", "agentsecret.canary"],
      cwd: project,
      readPaths: [gitBin, gitCore, gitShare],
    });
    try {
      const result = spawnSync(readConfig.command, readConfig.args, {
        cwd: readConfig.cwd,
        env: { ...readConfig.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(result.error, undefined);
      assert.equal(result.signal, null);
      assert.notEqual(
        result.status,
        0,
        "sandboxed Git read a config include outside the project",
      );
      assert.equal(result.stdout, "");
      assert.doesNotMatch(result.stderr, new RegExp(privateCanary));
    } finally {
      readConfig.cleanup();
    }
  },
);

test(
  "macOS Seatbelt Git preserves binary content and Unicode paths across add, commit, diff, and restore",
  { skip: process.platform !== "darwin" },
  (t) => {
    const root = mkdtempSync(
      path.join(tmpdir(), "agentsecret-git-binary-test-"),
    );
    t.after(() => rmSync(root, { recursive: true, force: true }));

    const developerDir = spawnSync("/usr/bin/xcode-select", ["-p"], {
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(developerDir.status, 0, developerDir.stderr);
    const gitBin = path.join(developerDir.stdout.trim(), "usr/bin");
    const gitCore = path.join(
      developerDir.stdout.trim(),
      "usr/libexec/git-core",
    );
    const gitShare = path.join(
      developerDir.stdout.trim(),
      "usr/share/git-core",
    );
    const project = path.join(root, "project");
    mkdirSync(path.join(project, "binary assets"), { recursive: true });
    const relativePath = "binary assets/naïve file.bin";
    const filePath = path.join(project, relativePath);
    const initialBytes = Buffer.from([0x00, 0xff, 0x80, 0x0a, 0x41, 0x00]);
    const changedBytes = Buffer.from([0x00, 0xfe, 0x81, 0x0d, 0x42, 0x00]);
    writeFileSync(filePath, initialBytes);

    const gitEnvironment = {
      GIT_EXEC_PATH: gitCore,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_TEMPLATE_DIR: "/dev/null",
    };
    const git = spawnSync(path.join(gitBin, "git"), ["init", "--quiet"], {
      cwd: project,
      env: { ...process.env, ...gitEnvironment },
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(git.status, 0, git.stderr);

    const runSandboxedGit = (args) => {
      const invocation = unit.prepareMacSandbox({
        executable: "/usr/bin/git",
        args,
        cwd: project,
        readPaths: [gitBin, gitCore, gitShare],
      });
      try {
        const result = spawnSync(invocation.command, invocation.args, {
          cwd: invocation.cwd,
          env: { ...invocation.env, ...gitEnvironment },
          timeout: 10_000,
        });
        assert.ifError(result.error);
        assert.equal(result.status, 0, result.stderr?.toString("utf8"));
        return result;
      } finally {
        invocation.cleanup();
      }
    };

    runSandboxedGit(["add", "--", relativePath]);
    runSandboxedGit([
      "-c",
      "user.name=AgentSecret Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "-c",
      "commit.gpgsign=false",
      "commit",
      "--quiet",
      "-m",
      "binary fixture",
    ]);

    const committedBytes = spawnSync(
      path.join(gitBin, "git"),
      ["show", `HEAD:${relativePath}`],
      {
        cwd: project,
        env: { ...process.env, ...gitEnvironment },
        timeout: 5000,
      },
    );
    assert.equal(
      committedBytes.status,
      0,
      committedBytes.stderr.toString("utf8"),
    );
    assert.deepEqual(committedBytes.stdout, initialBytes);

    writeFileSync(filePath, changedBytes);
    const diff = runSandboxedGit([
      "diff",
      "--binary",
      "--no-ext-diff",
      "--no-color",
      "--",
      relativePath,
    ]);
    const diffText = diff.stdout.toString("utf8");
    assert.match(diffText, /^diff --git /);
    assert.match(diffText, /GIT binary patch/);
    const changedPath = runSandboxedGit([
      "diff",
      "--name-only",
      "-z",
      "--",
      relativePath,
    ]);
    assert.deepEqual(
      changedPath.stdout,
      Buffer.concat([Buffer.from(relativePath), Buffer.from([0])]),
    );

    runSandboxedGit([
      "restore",
      "--source=HEAD",
      "--worktree",
      "--",
      relativePath,
    ]);
    assert.deepEqual(readFileSync(filePath), initialBytes);
  },
);

test(
  "macOS Seatbelt Git preserves executable-mode changes and detects a staged rename",
  { skip: process.platform !== "darwin" },
  (t) => {
    const root = mkdtempSync(path.join(tmpdir(), "agentsecret-git-mode-test-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));

    const developerDir = spawnSync("/usr/bin/xcode-select", ["-p"], {
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(developerDir.status, 0, developerDir.stderr);
    const developerPath = developerDir.stdout.trim();
    const gitBin = path.join(developerPath, "usr/bin");
    const gitCore = path.join(developerPath, "usr/libexec/git-core");
    const gitShare = path.join(developerPath, "usr/share/git-core");
    const project = path.join(root, "project");
    mkdirSync(path.join(project, "tools"), { recursive: true });
    const originalPath = "tools/helper.sh";
    const renamedPath = "tools/renamed helper.sh";
    const originalFile = path.join(project, originalPath);
    const renamedFile = path.join(project, renamedPath);
    const contents = Buffer.from("#!/bin/sh\nprintf 'fixture\\n'\n");
    writeFileSync(originalFile, contents, { mode: 0o644 });

    const gitEnvironment = {
      GIT_EXEC_PATH: gitCore,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_TEMPLATE_DIR: "/dev/null",
    };
    const initialized = spawnSync(
      path.join(gitBin, "git"),
      ["init", "--quiet"],
      {
        cwd: project,
        env: { ...process.env, ...gitEnvironment },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    assert.equal(initialized.status, 0, initialized.stderr);

    const runSandboxedGit = (args) => {
      const invocation = unit.prepareMacSandbox({
        executable: "/usr/bin/git",
        args,
        cwd: project,
        readPaths: [gitBin, gitCore, gitShare],
      });
      try {
        const result = spawnSync(invocation.command, invocation.args, {
          cwd: invocation.cwd,
          env: { ...invocation.env, ...gitEnvironment },
          timeout: 10_000,
        });
        assert.ifError(result.error);
        assert.equal(result.status, 0, result.stderr?.toString("utf8"));
        return result;
      } finally {
        invocation.cleanup();
      }
    };

    runSandboxedGit(["add", "--", originalPath]);
    runSandboxedGit([
      "-c",
      "user.name=AgentSecret Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "-c",
      "commit.gpgsign=false",
      "commit",
      "--quiet",
      "-m",
      "mode and rename fixture",
    ]);
    assert.equal(statSync(originalFile).mode & 0o777, 0o644);

    chmodSync(originalFile, 0o755);
    renameSync(originalFile, renamedFile);
    runSandboxedGit(["add", "--all", "--", "tools"]);

    const summary = runSandboxedGit([
      "diff",
      "--cached",
      "--summary",
      "--find-renames",
      "--",
      "tools",
    ]);
    const summaryText = summary.stdout.toString("utf8");
    assert.match(summaryText, /rename/i);
    assert.match(summaryText, /100644 => 100755/);

    const stagedNames = runSandboxedGit([
      "diff",
      "--cached",
      "--name-status",
      "--find-renames",
      "-z",
      "--",
      "tools",
    ]);
    assert.deepEqual(stagedNames.stdout.toString("utf8").split("\0"), [
      "R100",
      originalPath,
      renamedPath,
      "",
    ]);

    runSandboxedGit([
      "restore",
      "--source=HEAD",
      "--staged",
      "--worktree",
      "--",
      originalPath,
      renamedPath,
    ]);
    assert.equal(existsSync(renamedFile), false);
    assert.deepEqual(readFileSync(originalFile), contents);
    assert.equal(statSync(originalFile).mode & 0o777, 0o644);
  },
);

test(
  "macOS sandbox denies Unix-domain runtime and admin socket connections",
  { skip: process.platform !== "darwin" },
  async (t) => {
    unit.verifyMacSandboxRuntime();
    const root = realpathSync(mkdtempSync(path.join("/tmp", "as-")));
    const clients = new Set();
    let server;
    t.after(async () => {
      for (const client of clients) client.destroy();
      if (server?.listening)
        await new Promise((resolve) => server.close(resolve));
      rmSync(root, { recursive: true, force: true });
    });

    const project = path.join(root, "p");
    mkdirSync(project, { recursive: true });
    const socketPath = path.join(project, "runtime-admin.sock");
    let requests = 0;
    server = createNetServer((socket) => {
      requests++;
      clients.add(socket);
      socket.once("close", () => clients.delete(socket));
      socket.on("data", () => socket.end("synthetic socket response"));
    });
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(socketPath, resolve);
    });

    const runClient = (command, args, options) =>
      new Promise((resolve, reject) => {
        const child = spawn(command, args, {
          cwd: options.cwd,
          env: options.env,
          stdio: ["pipe", "pipe", "pipe"],
        });
        let stdout = "";
        let stderr = "";
        let settled = false;
        const finish = (error, result) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          if (error) reject(error);
          else resolve(result);
        };
        const timer = setTimeout(() => {
          child.kill("SIGKILL");
          finish(new Error(`${command} timed out`));
        }, 5000);
        child.stdout.setEncoding("utf8");
        child.stderr.setEncoding("utf8");
        child.stdout.on("data", (chunk) => (stdout += chunk));
        child.stderr.on("data", (chunk) => (stderr += chunk));
        child.once("error", (error) => finish(error));
        child.once("close", (code, signal) =>
          finish(null, { code, signal, stdout, stderr }),
        );
        child.stdin.end(options.input);
      });
    const args = ["-w", "2", "-U", socketPath];
    const baseline = await runClient("/usr/bin/nc", args, {
      cwd: project,
      input: "synthetic request",
    });
    assert.equal(baseline.code, 0, baseline.stderr);
    assert.equal(baseline.stdout, "synthetic socket response");
    assert.equal(requests, 1);

    const invocation = unit.prepareMacSandbox({
      executable: "/usr/bin/nc",
      args,
      cwd: project,
    });
    try {
      const sandboxed = await runClient(invocation.command, invocation.args, {
        cwd: invocation.cwd,
        env: invocation.env,
        input: "synthetic request",
      });
      assert.notEqual(sandboxed.code, 0, sandboxed.stdout);
      assert.equal(sandboxed.signal, null);
      assert.equal(requests, 1, "the sandbox must not reach the socket");
    } finally {
      invocation.cleanup();
    }
  },
);

test(
  "macOS sandbox drops host proxy, loader, and credential-agent environment variables",
  { skip: process.platform !== "darwin" },
  async (t) => {
    const project = mkdtempSync(path.join(tmpdir(), "agentsecret-env-test-"));
    t.after(() => rmSync(project, { recursive: true, force: true }));
    const hostOnlyNames = [
      "HTTP_PROXY",
      "HTTPS_PROXY",
      "ALL_PROXY",
      "NO_PROXY",
      "http_proxy",
      "https_proxy",
      "all_proxy",
      "no_proxy",
      "NODE_OPTIONS",
      "NODE_PATH",
      "DYLD_INSERT_LIBRARIES",
      "DYLD_LIBRARY_PATH",
      "SSH_AUTH_SOCK",
      "SSH_AGENT_PID",
      "AWS_ACCESS_KEY_ID",
      "AWS_SECRET_ACCESS_KEY",
    ];
    const originalEnvironment = new Map(
      hostOnlyNames.map((name) => [name, process.env[name]]),
    );
    let invocation;
    try {
      for (const name of hostOnlyNames) process.env[name] = `host-only-${name}`;
      invocation = unit.prepareMacSandbox({
        executable: "/bin/echo",
        args: ["synthetic"],
        cwd: project,
      });
      for (const name of hostOnlyNames)
        assert.equal(invocation.env[name], undefined, name);
      assert.equal(invocation.env.HOME, realpathSync(project));
      assert.equal(invocation.env.PATH, "/usr/bin:/bin:/usr/sbin:/sbin");
      assert.ok(invocation.env.TMPDIR);
      assert.ok(
        Object.keys(invocation.env).every((name) =>
          [
            "HOME",
            "PATH",
            "TMPDIR",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "TERM",
          ].includes(name),
        ),
      );
    } finally {
      invocation?.cleanup();
      for (const [name, value] of originalEnvironment) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  },
);

test(
  "macOS runner removes scratch when the sandbox process fails before spawning",
  { skip: process.platform !== "darwin" },
  async (t) => {
    const project = mkdtempSync(path.join(tmpdir(), "agentsecret-spawn-fail-"));
    t.after(() => rmSync(project, { recursive: true, force: true }));
    let scratch;
    const spawnMethod = t.mock.method(
      childProcess,
      "spawn",
      (_command, _args, options) => {
        scratch = options.env.TMPDIR;
        assert.ok(
          existsSync(scratch),
          "scratch exists when spawn is attempted",
        );
        const child = new EventEmitter();
        process.nextTick(() => {
          child.emit(
            "error",
            Object.assign(new Error("synthetic spawn refusal"), {
              code: "EACCES",
            }),
          );
          child.emit("close", null);
        });
        return child;
      },
    );
    syncBuiltinESMExports();
    t.after(() => {
      spawnMethod.mock.restore();
      syncBuiltinESMExports();
    });

    await assert.rejects(
      unit.runMacSandbox(
        { executable: "/bin/echo", args: ["synthetic"], cwd: project },
        new AbortController().signal,
        "ignore",
      ),
      { code: "EACCES" },
    );
    assert.ok(scratch, "test captures the private runner scratch path");
    assert.equal(existsSync(scratch), false);
  },
);

test(
  "macOS runner retains scratch when a pid exists before spawn event and termination is uncertain",
  { skip: process.platform !== "darwin" },
  async (t) => {
    const project = mkdtempSync(path.join(tmpdir(), "agentsecret-pid-race-"));
    let scratch;
    t.after(() => {
      if (scratch) rmSync(scratch, { recursive: true, force: true });
      rmSync(project, { recursive: true, force: true });
    });

    const controller = new AbortController();
    const child = new EventEmitter();
    child.pid = 987654321;
    const spawnMethod = t.mock.method(
      childProcess,
      "spawn",
      (_cmd, _args, options) => {
        scratch = options.env.TMPDIR;
        controller.abort();
        return child;
      },
    );
    const kill = process.kill.bind(process);
    const killMethod = t.mock.method(process, "kill", (pid, signal) => {
      if (pid === -child.pid && signal !== 0)
        throw Object.assign(new Error("termination is not confirmed"), {
          code: "EPERM",
        });
      return kill(pid, signal);
    });
    syncBuiltinESMExports();
    t.after(() => {
      killMethod.mock.restore();
      spawnMethod.mock.restore();
      syncBuiltinESMExports();
    });

    await assert.rejects(
      unit.runMacSandbox(
        { executable: "/bin/echo", args: ["synthetic"], cwd: project },
        controller.signal,
        "ignore",
      ),
      { code: "EPERM" },
    );
    assert.ok(scratch);
    assert.equal(existsSync(scratch), true);
  },
);

test(
  "macOS runner retains scratch when process-group termination cannot be established",
  { skip: process.platform !== "darwin" },
  async (t) => {
    const project = mkdtempSync(
      path.join(tmpdir(), "agentsecret-group-probe-"),
    );
    let scratch;
    t.after(() => {
      if (scratch) rmSync(scratch, { recursive: true, force: true });
      rmSync(project, { recursive: true, force: true });
    });
    const kill = process.kill.bind(process);
    const execFileSync = childProcess.execFileSync.bind(childProcess);
    let probes = 0;
    t.mock.method(process, "kill", (pid, signal) => {
      if (pid < 0 && signal === 0) {
        probes++;
        throw Object.assign(new Error("Process group is inaccessible."), {
          code: "EPERM",
        });
      }
      return kill(pid, signal);
    });
    t.mock.method(childProcess, "execFileSync", (file, ...args) =>
      file === "/bin/ps" ? "invalid inventory" : execFileSync(file, ...args),
    );
    // The command exits before the liveness probe, leaving no real workload.
    await assert.rejects(
      unit.runMacSandbox(
        {
          executable: "/bin/sh",
          args: ["-c", 'printf %s "$TMPDIR" > scratch.txt'],
          cwd: project,
        },
        new AbortController().signal,
        "ignore",
      ),
      { code: "EPERM" },
    );
    assert.ok(probes > 0);
    scratch = readFileSync(path.join(project, "scratch.txt"), "utf8");
    assert.ok(existsSync(scratch), "indeterminate cleanup must retain scratch");
  },
);

test(
  "macOS runner polls an EPERM process group until process inventory confirms exit",
  { skip: process.platform !== "darwin" },
  async (t) => {
    const project = mkdtempSync(path.join(tmpdir(), "agentsecret-group-poll-"));
    const child = new EventEmitter();
    child.pid = 987654321;
    child.kill = () => true;
    let scratch;
    let groupProbes = 0;
    let inventoryCalls = 0;
    const originalKill = process.kill.bind(process);
    const originalExecFileSync = childProcess.execFileSync.bind(childProcess);
    const spawnMethod = t.mock.method(
      childProcess,
      "spawn",
      (_command, _args, options) => {
        scratch = options.env.TMPDIR;
        setImmediate(() => child.emit("close", 0, null));
        return child;
      },
    );
    const killMethod = t.mock.method(process, "kill", (pid, signal) => {
      if (pid === -child.pid && signal === 0) {
        groupProbes++;
        throw Object.assign(new Error("process group probe denied"), {
          code: "EPERM",
        });
      }
      if (pid === -child.pid) return true;
      return originalKill(pid, signal);
    });
    const inventoryMethod = t.mock.method(
      childProcess,
      "execFileSync",
      (command, ...args) => {
        if (command === "/bin/ps") {
          inventoryCalls++;
          return inventoryCalls === 1 ? `${child.pid}\n` : `${child.pid + 1}\n`;
        }
        return originalExecFileSync(command, ...args);
      },
    );
    syncBuiltinESMExports();
    t.after(() => {
      killMethod.mock.restore();
      spawnMethod.mock.restore();
      inventoryMethod.mock.restore();
      syncBuiltinESMExports();
      if (scratch) rmSync(scratch, { recursive: true, force: true });
      rmSync(project, { recursive: true, force: true });
    });

    const result = await unit.runMacSandbox(
      { executable: "/bin/echo", args: ["synthetic"], cwd: project },
      new AbortController().signal,
      "ignore",
    );
    assert.equal(result, 0);
    assert.ok(groupProbes >= 2);
    assert.equal(inventoryCalls, 2);
    assert.ok(scratch);
    assert.equal(existsSync(scratch), false);
  },
);
