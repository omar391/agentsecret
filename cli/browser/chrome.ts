import { execFileSync, spawnSync } from "node:child_process";
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  realpathSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { CdpPipeTransport } from "./cdp-pipe";
import { BrowserDriver } from "./driver";
import type { BrowserFillDriver } from "./execute";

export const TRUSTED_CHROME_EXECUTABLE =
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

/** Verify Apple's assessment and Google's pinned Developer ID before launch. */
export function verifyGoogleChromeCodeSignature(executable: string): void {
  try {
    const info = lstatSync(executable);
    const uid = typeof process.getuid === "function" ? process.getuid() : -1;
    if (
      info.isSymbolicLink() ||
      !info.isFile() ||
      (info.mode & 0o111) === 0 ||
      (uid >= 0 && info.uid !== uid && info.uid !== 0) ||
      realpathSync(executable) !== executable
    )
      throw new Error("browser_chrome_unverified");
    execFileSync(
      "/usr/bin/codesign",
      ["--verify", "--deep", "--strict", executable],
      { stdio: "ignore" },
    );
    const details = spawnSync(
      "/usr/bin/codesign",
      ["-dv", "--verbose=4", executable],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    const signature = details.stdout + details.stderr;
    if (
      details.status !== 0 ||
      !/^Identifier=com\.google\.Chrome$/mu.test(signature) ||
      !/^TeamIdentifier=EQHXZ8M8AV$/mu.test(signature) ||
      !/^Authority=Developer ID Application: Google LLC \(EQHXZ8M8AV\)$/mu.test(
        signature,
      ) ||
      !/^Authority=Developer ID Certification Authority$/mu.test(signature) ||
      !/^Authority=Apple Root CA$/mu.test(signature)
    )
      throw new Error("browser_chrome_unverified");
    const appBundle = resolve(dirname(dirname(dirname(executable))));
    const assessment = spawnSync(
      "/usr/sbin/spctl",
      ["--assess", "--type", "execute", "--verbose=4", appBundle],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    if (
      assessment.status !== 0 ||
      !/accepted/u.test(assessment.stdout + assessment.stderr) ||
      !/source=Notarized Developer ID/u.test(
        assessment.stdout + assessment.stderr,
      )
    )
      throw new Error("browser_chrome_unverified");
  } catch {
    throw new Error("browser_chrome_unverified");
  }
}

export function verifyTrustedChromeInstallation(executable: string): void {
  if (
    executable !== TRUSTED_CHROME_EXECUTABLE ||
    !existsSync("/usr/bin/codesign") ||
    !existsSync("/usr/sbin/spctl")
  )
    throw new Error("browser_chrome_unverified");
  verifyGoogleChromeCodeSignature(executable);
}

export interface LaunchedBrowser {
  driver: BrowserFillDriver;
  close(): Promise<void>;
}

/**
 * Launch the runtime-owned headless page at the grant origin over Chrome's
 * private CDP pipe, wait until its main frame reports that exact origin, and
 * hand back a guarded driver plus a teardown that also removes the throwaway
 * profile. No debugging port or shared profile is ever exposed.
 */
export async function launchChromeDriver(input: {
  executable: string;
  url: string;
  origin: string;
  signal?: AbortSignal;
  extraArgs?: string[];
}): Promise<LaunchedBrowser> {
  if (!existsSync(input.executable)) throw new Error("browser_chrome_missing");
  const profile = mkdtempSync(join(tmpdir(), "agentsecret-browser-"));
  const transport = CdpPipeTransport.launch({
    executable: input.executable,
    profileDirectory: profile,
    url: input.url,
    origin: input.origin,
    signal: input.signal,
    extraArgs: input.extraArgs,
  });
  try {
    let page;
    const attachDeadline = Date.now() + 10_000;
    while (true) {
      try {
        page = await transport.attachPage();
        break;
      } catch (error) {
        if (Date.now() >= attachDeadline || input.signal?.aborted) throw error;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    }
    const readyDeadline = Date.now() + 10_000;
    while (true) {
      const tree = (await page.send("Page.getFrameTree", {})) as {
        frameTree?: { frame?: { url?: unknown } };
      };
      let frameOrigin = "";
      try {
        frameOrigin = new URL(
          String(tree?.frameTree?.frame?.url),
        ).origin.toLowerCase();
      } catch {}
      if (frameOrigin === input.origin) break;
      if (Date.now() >= readyDeadline)
        throw new Error("browser_navigation_timeout");
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    return {
      driver: new BrowserDriver(page),
      async close() {
        try {
          await transport.close();
        } finally {
          rmSync(profile, { recursive: true, force: true });
        }
      },
    };
  } catch (error) {
    try {
      await transport.close();
    } finally {
      rmSync(profile, { recursive: true, force: true });
    }
    throw error;
  }
}
