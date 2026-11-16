import { existsSync, readFileSync, statSync } from "node:fs";
import { extname, join, normalize, resolve, sep } from "node:path";
import type { AssetsAdapter } from "../core/application";

const CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".map": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".webmanifest": "application/manifest+json",
  ".mp4": "video/mp4",
};

/**
 * Static asset serving for a self-hosted Node server, mirroring the Worker's
 * assets binding. Files are read from a single directory (the built web
 * bundle, which also carries the published `cli.mjs`/`run.mjs` artifacts);
 * unknown GET paths fall back to `index.html` for the single-page app, and
 * any path that would escape the root is refused.
 */
export class NodeAssetsAdapter implements AssetsAdapter {
  private readonly root: string;
  private readonly present: boolean;

  constructor(rootDir: string) {
    this.root = resolve(rootDir);
    this.present = existsSync(this.root) && statSync(this.root).isDirectory();
  }

  available(): boolean {
    return this.present;
  }

  private resolvePath(pathname: string): string | null {
    let decoded: string;
    try {
      decoded = decodeURIComponent(pathname);
    } catch {
      // Malformed percent-encoding is a client error, not a server fault.
      return null;
    }
    const candidate = normalize(join(this.root, decoded));
    if (candidate !== this.root && !candidate.startsWith(this.root + sep))
      return null;
    return candidate;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    let file = this.resolvePath(url.pathname);
    if (file === null) return new Response(null, { status: 404 });
    if (!existsSync(file) || !statSync(file).isFile()) {
      // SPA fallback: serve the app shell for unknown GET paths.
      const index = join(this.root, "index.html");
      if (request.method === "GET" && existsSync(index)) file = index;
      else return new Response(null, { status: 404 });
    }
    const body = readFileSync(file);
    const type =
      CONTENT_TYPES[extname(file).toLowerCase()] ?? "application/octet-stream";
    return new Response(body, {
      status: 200,
      headers: {
        "Content-Type": type,
        "Cache-Control": /\.[a-f0-9]{8,}\./i.test(file)
          ? "public, max-age=31536000, immutable"
          : "no-cache, must-revalidate",
      },
    });
  }
}
