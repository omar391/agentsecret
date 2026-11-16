/**
 * Sanitizes headers and response bodies before returning them to the AI agent,
 * reducing accidental reflection of known credentials. Arbitrary upstream
 * transformations are not a cryptographic information-flow boundary.
 */
export function sanitizeResponseHeaders(
  headers: Headers,
  secretsToRedact: string[] = [],
): Record<string, string> {
  const result: Record<string, string> = Object.create(null);

  // Headers that must never be reflected back to the LLM agent
  const strippedHeaders = new Set([
    "set-cookie",
    "set-cookie2",
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "www-authenticate",
  ]);

  headers.forEach((val, key) => {
    const lower = key.toLowerCase();
    if (
      !strippedHeaders.has(lower) &&
      /^(content-type|cache-control|retry-after|etag|last-modified|x-ratelimit-(limit|remaining|reset))$/.test(
        lower,
      )
    ) {
      // Also scrub any secret values present inside header values (e.g. Location or custom headers)
      let cleanVal = val;
      if (secretsToRedact.length > 0) {
        const { sanitized } = scrubSecretsFromPayload(
          cleanVal,
          secretsToRedact,
          false,
        );
        cleanVal =
          typeof sanitized === "string" ? sanitized : JSON.stringify(sanitized);
      }
      result[key] = cleanVal;
    }
  });

  return result;
}

// Well-known credential pattern regular expressions
const KNOWN_CREDENTIAL_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  { name: "GITHUB_TOKEN", regex: /gh[pousr]_[A-Za-z0-9_]{36,255}/g },
  {
    name: "STRIPE_KEY",
    regex: /(?:sk|rk|whsec)_(?:live|test)_[0-9a-zA-Z]{24,}/g,
  },
  {
    name: "SLACK_TOKEN",
    regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
  },
  {
    name: "AWS_ACCESS_KEY",
    regex:
      /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
  },
  { name: "ANTHROPIC_KEY", regex: /sk-ant-[a-zA-Z0-9_\-]{40,}/g },
  { name: "OPENAI_KEY", regex: /sk-[a-zA-Z0-9]{48,}/g },
  {
    name: "JWT_BEARER",
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  },
];

/**
 * Calculates Shannon entropy for a string (in bits per symbol).
 * Typical English text / JSON keys have entropy 2.5 - 3.5.
 * High-entropy random secrets / hashes typically have entropy > 4.2.
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const frequencies: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(frequencies)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Generates variations of a secret:
 * - raw
 * - URL-encoded
 * - Base64 standard and URL-safe
 * - JSON-escaped
 */
function generateSecretVariations(secret: string): string[] {
  const variations = new Set<string>();
  const trimmed = secret.trim();
  if (!secret.length) return [];
  variations.add(secret);
  if (!trimmed.length) return Array.from(variations);

  variations.add(trimmed);

  // URL encoded
  const urlEncoded = encodeURIComponent(trimmed);
  if (urlEncoded !== trimmed) variations.add(urlEncoded);

  // Base64 variations
  try {
    const b64 = btoa(trimmed);
    variations.add(b64);
    const b64url = b64
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    if (b64url !== b64) variations.add(b64url);
  } catch {
    // ignore
  }

  // JSON escaped
  try {
    const jsonEscaped = JSON.stringify(trimmed).slice(1, -1);
    if (jsonEscaped !== trimmed) variations.add(jsonEscaped);
  } catch {
    // ignore
  }

  return Array.from(variations);
}

/**
 * Recursively scans and replaces any occurrence of raw secret values
 * in text or parsed JSON objects (including object keys!),
 * as well as known credential patterns and high-entropy secrets.
 */
export function scrubSecretsFromPayload(
  payload: any,
  secretsToRedact: string[],
  enablePatternScanning = true,
  originalJson?: string,
): { sanitized: any; redactionsCount: number } {
  let redactionsCount = 0;

  // Build list of all variations for every known secret
  const allSecretTargets: string[] = [];
  for (const s of secretsToRedact) {
    if (s && s.length > 0) {
      allSecretTargets.push(...generateSecretVariations(s));
    }
  }

  const exactTargets = [...new Set(allSecretTargets)];
  const scalarTargets = new Set<unknown>();
  const structuredTargets = new Set<string>();
  for (const target of exactTargets) {
    try {
      const value: unknown = JSON.parse(target);
      if (
        value === null ||
        typeof value === "number" ||
        typeof value === "boolean" ||
        typeof value === "string"
      )
        scalarTargets.add(value);
      else structuredTargets.add(JSON.stringify(value));
    } catch {
      // Most credential representations are not complete JSON values.
    }
  }
  if (originalJson !== undefined) {
    // The caller has already validated this JSON. Bind matches inside primitive
    // tokens to their decoded values, including escaped strings. A match that
    // crosses token boundaries cannot be safely attributed to one primitive:
    // conservatively redact the entire body instead of losing the match.
    const matches = exactMatchEnds(originalJson);
    if (matches) {
      const tokens =
        /"(?:\\[\s\S]|[^"\\])*"|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/g;
      let checked = 0;
      for (const match of originalJson.matchAll(tokens)) {
        const start = match.index;
        const end = start + match[0].length;
        let sensitive = false;
        for (; checked < end; checked++) {
          if (!matches[checked]) continue;
          if (checked < start || matches[checked] > end)
            return { sanitized: "[REDACTED_SECRET]", redactionsCount: 1 };
          sensitive = true;
        }
        if (sensitive) scalarTargets.add(JSON.parse(match[0]));
      }
      for (; checked < originalJson.length; checked++)
        if (matches[checked])
          return { sanitized: "[REDACTED_SECRET]", redactionsCount: 1 };
    }
  }

  function exactMatchEnds(text: string): Uint32Array | undefined {
    // Find every match against the original text, including overlapping matches.
    // One end offset per character bounds memory independently of match count.
    let matchEnds: Uint32Array | undefined;
    for (const target of exactTargets) {
      let start = text.indexOf(target);
      while (start !== -1) {
        let end = start + target.length;
        // Coalesce overlapping occurrences of this target before recording them.
        // Repetitive responses must not require examining every long match.
        let last = text.lastIndexOf(target, end - 1);
        while (last + target.length > end) {
          end = last + target.length;
          last = text.lastIndexOf(target, end - 1);
        }
        matchEnds ??= new Uint32Array(text.length);
        matchEnds[start] = Math.max(matchEnds[start], end);
        start = text.indexOf(target, end);
      }
    }
    return matchEnds;
  }

  function scrubString(text: string): string {
    if (scalarTargets.has(text)) {
      redactionsCount++;
      return "[REDACTED_SECRET]";
    }
    const matchEnds = exactMatchEnds(text);
    let result = text;
    if (matchEnds) {
      const pieces: string[] = [];
      let copied = 0;
      for (let start = 0; start < text.length; start++) {
        if (!matchEnds[start]) continue;
        let end = matchEnds[start];
        // Merge the full union before replacing; an earlier short match must
        // never hide a longer credential beginning inside it.
        for (let next = start + 1; next < end; next++)
          end = Math.max(end, matchEnds[next]);
        pieces.push(text.slice(copied, start), "[REDACTED_SECRET]");
        redactionsCount++;
        copied = end;
        start = end - 1;
      }
      pieces.push(text.slice(copied));
      result = pieces.join("");
    }

    // 2. Scan for well-known credential regexes
    if (enablePatternScanning) {
      for (const pattern of KNOWN_CREDENTIAL_PATTERNS) {
        if (pattern.regex.test(result)) {
          result = result.replace(pattern.regex, () => {
            redactionsCount++;
            return `[REDACTED:${pattern.name}]`;
          });
        }
      }

      // 3. Scan words with high entropy (>= 28 chars long and entropy >= 4.2)
      const words = result.split(/[\s"'{}[\],:]+/);
      for (const word of words) {
        if (word.length >= 28 && !word.startsWith("[REDACTED")) {
          const entropy = calculateShannonEntropy(word);
          if (entropy >= 4.2) {
            const wordRegex = new RegExp(escapeRegExp(word), "g");
            result = result.replace(wordRegex, "[REDACTED:HIGH_ENTROPY_TOKEN]");
            redactionsCount++;
          }
        }
      }
    }

    return result;
  }

  function walk(node: any, depth = 0): any {
    if (depth > 64) return "[REDACTED:DEPTH_LIMIT]";
    if (typeof node === "string") {
      return scrubString(node);
    }
    if (
      node === null ||
      typeof node === "number" ||
      typeof node === "boolean"
    ) {
      if (scalarTargets.has(node)) {
        redactionsCount++;
        return "[REDACTED_SECRET]";
      }
      const value = String(node);
      const scrubbed = scrubString(value);
      return scrubbed === value ? node : scrubbed;
    }
    if (
      originalJson !== undefined &&
      structuredTargets.size > 0 &&
      node !== null &&
      typeof node === "object"
    ) {
      try {
        if (structuredTargets.has(JSON.stringify(node))) {
          redactionsCount++;
          return "[REDACTED_SECRET]";
        }
      } catch {
        // An overdeep/unserializable structure cannot be compared safely.
        redactionsCount++;
        return "[REDACTED_SECRET]";
      }
    }
    if (Array.isArray(node)) {
      return node.map((item) => walk(item, depth + 1));
    }
    if (node !== null && typeof node === "object") {
      const copy: Record<string, any> = Object.create(null);
      for (const [k, v] of Object.entries(node)) {
        const sanitizedKey = scrubString(k);
        copy[sanitizedKey] = walk(v, depth + 1);
      }
      return copy;
    }
    return node;
  }

  const sanitized = walk(payload);
  return { sanitized, redactionsCount };
}

function escapeRegExp(string: string): string {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
