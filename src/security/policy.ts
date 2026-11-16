import { SecretPolicy } from "../types";

const globallyReachableProtocolPrefixes: ReadonlyArray<
  readonly [string, number]
> = [
  ["2001:1::1", 128], // PCP anycast
  ["2001:1::2", 128], // TURN anycast
  ["2001:1::3", 128], // DNS-SD registration anycast
  ["2001:3::", 32], // AMT
  ["2001:4:112::", 48], // AS112-v6
  ["2001:20::", 28], // ORCHIDv2
  ["2001:30::", 28], // Drone Remote ID DETs
];

// IANA's Special-Use Domain Names registry applies each designation to the
// listed name and all subdomains. Keep exact zone suffixes here rather than
// treating every name below .arpa as private.
const specialUseDomainSuffixes = [
  "alt",
  "6tisch.arpa",
  "eap.arpa",
  "eap-noob.arpa",
  "home.arpa",
  "10.in-addr.arpa",
  "254.169.in-addr.arpa",
  ...Array.from({ length: 16 }, (_, index) => `${index + 16}.172.in-addr.arpa`),
  "170.0.0.192.in-addr.arpa",
  "171.0.0.192.in-addr.arpa",
  "168.192.in-addr.arpa",
  "8.e.f.ip6.arpa",
  "9.e.f.ip6.arpa",
  "a.e.f.ip6.arpa",
  "b.e.f.ip6.arpa",
  "ipv4only.arpa",
  "resolver.arpa",
  "service.arpa",
  "example",
  "example.com",
  "example.net",
  "example.org",
  "invalid",
  "local",
  "localhost",
  "onion",
  "test",
];

/**
 * Rejects known local/private hostnames and literal IP ranges that must not be
 * used as public broker destinations. This does not validate DNS answers or
 * prevent DNS rebinding; those require trusted network-level egress controls.
 */
export function isSsrfTarget(hostname: string): boolean {
  if (!hostname) return true;
  let lower = hostname.toLowerCase().trim();

  // Strip IPv6 brackets if present, e.g. [::1] -> ::1
  if (lower.startsWith("[") && lower.endsWith("]")) {
    lower = lower.slice(1, -1);
  }

  // Strip trailing dots, e.g. localhost. or 127.0.0.1.
  lower = lower.replace(/\.+$/, "");
  if (!lower.includes(".") && !lower.includes(":")) return true;
  if (
    specialUseDomainSuffixes.some(
      (suffix) => lower === suffix || lower.endsWith(`.${suffix}`),
    )
  )
    return true;
  const ipv4 = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(lower);
  if (ipv4) {
    const [a, b, c, d] = ipv4.slice(1).map(Number);
    if (
      a === 0 ||
      a >= 224 ||
      (a === 192 && b === 0 && c === 0 && ![9, 10].includes(d)) ||
      (a === 192 && b === 0 && c === 2) ||
      (a === 192 && b === 88 && c === 99) ||
      (a === 198 && [18, 19].includes(b)) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113)
    )
      return true;
  }

  // 1. Direct local and cloud metadata endpoints
  if (
    lower === "127.0.0.1" ||
    lower === "0.0.0.0" ||
    lower === "169.254.169.254" || // AWS / GCP / Azure metadata endpoint
    lower === "metadata.google.internal" ||
    lower === "instance-data"
  ) {
    return true;
  }

  // 2. DNS Rebinding services and internal TLDs
  if (
    lower.endsWith(".nip.io") ||
    lower.endsWith(".sslip.io") ||
    lower.endsWith(".xip.io") ||
    lower.endsWith(".internal") ||
    lower.endsWith(".corp") ||
    lower.endsWith(".lan")
  ) {
    return true;
  }

  // 3. IPv6 checks use parsed address bits, so compressed and expanded literals
  // receive the same range checks.
  if (lower.includes(":")) {
    const address = parseIPv6Address(lower);
    // A colon-bearing malformed literal must fail closed. URL parsing rejects
    // malformed IPv6 URLs, but callers also use this helper directly.
    if (!address) return true;

    // The well-known NAT64 prefix is globally routed, but the embedded IPv4
    // destination can still be private. Apply the IPv4 policy to that suffix.
    if (
      ["64:ff9b::", "::"].some((prefix) =>
        ipv6PrefixMatches(address, prefix, 96),
      )
    ) {
      const embeddedIpv4 = Number(address & 0xffff_ffffn);
      const octets = [24, 16, 8, 0].map(
        (shift) => (embeddedIpv4 >>> shift) & 0xff,
      );
      if (isSsrfTarget(octets.join("."))) return true;
    }

    // IANA reserves 2001::/23 for protocol assignments. The registry marks
    // the aggregate non-globally-reachable except for specific more-precise
    // assignments, so allow only those explicitly marked globally reachable.
    if (
      ipv6PrefixMatches(address, "2001::", 23) &&
      !globallyReachableProtocolPrefixes.some(([prefix, bits]) =>
        ipv6PrefixMatches(address, prefix, bits),
      )
    ) {
      return true;
    }

    const blockedPrefixes: Array<[string, number]> = [
      ["::", 128], // unspecified
      ["::1", 128], // loopback
      ["::ffff:0:0", 96], // IPv4-mapped; also avoids mapped private-address bypasses
      ["64:ff9b:1::", 48], // local-use NAT64
      ["100::", 64], // discard-only
      ["100:0:0:1::", 64], // dummy prefix
      ["2001::", 32], // Teredo embeds IPv4 addresses
      ["2001:2::", 48], // benchmarking
      ["2001:10::", 28], // deprecated ORCHID
      ["2001:db8::", 32], // documentation
      ["2002::", 16], // 6to4 embeds an IPv4 destination
      ["3fff::", 20], // documentation
      ["5f00::", 16], // SRv6 SIDs
      ["fc00::", 7], // unique-local
      ["fe80::", 10], // link-local
      ["fec0::", 10], // deprecated site-local
      ["ff00::", 8], // multicast is not a valid public unicast destination
    ];
    if (
      blockedPrefixes.some(([prefix, bits]) =>
        ipv6PrefixMatches(address, prefix, bits),
      )
    ) {
      return true;
    }
  }

  // 4. IPv4 Private Ranges (RFC 1918 & RFC 6598) & Loopback / Link-local
  if (
    lower.startsWith("10.") ||
    lower.startsWith("192.168.") ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(lower) ||
    lower.startsWith("127.") || // Loopback
    lower.startsWith("169.254.") // Link-local
  ) {
    return true;
  }

  // CGNAT RFC 6598 (100.64.0.0/10 => 100.64.0.0 - 100.127.255.255)
  const cgnatMatch = lower.match(/^100\.(\d{1,3})\./);
  if (cgnatMatch) {
    const octet = parseInt(cgnatMatch[1], 10);
    if (octet >= 64 && octet <= 127) {
      return true;
    }
  }

  // 5. Obfuscated IP representations (octal, hex, or decimal integers e.g. 2130706433 or 0177.0.0.1)
  if (
    /^[0-9]+$/.test(lower) ||
    /^0[0-7]+(\.[0-9]+)*$/.test(lower) ||
    /^0x[0-9a-f]+$/i.test(lower)
  ) {
    return true;
  }

  return false;
}

/** Parse an IPv6 literal into a 128-bit integer, including embedded IPv4. */
function parseIPv6Address(host: string): bigint | undefined {
  let value = host;
  if (value.startsWith("[") && value.endsWith("]")) {
    value = value.slice(1, -1);
  }

  const dottedTail = /(?:^|:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(value);
  if (dottedTail) {
    const octets = dottedTail[1].split(".").map(Number);
    if (octets.some((octet) => octet > 255)) return undefined;
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    value = value.slice(0, dottedTail.index) + `:${high}:${low}`;
  }

  const halves = value.split("::");
  if (halves.length > 2) return undefined;
  const parseHalf = (half: string): number[] | undefined => {
    if (!half) return [];
    const groups = half.split(":");
    if (groups.some((group) => !/^[0-9a-f]{1,4}$/i.test(group)))
      return undefined;
    return groups.map((group) => Number.parseInt(group, 16));
  };
  const left = parseHalf(halves[0]);
  const right = parseHalf(halves[1] ?? "");
  if (!left || !right) return undefined;

  const missing = 8 - left.length - right.length;
  if (
    (halves.length === 1 && missing !== 0) ||
    (halves.length === 2 && missing < 1)
  ) {
    return undefined;
  }
  const groups = [...left, ...Array(missing).fill(0), ...right];
  if (groups.length !== 8) return undefined;
  return groups.reduce(
    (address, group) => (address << 16n) | BigInt(group),
    0n,
  );
}

function ipv6PrefixMatches(
  address: bigint,
  prefix: string,
  bits: number,
): boolean {
  const network = parseIPv6Address(prefix);
  if (network === undefined) return false;
  const shift = BigInt(128 - bits);
  return address >> shift === network >> shift;
}

/**
 * Validates a target URL against SSRF threats, domain whitelist, method rules,
 * and optional path glob/regex patterns.
 */
export function validateRequestPolicy(
  policy: SecretPolicy,
  targetUrl: string,
  method: string,
): { isValid: boolean; error?: string; parsedUrl?: URL } {
  let parsed: URL;

  try {
    parsed = new URL(targetUrl);
  } catch (err) {
    return { isValid: false, error: "Invalid URL format" };
  }

  // Enforce HTTPS
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.hash ||
    (parsed.port && parsed.port !== "443")
  ) {
    return {
      isValid: false,
      error: "Only HTTPS URLs are allowed by security policy",
    };
  }

  // 1. SSRF and private IP protection
  if (isSsrfTarget(parsed.hostname)) {
    return {
      isValid: false,
      error: `Access to internal/private hostname "${parsed.hostname}" is prohibited (SSRF prevention).`,
    };
  }

  // 2. Domain Whitelisting
  const allowed = policy.allowedDomains || [];
  const targetHost = parsed.hostname.toLowerCase();

  const domainMatches = allowed.some((domain) => {
    const d = domain.toLowerCase();
    if (d.startsWith("*.")) {
      const suffix = d.slice(1); // e.g. .example.com
      return targetHost.endsWith(suffix) || targetHost === d.slice(2);
    }
    return targetHost === d;
  });

  if (!domainMatches) {
    return {
      isValid: false,
      error: `Domain "${targetHost}" is not permitted by policy for alias "${policy.alias}". Allowed: [${allowed.join(
        ", ",
      )}]`,
    };
  }

  // 3. HTTP Method Enforcement
  const upperMethod = method.toUpperCase();
  const allowedMethods = (policy.allowedMethods || ["GET"]).map((m) =>
    m.toUpperCase(),
  );

  if (!allowedMethods.includes(upperMethod)) {
    return {
      isValid: false,
      error: `HTTP method "${upperMethod}" is not permitted for alias "${policy.alias}". Allowed: [${allowedMethods.join(
        ", ",
      )}]`,
    };
  }

  // 4. Path Pattern Rules (Support glob patterns and negation with !)
  if (policy.pathPatterns && policy.pathPatterns.length > 0) {
    let targetPath: string;
    try {
      targetPath = decodeURIComponent(parsed.pathname);
    } catch {
      return { isValid: false, error: "Invalid path encoding" };
    }

    for (const pattern of policy.pathPatterns) {
      if (pattern.startsWith("!")) {
        const negatedPattern = pattern.slice(1);
        const regex = globToRegex(negatedPattern);
        if (regex.test(targetPath)) {
          return {
            isValid: false,
            error: `Path "${targetPath}" is explicitly forbidden by policy rule "${pattern}".`,
          };
        }
      }
    }

    const positivePatterns = policy.pathPatterns.filter(
      (p) => !p.startsWith("!"),
    );
    if (positivePatterns.length > 0) {
      const matchesPositive = positivePatterns.some((pattern) => {
        const regex = globToRegex(pattern);
        return regex.test(targetPath);
      });

      if (!matchesPositive) {
        return {
          isValid: false,
          error: `Path "${targetPath}" does not match any allowed path pattern for alias "${policy.alias}". Allowed: [${positivePatterns.join(
            ", ",
          )}]`,
        };
      }
    }
  }

  return { isValid: true, parsedUrl: parsed };
}

/**
 * Converts standard glob patterns to strict RegExp.
 * Supports:
 *   - `*` matching single path segment
 *   - `**` matching multiple path segments
 */
export function globToRegex(glob: string): RegExp {
  const normalized = glob.replace(/\/+/g, "/");
  let regexStr = "^";

  for (let i = 0; i < normalized.length; i++) {
    const char = normalized[i];

    if (char === "*") {
      if (normalized[i + 1] === "*") {
        // Recursive wildcard `**`
        regexStr += ".*";
        i++;
      } else {
        // Single segment wildcard `*`
        regexStr += "[^/]*";
      }
    } else if ("./\\+?^$()[]{}|".includes(char)) {
      regexStr += "\\" + char;
    } else {
      regexStr += char;
    }
  }

  regexStr += "$";
  return new RegExp(regexStr);
}
