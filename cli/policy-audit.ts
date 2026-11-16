import type { RunEgressRule } from "./run-spec";

/**
 * Verify the effective sbx policy captured from a live sandbox matches the
 * run's declared egress exactly. The caller supplies the stdout of three
 * `sbx policy ls --wide --include-inactive --format json` audits: the
 * account listing before sandbox creation, the sandbox listing before any
 * scoped grant, and the sandbox listing after every scoped grant.
 *
 * The contract:
 * - every listing parses as a closed `{ rules: [...] }` object;
 * - the account policy carries an active global deny for network traffic;
 * - the only active scoped rules are HTTP allows bound to this sandbox;
 * - each declared egress rule has exactly one matching active allow with the
 *   same host:443 target, method and path;
 * - the post-grant verify listing contains no active scoped rule beyond the
 *   declared grants (comparing against the pre-grant sandbox listing keeps
 *   unrelated or recreated grants from slipping through);
 * - no resource type other than `http` is actively allowed at sandbox scope.
 */

export interface SbxPolicyRule {
  id?: unknown;
  scope?: unknown;
  resource_type?: unknown;
  decision?: unknown;
  status?: unknown;
  resources?: unknown;
  actions?: unknown;
  origin?: unknown;
  sandbox_id?: unknown;
  methods?: unknown;
  http_targets?: unknown;
}

export class PolicyAuditError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

function fail(code: string): never {
  throw new PolicyAuditError(code);
}

function parseRules(
  stdout: string | undefined,
  stage: string,
): SbxPolicyRule[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout ?? "");
  } catch {
    fail(stage + "_json_invalid");
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    Array.isArray(parsed) ||
    Object.keys(parsed).length !== 1 ||
    !Array.isArray((parsed as { rules?: unknown }).rules)
  ) {
    fail(stage + "_shape_invalid");
  }
  const rules = (parsed as { rules: unknown[] }).rules;
  for (const rule of rules) {
    // Exact key set observed from sbx v0.53.0 `policy ls --wide
    // --include-inactive --format json` for both account and sandbox
    // listings. Unknown keys fail closed so a changed vendor schema can
    // never be read as an empty permission set.
    const allowedKeys = new Set([
      "id",
      "name",
      "policy_id",
      "policy_name",
      "scope",
      "applies_to",
      "resource_type",
      "decision",
      "status",
      "origin",
      "layer",
      "editable",
      "provenance",
      "reason",
      "resources",
      "actions",
      "sandbox_id",
      "methods",
      "http_targets",
    ]);
    if (typeof rule !== "object" || rule === null || Array.isArray(rule)) {
      fail(stage + "_rule_invalid");
    }
    const record = rule as Record<string, unknown>;
    if (
      Object.keys(record).some((key) => !allowedKeys.has(key)) ||
      typeof record.scope !== "string" ||
      !(record.scope === "global" || /^sandbox:.+$/u.test(record.scope)) ||
      typeof record.resource_type !== "string" ||
      typeof record.decision !== "string" ||
      !["allow", "deny"].includes(record.decision) ||
      typeof record.status !== "string" ||
      !["active", "inactive"].includes(record.status) ||
      (record.id !== undefined && typeof record.id !== "string") ||
      (record.name !== undefined && typeof record.name !== "string") ||
      (record.policy_id !== undefined &&
        typeof record.policy_id !== "string") ||
      (record.policy_name !== undefined &&
        typeof record.policy_name !== "string") ||
      (record.applies_to !== undefined &&
        typeof record.applies_to !== "string") ||
      (record.layer !== undefined && typeof record.layer !== "string") ||
      (record.editable !== undefined && typeof record.editable !== "boolean") ||
      (record.provenance !== undefined &&
        (typeof record.provenance !== "object" ||
          record.provenance === null ||
          Array.isArray(record.provenance))) ||
      (record.reason !== undefined && typeof record.reason !== "string") ||
      (record.resources !== undefined &&
        (!Array.isArray(record.resources) ||
          record.resources.some((v) => typeof v !== "string"))) ||
      (record.origin !== undefined && typeof record.origin !== "string") ||
      (record.sandbox_id !== undefined &&
        typeof record.sandbox_id !== "string") ||
      (record.methods !== undefined &&
        (!Array.isArray(record.methods) ||
          record.methods.some((v) => typeof v !== "string"))) ||
      (record.actions !== undefined &&
        (!Array.isArray(record.actions) ||
          record.actions.some((v) => typeof v !== "string"))) ||
      (record.http_targets !== undefined &&
        (!Array.isArray(record.http_targets) ||
          record.http_targets.some(
            (v) =>
              typeof v !== "object" ||
              v === null ||
              Array.isArray(v) ||
              Object.keys(v).some((key) => !["host", "path"].includes(key)) ||
              typeof (v as Record<string, unknown>).host !== "string" ||
              typeof (v as Record<string, unknown>).path !== "string",
          )))
    ) {
      fail(stage + "_rule_invalid");
    }
  }
  return rules as SbxPolicyRule[];
}

function isActive(rule: SbxPolicyRule): boolean {
  return rule.status === "active" && rule.decision === "allow";
}

function isSandboxScoped(rule: SbxPolicyRule, sandboxName: string): boolean {
  return (
    rule.scope === "sandbox:" + sandboxName || rule.sandbox_id === sandboxName
  );
}

function declaredKey(rule: RunEgressRule): string {
  const host = rule.host.includes(":") ? rule.host : rule.host + ":443";
  return host + "|" + rule.method + "|" + rule.path;
}

function ruleKey(rule: SbxPolicyRule, index: number): string {
  const targets = Array.isArray(rule.http_targets) ? rule.http_targets : [];
  const parts: string[] = [];
  for (const target of targets) {
    if (
      typeof target !== "object" ||
      target === null ||
      typeof (target as { host?: unknown }).host !== "string" ||
      typeof (target as { path?: unknown }).path !== "string"
    ) {
      fail("scoped_rule_target_invalid:" + index);
    }
    const host = (target as { host: string; path: string }).host;
    const path = (target as { host: string; path: string }).path;
    const methods = Array.isArray(rule.methods) ? rule.methods : [];
    if (methods.length !== 1 || typeof methods[0] !== "string") {
      fail("scoped_rule_method_invalid:" + index);
    }
    parts.push(host + "|" + methods[0] + "|" + path);
  }
  if (parts.length !== 1) fail("scoped_rule_target_count_invalid:" + index);
  return parts[0];
}

function activeScopedHttpKeys(
  rules: SbxPolicyRule[],
  sandboxName: string,
): Map<string, number> {
  const keys = new Map<string, number>();
  for (const [index, rule] of rules.entries()) {
    if (!isActive(rule) || !isSandboxScoped(rule, sandboxName)) continue;
    if (rule.resource_type !== "http") {
      fail("scoped_allow_resource_type_invalid:" + rule.resource_type);
    }
    const key = ruleKey(rule, index);
    if (keys.has(key)) fail("scoped_rule_duplicate:" + key);
    keys.set(key, index);
  }
  return keys;
}

function activeNetworkOrHttpAllows(
  rules: SbxPolicyRule[],
  expected: Map<string, RunEgressRule>,
  stage: string,
  sandboxName: string,
  skipAllScoped: boolean,
): void {
  for (const [index, rule] of rules.entries()) {
    if (!isActive(rule)) continue;
    // The account listing shows every sandbox on this host. Only global
    // rules apply to the sandbox this run is about to create; another
    // sandbox's scoped grant says nothing about this one and is not a
    // bypass of the declaration.
    if (
      skipAllScoped
        ? rule.scope !== "global"
        : isSandboxScoped(rule, sandboxName)
    )
      continue;
    if (rule.resource_type === "network")
      fail(stage + "_network_allow_forbidden");
    if (rule.resource_type !== "http") continue;
    const key = ruleKey(rule, index);
    if (!expected.has(key)) fail(stage + "_http_allow_not_declared:" + key);
  }
}

function hasUniversalNetworkDefaultDeny(rules: SbxPolicyRule[]): boolean {
  return rules.some(
    (rule) =>
      rule.scope === "global" &&
      rule.resource_type === "network" &&
      rule.decision === "deny" &&
      rule.status === "active" &&
      Array.isArray(rule.resources) &&
      rule.resources.includes("**") &&
      Array.isArray(rule.actions) &&
      rule.actions.includes("net:connect:tcp") &&
      rule.actions.includes("net:connect:udp"),
  );
}

export function verifyRuntimePolicyAudit(
  audits: {
    account: string | undefined;
    sandbox: string | undefined;
    verify: string | undefined;
  },
  declared: RunEgressRule[],
  sandboxName: string,
): void {
  const account = parseRules(audits.account, "account_policy");
  const sandbox = parseRules(audits.sandbox, "sandbox_policy");
  const verify = parseRules(audits.verify, "verify_policy");

  for (const [stage, rules] of [
    ["account_policy", account],
    ["sandbox_policy", sandbox],
    ["verify_policy", verify],
  ] as const) {
    const denied = hasUniversalNetworkDefaultDeny(rules);
    if (!denied) {
      fail(
        stage === "account_policy"
          ? "account_network_default_deny_missing"
          : stage + "_network_default_deny_missing",
      );
    }
  }

  const expected = new Map(declared.map((rule) => [declaredKey(rule), rule]));
  activeNetworkOrHttpAllows(
    account,
    expected,
    "account_policy",
    sandboxName,
    true,
  );
  activeNetworkOrHttpAllows(
    sandbox,
    expected,
    "sandbox_policy",
    sandboxName,
    false,
  );
  activeNetworkOrHttpAllows(
    verify,
    expected,
    "verify_policy",
    sandboxName,
    false,
  );

  const beforeKeys = activeScopedHttpKeys(sandbox, sandboxName);
  const afterKeys = activeScopedHttpKeys(verify, sandboxName);

  for (const [key, index] of beforeKeys) {
    if (!afterKeys.has(key)) fail("scoped_rule_missing_after_grant:" + key);
    const allowed = declared.some((rule) => declaredKey(rule) === key);
    if (allowed) fail("declared_rule_present_before_grant:" + key);
    void index;
  }

  for (const [key] of expected) {
    if (beforeKeys.has(key)) fail("declared_rule_present_before_grant:" + key);
  }
  for (const [key] of afterKeys) {
    if (!expected.has(key)) fail("scoped_rule_not_declared:" + key);
  }
  for (const [key] of expected) {
    if (!afterKeys.has(key)) fail("declared_rule_missing_after_grant:" + key);
  }
}
