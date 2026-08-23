/** Client-side display and request policy. Not an authority boundary. */

export const FORBIDDEN_BROWSER_TARGETS = [
  "sqlite",
  "secretstore",
  "filesystem",
  "shell",
  "provider-direct",
] as const;

export const UNAVAILABLE_OPERATIONS = {
  "task-cancel": "not-run",
  "agent-pause": "not-run",
  "agent-resume": "not-run",
  "agent-stop": "not-run",
  "agent-restart": "not-run",
  "agent-quarantine": "not-run",
} as const;

export const SECRET_FIELD_NAMES = [
  "api_key",
  "apiKey",
  "bootstrap_secret",
  "token",
  "secret_ref",
  "secretRef",
] as const;

const SECRET_SHAPE = /(?:sk-|api[_-]?key|secret_ref|Bearer\s+[A-Za-z0-9._-]+)/i;

export function assertNoBrowserAuthorityTarget(target: string): void {
  if ((FORBIDDEN_BROWSER_TARGETS as readonly string[]).includes(target)) {
    throw new Error(`browser must not access ${target} directly`);
  }
}

export function redactSecrets(value: unknown): unknown {
  if (typeof value === "string") {
    if (SECRET_SHAPE.test(value)) {
      return "[redacted]";
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(redactSecrets);
  }
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      if ((SECRET_FIELD_NAMES as readonly string[]).includes(key)) {
        out[key] = nested == null || nested === "" ? "absent" : "present";
        continue;
      }
      out[key] = redactSecrets(nested);
    }
    return out;
  }
  return value;
}

export function containsSecretMaterial(text: string): boolean {
  return SECRET_SHAPE.test(text);
}

export function displayCost(value: unknown, status?: string): string {
  if (status === "cost_unavailable" || status === "unknown" || value == null) {
    return status === "cost_unavailable" ? "cost_unavailable" : "unknown";
  }
  if (value === 0 && status !== "zero") {
    return "unknown";
  }
  return String(value);
}

export function isCompletedAuthorityState(state: string | undefined): boolean {
  return state === "completed" || state === "COMPLETED";
}

export function inferCompletionFromObservation(input: {
  processExit?: number | null;
  providerResponse?: unknown;
  piEvent?: unknown;
  httpReceipt?: unknown;
  streamClosed?: boolean;
}): "unknown" | "completed" {
  void input;
  return "unknown";
}

/** CAS revision the daemon uses: active binding only. Revoked/missing → 0. */
export function bindingRevisionForCas(row: {
  status?: unknown;
  revision?: unknown;
} | undefined): number {
  if (!row || String(row.status ?? "") !== "active") {
    return 0;
  }
  const revision = Number(row.revision ?? 0);
  return Number.isFinite(revision) ? revision : 0;
}

export function acceptBindingMutation(input: {
  expectedRevision: number | undefined;
  currentRevision: number | undefined;
  fallback?: boolean;
  perRequestOverride?: boolean;
}): { ok: true } | { ok: false; reason: string } {
  if (input.fallback || input.perRequestOverride) {
    return { ok: false, reason: "fallback and per-request Provider override are forbidden" };
  }
  if (
    input.expectedRevision === undefined ||
    input.currentRevision === undefined ||
    input.expectedRevision !== input.currentRevision
  ) {
    return { ok: false, reason: "stale binding revision" };
  }
  return { ok: true };
}

export function dispatchAllowed(input: {
  accountStatus?: string;
  bindingStatus?: string;
}): boolean {
  if (!input.bindingStatus || input.bindingStatus === "unbound") {
    return false;
  }
  if (
    input.accountStatus === "revoked" ||
    input.accountStatus === "degraded" ||
    input.accountStatus === "unknown" ||
    input.bindingStatus === "revoked" ||
    input.bindingStatus === "degraded"
  ) {
    return false;
  }
  return input.accountStatus === "active" || input.accountStatus === "usable";
}

export function escapeUntrustedText(text: string, maxChars = 4096): string {
  const clipped = text.length > maxChars ? `${text.slice(0, maxChars)}…` : text;
  return clipped
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function unavailableLabel(operation: keyof typeof UNAVAILABLE_OPERATIONS): string {
  return `${operation}: ${UNAVAILABLE_OPERATIONS[operation]}`;
}
