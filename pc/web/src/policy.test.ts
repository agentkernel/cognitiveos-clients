import { describe, expect, it } from "vitest";
import {
  acceptBindingMutation,
  acceptDshApply,
  bindingRevisionForCas,
  dispatchAllowed,
  assertNoBrowserAuthorityTarget,
  containsSecretMaterial,
  displayCost,
  escapeUntrustedText,
  inferCompletionFromObservation,
  redactSecrets,
  unavailableLabel,
} from "./policy";

describe("secret redaction", () => {
  it("never leaves api_key or secret_ref values in the projection", () => {
    const redacted = redactSecrets({
      id: "acct-1",
      api_key: "sk-live-secret",
      secret_ref: "ss://provider/acct-1",
      nested: { token: "Bearer abc.def" },
    }) as Record<string, unknown>;
    expect(redacted.api_key).toBe("present");
    expect(redacted.secret_ref).toBe("present");
    expect(JSON.stringify(redacted)).not.toMatch(/sk-live|ss:\/\/|Bearer abc/);
  });

  it("detects secret material that must not enter URL, storage, or logs", () => {
    expect(containsSecretMaterial("https://example/?api_key=sk-abc")).toBe(true);
    expect(containsSecretMaterial("/management/provider/v1/accounts")).toBe(false);
  });
});

describe("forbidden browser authority", () => {
  it("rejects SQLite, SecretStore, filesystem, shell, and provider-direct", () => {
    for (const target of ["sqlite", "secretstore", "filesystem", "shell", "provider-direct"]) {
      expect(() => assertNoBrowserAuthorityTarget(target)).toThrow(/must not access/);
    }
  });
});

describe("unavailable typed operations", () => {
  it("maps missing HTTP cancel and Agent lifecycle to not-run", () => {
    expect(unavailableLabel("task-cancel")).toBe("task-cancel: not-run");
    expect(unavailableLabel("agent-pause")).toBe("agent-pause: not-run");
    expect(unavailableLabel("agent-quarantine")).toBe("agent-quarantine: not-run");
  });
});

describe("binding mutation gates", () => {
  it("rejects stale revision, fallback, and per-request override", () => {
    expect(
      acceptBindingMutation({ expectedRevision: 1, currentRevision: 2 }),
    ).toEqual({ ok: false, reason: "stale binding revision" });
    expect(
      acceptBindingMutation({
        expectedRevision: 3,
        currentRevision: 3,
        fallback: true,
      }),
    ).toMatchObject({ ok: false });
    expect(
      acceptBindingMutation({
        expectedRevision: 3,
        currentRevision: 3,
        perRequestOverride: true,
      }),
    ).toMatchObject({ ok: false });
  });

  it("applies only an active dsh catalog model while web is ACTIVE", () => {
    expect(
      acceptDshApply({
        agent: "dsh",
        bindingStatus: "active",
        modelId: "grok-4.6",
        catalogModelIds: ["deepseek-v4-flash", "grok-4.6"],
        runtimeState: "ACTIVE",
        processAlive: true,
      }),
    ).toEqual({ ok: true });
    expect(
      acceptDshApply({
        agent: "pi",
        bindingStatus: "active",
        modelId: "grok-4.6",
        runtimeState: "ACTIVE",
        processAlive: true,
      }),
    ).toMatchObject({ ok: false });
    expect(
      acceptDshApply({
        agent: "dsh",
        bindingStatus: "revoked",
        modelId: "grok-4.6",
        runtimeState: "ACTIVE",
        processAlive: true,
      }),
    ).toMatchObject({ ok: false });
    expect(
      acceptDshApply({
        agent: "dsh",
        bindingStatus: "active",
        modelId: "grok-4.6",
        catalogModelIds: ["deepseek-v4-flash"],
        runtimeState: "ACTIVE",
        processAlive: true,
      }),
    ).toMatchObject({ ok: false });
    expect(
      acceptDshApply({
        agent: "dsh",
        bindingStatus: "active",
        modelId: "grok-4.6",
        runtimeState: "INACTIVE",
        processAlive: false,
      }),
    ).toMatchObject({ ok: false });
  });

  it("uses only an active binding revision for CAS", () => {
    expect(bindingRevisionForCas(undefined)).toBe(0);
    expect(bindingRevisionForCas({ status: "revoked", revision: 2 })).toBe(0);
    expect(bindingRevisionForCas({ status: "active", revision: 3 })).toBe(3);
  });

  it("allows storing a binding on a revoked account but blocks dispatch", () => {
    expect(acceptBindingMutation({ expectedRevision: 0, currentRevision: 0 })).toEqual({
      ok: true,
    });
    expect(dispatchAllowed({ accountStatus: "revoked", bindingStatus: "active" })).toBe(false);
    expect(dispatchAllowed({ accountStatus: "active", bindingStatus: "active" })).toBe(true);
    expect(dispatchAllowed({ accountStatus: "active", bindingStatus: "unbound" })).toBe(false);
  });
});

describe("completion and observation", () => {
  it("does not infer Task completion from process, Provider, Pi, or HTTP receipt", () => {
    expect(
      inferCompletionFromObservation({
        processExit: 0,
        providerResponse: { ok: true },
        piEvent: { type: "done" },
        httpReceipt: { status: 200 },
        streamClosed: true,
      }),
    ).toBe("unknown");
  });

  it("does not treat a zero cost as a completed authority fact", () => {
    expect(displayCost(0)).toBe("unknown");
    expect(displayCost(null, "cost_unavailable")).toBe("cost_unavailable");
  });
});

describe("untrusted output", () => {
  it("escapes markup so Agent or Provider text cannot execute", () => {
    expect(escapeUntrustedText('<script>alert(1)</script>')).toBe(
      "&lt;script&gt;alert(1)&lt;/script&gt;",
    );
  });
});
