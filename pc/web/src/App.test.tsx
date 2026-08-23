import { createRoot } from "react-dom/client";
import { act } from "react";
import { afterEach, describe, expect, it } from "vitest";
import { App, NAV } from "./App";
import { redactSecrets } from "./policy";
import { clearSession, exportClientState, rememberBearer } from "./session";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const MENU = [...NAV, ["/session", "Session"]] as const;

async function mountApp(): Promise<{ host: HTMLDivElement; root: ReturnType<typeof createRoot> }> {
  window.history.pushState({}, "", "/");
  window.location.hash = "#/";
  const host = document.createElement("div");
  document.body.appendChild(host);
  const root = createRoot(host);
  await act(async () => {
    root.render(<App />);
  });
  return { host, root };
}

function menuLink(host: HTMLElement, label: string): HTMLAnchorElement {
  const found = [...host.querySelectorAll("nav a")].find(
    (node) => node.textContent?.trim() === label,
  );
  if (!found) {
    throw new Error(`sidebar link ${label} missing`);
  }
  return found as HTMLAnchorElement;
}

describe("DOM and export redaction", () => {
  it("never writes api_key or SecretRef values into the document", () => {
    const host = document.createElement("div");
    document.body.appendChild(host);
    const root = createRoot(host);
    const projection = redactSecrets({
      id: "acct-1",
      api_key: "sk-live-secret",
      secret_ref: "ss://provider/acct-1",
    });
    act(() => {
      root.render(<pre>{JSON.stringify(projection)}</pre>);
    });
    expect(host.textContent).not.toMatch(/sk-live|ss:\/\//);
    expect(host.textContent).toMatch(/"api_key":"present"/);
    expect(exportClientState()).toEqual({});
    act(() => {
      root.unmount();
    });
    host.remove();
  });
});

describe("sidebar hash navigation", () => {
  afterEach(() => {
    clearSession();
    window.location.hash = "";
    document.body.replaceChildren();
  });

  it("emits hash hrefs, not pathname routes that the daemon 404s", async () => {
    const { host, root } = await mountApp();
    for (const [to, label] of MENU) {
      const href = menuLink(host, label).getAttribute("href") ?? "";
      expect(href.startsWith("#"), `${label} href ${href}`).toBe(true);
      expect(href).not.toBe(to);
      expect(href).not.toMatch(/^\/ui\//);
    }
    act(() => {
      root.unmount();
    });
  });

  it("says the in-place bootstrap field is not a Provider LLM API key", async () => {
    const { host, root } = await mountApp();
    expect(host.querySelector("[data-page='session-gate']")).not.toBeNull();
    expect(host.textContent).toMatch(/not a Provider LLM API key/i);
    expect(host.textContent).toMatch(/local-bootstrap\.secret/);
    expect(host.textContent).not.toMatch(/sk-live|ss:\/\//);
    act(() => {
      root.unmount();
    });
  });

  it("changes the hash and main heading for every sidebar item without a session", async () => {
    const { host, root } = await mountApp();
    for (const [to, label] of MENU) {
      const link = menuLink(host, label);
      await act(async () => {
        link.click();
      });
      const expectedHash = `#${to === "/" ? "/" : to}`.replace(/^#\/\/$/, "#/");
      expect(window.location.hash).toBe(to === "/" ? "#/" : `#${to}`);
      const heading = host.querySelector("main h2")?.textContent ?? "";
      expect(heading, `clicked ${label} hash=${window.location.hash}`).toMatch(
        new RegExp(label, "i"),
      );
      expect(link.getAttribute("aria-current")).toBe("page");
      void expectedHash;
    }
    act(() => {
      root.unmount();
    });
  });

  it("keeps Provider and Bindings views reachable after a memory session is issued", async () => {
    rememberBearer("management", "mgmt-test-token");
    rememberBearer("task", "task-test-token");
    const { host, root } = await mountApp();
    await act(async () => {
      menuLink(host, "Providers").click();
    });
    expect(window.location.hash).toBe("#/providers");
    expect(host.querySelector("main h2")?.textContent).toMatch(/Providers/i);
    expect(host.textContent).toMatch(/Create named account/i);
    await act(async () => {
      menuLink(host, "Bindings").click();
    });
    expect(window.location.hash).toBe("#/bindings");
    expect(host.querySelector("main h2")?.textContent).toMatch(/binding/i);
    act(() => {
      root.unmount();
    });
  });
});
