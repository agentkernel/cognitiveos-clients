import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { HashRouter, NavLink, Route, Routes, useParams } from "react-router-dom";
import { issueChannelSession, readJson, rejectCallerHeaderInjection } from "./api";
import { AGENT_IDENTITY_KEYS, mergeIdentities, type AgentIdentities } from "./identities";
import {
  acceptBindingMutation,
  acceptDshApply,
  bindingRevisionForCas,
  displayCost,
  dispatchAllowed,
  escapeUntrustedText,
  inferCompletionFromObservation,
  redactSecrets,
  unavailableLabel,
} from "./policy";
import {
  PROVIDER_KINDS,
  capabilityDisposition,
  classifyProbe,
  requiresTrustConfirmation,
} from "./probe";
import { clearSession, rememberBearer, rememberPrincipal, sessionHasChannel, sessionPrincipal } from "./session";
import { interpretCandidate, workspaceSearchDraft } from "./taskDraft";
import { createWatchController } from "./watch";
import { isWatchResumeStale, latestSequence, parseSse } from "./watchSse";

type LoadState = {
  status: "loading" | "ready" | "empty" | "denied" | "disconnected" | "unknown" | "not-run";
  ms?: number;
  body?: unknown;
  message?: string;
};

export const NAV = [
  ["/", "Home"],
  ["/agents", "Agents"],
  ["/providers", "Providers"],
  ["/bindings", "Bindings"],
  ["/tasks", "Tasks"],
  ["/activity", "Activity"],
  ["/resources", "Resources"],
] as const;

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function asList(value: unknown, keys: string[]): unknown[] {
  const record = asRecord(value);
  for (const key of keys) {
    if (Array.isArray(record[key])) {
      return record[key] as unknown[];
    }
  }
  return [];
}

async function load(path: string, channel: "management" | "task"): Promise<LoadState> {
  try {
    const result = await readJson(path, channel);
    if (result.status === 401 || result.status === 403) {
      return { status: "denied", ms: result.ms, body: result.body, message: `HTTP ${result.status}` };
    }
    if (!result.ok) {
      return { status: "unknown", ms: result.ms, body: result.body, message: `HTTP ${result.status}` };
    }
    const list = asList(result.body, ["items", "accounts", "bindings", "events", "alerts", "models"]);
    if (list.length === 0 && JSON.stringify(result.body).includes("[]")) {
      return { status: "empty", ms: result.ms, body: result.body };
    }
    return { status: "ready", ms: result.ms, body: result.body };
  } catch (error) {
    return {
      status: "disconnected",
      message: error instanceof Error ? error.message : "disconnected",
    };
  }
}

function StateNote({ state }: { state: LoadState }) {
  return (
    <p className="muted" role="status">
      {state.status}
      {state.ms != null ? ` · ${state.ms} ms` : ""}
      {state.message ? ` · ${state.message}` : ""}
    </p>
  );
}

function JsonPanel({ title, value }: { title: string; value: unknown }) {
  return (
    <section className="panel">
      <h3>{title}</h3>
      <pre>{JSON.stringify(redactSecrets(value ?? {}), null, 2)}</pre>
    </section>
  );
}

function secretPresence(value: unknown): string {
  if (value == null || value === "" || value === "absent") {
    return "absent";
  }
  return "present";
}

const SessionTick = createContext({ tick: 0, bump: () => {} });

function SessionScope({ children }: { children: React.ReactNode }) {
  const [tick, setTick] = useState(0);
  const bump = useCallback(() => setTick((value) => value + 1), []);
  return <SessionTick.Provider value={{ tick, bump }}>{children}</SessionTick.Provider>;
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="shell">
      <a
        className="skip"
        href="#main"
        onClick={(event) => {
          event.preventDefault();
          document.getElementById("main")?.focus();
        }}
      >
        Skip to content
      </a>
      <nav className="side" aria-label="Primary">
        <h1>CognitiveOS Personal</h1>
        <p className="muted">Daemon client only. Not an authority writer.</p>
        <ul>
          {NAV.map(([to, label]) => (
            <li key={to}>
              <NavLink to={to} end={to === "/"}>
                {label}
              </NavLink>
            </li>
          ))}
          <li>
            <NavLink to="/session">Session</NavLink>
          </li>
        </ul>
      </nav>
      <main id="main" tabIndex={-1}>
        {children}
      </main>
    </div>
  );
}

function RequireSession({
  channel,
  title,
  children,
}: {
  channel: "management" | "task";
  title: string;
  children: React.ReactNode;
}) {
  const { tick } = useContext(SessionTick);
  void tick;
  if (!sessionHasChannel(channel)) {
    return (
      <section data-page="session-gate">
        <h2>{title}</h2>
        <p className="warn" role="status">
          This page needs a {channel} session. Sidebar navigation still changes the view.
          Paste this daemon&apos;s bootstrap secret — not a Provider LLM API key.
        </p>
        <SessionForm />
      </section>
    );
  }
  return <>{children}</>;
}

function SessionForm() {
  const { bump } = useContext(SessionTick);
  const [secret, setSecret] = useState("");
  const [principal, setPrincipal] = useState("principal://local/owner");
  const [message, setMessage] = useState("Session tokens stay in memory only.");

  async function issue(event: React.FormEvent) {
    event.preventDefault();
    const bootstrap = secret;
    setSecret("");
    rememberPrincipal(principal);
    const management = await issueChannelSession("management", principal, bootstrap);
    const task = await issueChannelSession("task", principal, bootstrap);
    if (management.ok && management.token) {
      rememberBearer("management", management.token);
    }
    if (task.ok && task.token) {
      rememberBearer("task", task.token);
    }
    setMessage(
      `management ${management.ok ? "ready" : `HTTP ${management.status}`}; task ${
        task.ok ? "ready" : `HTTP ${task.status}`
      }. Bootstrap discarded.`,
    );
    bump();
  }

  return (
    <form onSubmit={(event) => void issue(event)}>
      <label>
        Principal
        <input value={principal} onChange={(event) => setPrincipal(event.target.value)} />
      </label>
      <label>
        Daemon bootstrap secret
        <input
          type="password"
          autoComplete="off"
          value={secret}
          onChange={(event) => setSecret(event.target.value)}
        />
      </label>
      <p className="muted">
        File <code>local-bootstrap.secret</code> on this daemon. Not a Provider LLM API key
        and not a SecretRef. The browser cannot read the file. Sessions stay in memory only.
      </p>
      <button type="submit">Issue management and Task sessions</button>
      <button
        type="button"
        onClick={() => {
          clearSession();
          setMessage("Session cleared.");
          bump();
        }}
      >
        Clear memory session
      </button>
      <p role="status">{message}</p>
    </form>
  );
}

function SessionPage() {
  return (
    <>
      <h2>Session bootstrap</h2>
      <p className="muted">
        Paste this daemon&apos;s <code>local-bootstrap.secret</code> once. It is not a
        Provider LLM API key. It is never written to localStorage, sessionStorage,
        IndexedDB, the URL, or exported state.
      </p>
      <SessionForm />
    </>
  );
}

function HomePage() {
  const [health, setHealth] = useState<LoadState>({ status: "loading" });
  const [status, setStatus] = useState<LoadState>({ status: "loading" });
  const [readiness, setReadiness] = useState<LoadState>({ status: "loading" });
  const [doctor, setDoctor] = useState<LoadState>({ status: "loading" });

  useEffect(() => {
    void (async () => {
      try {
        const started = performance.now();
        const response = await fetch("/personal/health", { credentials: "omit" });
        setHealth({
          status: response.ok ? "ready" : "unknown",
          ms: Math.round(performance.now() - started),
          body: await response.json().catch(() => ({})),
        });
      } catch {
        setHealth({ status: "disconnected", message: "daemon unreachable" });
      }
      setStatus(await load("/personal/status", "management"));
      setReadiness(await load("/personal/readiness", "management"));
      setDoctor(await load("/personal/doctor", "management"));
    })();
  }, []);

  return (
    <>
      <h2>Home</h2>
      <div className="status-grid">
        <section className="panel">
          <h3>Health</h3>
          <StateNote state={health} />
        </section>
        <section className="panel">
          <h3>Status</h3>
          <StateNote state={status} />
        </section>
        <section className="panel">
          <h3>Readiness</h3>
          <StateNote state={readiness} />
        </section>
        <section className="panel">
          <h3>Doctor</h3>
          <StateNote state={doctor} />
        </section>
      </div>
      <JsonPanel title="Readiness projection" value={readiness.body} />
      <JsonPanel title="Doctor projection" value={doctor.body} />
    </>
  );
}

function identitiesFromResource(item: Record<string, unknown>): AgentIdentities {
  return mergeIdentities({
    package: String(item.package_id ?? item.package ?? "unknown"),
    installation: String(item.installation_id ?? item.installation ?? "unknown"),
    registration: String(item.registration_id ?? item.registration ?? "unknown"),
    instance: String(item.id ?? item.instance_id ?? item.instance ?? "unknown"),
    sidecar: String(item.sidecar_id ?? item.sidecar ?? "unknown"),
    execution: String(item.execution_id ?? item.execution ?? "unknown"),
    process: String(item.process_id ?? item.process ?? "unknown"),
    task: String(item.task_id ?? item.current_task ?? "unknown"),
    shell_session: String(item.shell_session_id ?? item.shell_session ?? "unknown"),
  });
}

function AgentsPage() {
  const [runtime, setRuntime] = useState<LoadState>({ status: "loading" });
  const [bindings, setBindings] = useState<LoadState>({ status: "loading" });
  const [dsh, setDsh] = useState<LoadState>({ status: "loading" });

  useEffect(() => {
    void (async () => {
      setRuntime(await load("/management/resource/v1/list?family=runtime", "management"));
      setBindings(await load("/management/agent-bindings", "management"));
      setDsh(await load("/personal/dsh/runtime", "management"));
    })();
  }, []);

  const items = asList(runtime.body, ["items", "resources"]).map(asRecord);

  return (
    <>
      <h2>Agents</h2>
      <StateNote state={runtime} />
      <p className="muted">
        Pause, resume, stop, restart, and quarantine are {unavailableLabel("agent-pause")},{" "}
        {unavailableLabel("agent-resume")}, {unavailableLabel("agent-stop")},{" "}
        {unavailableLabel("agent-restart")}, {unavailableLabel("agent-quarantine")}. No generic
        lifecycle route is offered.
      </p>
      {items.length === 0 ? (
        <p className="warn">No runtime family items. Binding identities still stay distinct.</p>
      ) : (
        <table>
          <caption>Runtime family inventory</caption>
          <thead>
            <tr>
              <th>Instance</th>
              <th>Package</th>
              <th>Status</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item, index) => {
              const identities = identitiesFromResource(item);
              return (
                <tr key={String(item.id ?? index)}>
                  <td>{identities.instance}</td>
                  <td>{identities.package}</td>
                  <td>{String(item.status ?? item.lifecycle ?? "unknown")}</td>
                  <td>
                    <NavLink to={`/agents/${encodeURIComponent(String(item.id ?? index))}`}>
                      Inspect
                    </NavLink>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      <JsonPanel title="Bindings projection" value={bindings.body} />
      <JsonPanel title="dsh runtime (process liveness is not Task completion)" value={dsh.body} />
    </>
  );
}

function AgentDetailPage() {
  const { id } = useParams();
  const [inspect, setInspect] = useState<LoadState>({ status: "loading" });

  useEffect(() => {
    if (!id) {
      return;
    }
    void (async () => {
      setInspect(
        await load(
          `/management/resource/v1/inspect?family=runtime&id=${encodeURIComponent(id)}`,
          "management",
        ),
      );
    })();
  }, [id]);

  const item = asRecord(asRecord(inspect.body).item ?? inspect.body);
  const identities = identitiesFromResource(item);

  return (
    <>
      <h2>Agent detail</h2>
      <StateNote state={inspect} />
      <div className="identity-grid">
        {AGENT_IDENTITY_KEYS.map((key) => (
          <article className="identity-card" key={key}>
            <h3>{key}</h3>
            <p>{identities[key]}</p>
          </article>
        ))}
      </div>
      <section className="panel">
        <h3>Typed lifecycle</h3>
        <p>{unavailableLabel("agent-pause")}</p>
        <p>{unavailableLabel("agent-resume")}</p>
        <p>{unavailableLabel("agent-stop")}</p>
        <p>{unavailableLabel("agent-restart")}</p>
        <p>{unavailableLabel("agent-quarantine")}</p>
      </section>
      <JsonPanel title="Inspect projection" value={inspect.body} />
    </>
  );
}

function ProvidersPage() {
  const [accounts, setAccounts] = useState<LoadState>({ status: "loading" });
  const [kind, setKind] = useState<(typeof PROVIDER_KINDS)[number]>("openai_official");
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [allowInsecure, setAllowInsecure] = useState(false);
  const [trustConfirmed, setTrustConfirmed] = useState(false);
  const [message, setMessage] = useState("Keys travel only in the key POST body, then SecretStore.");

  async function refresh() {
    setAccounts(await load("/management/providers/accounts", "management"));
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function create(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const needsTrust = requiresTrustConfirmation({
      kind,
      allowPrivateNetwork: allowPrivate,
      allowInsecureHttp: allowInsecure,
    });
    if (needsTrust && !trustConfirmed) {
      setMessage("Trust confirmation is required before persisting a private or HTTP endpoint.");
      return;
    }
    const body = {
      display_name: String(form.get("display_name") ?? ""),
      provider_kind: kind,
      endpoint: String(form.get("endpoint") ?? "") || undefined,
      allow_private_network: allowPrivate,
      allow_insecure_http: allowInsecure,
    };
    rejectCallerHeaderInjection(body);
    const result = await readJson("/management/providers/accounts", "management", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const created = asRecord(asRecord(result.body).account);
    setMessage(
      result.ok
        ? `Account created (${String(created.id ?? "unknown")}). Enter the API key on the account page; it is not in this create form.`
        : `HTTP ${result.status} ${String(asRecord(result.body).code ?? "")}`,
    );
    event.currentTarget.reset();
    setKind("openai_official");
    setAllowPrivate(false);
    setAllowInsecure(false);
    setTrustConfirmed(false);
    await refresh();
  }

  const rows = asList(accounts.body, ["accounts", "items"]).map(asRecord);
  const needsTrust = requiresTrustConfirmation({
    kind,
    allowPrivateNetwork: allowPrivate,
    allowInsecureHttp: allowInsecure,
  });

  return (
    <>
      <h2>Providers</h2>
      <StateNote state={accounts} />
      <form onSubmit={create}>
        <h3>Create named account</h3>
        <p className="muted">
          Sequence: validate → trust confirmation when required → persist account → secret input on
          the account page → SecretStore write → bounded probe. The browser does not write
          SecretStore and does not call the Provider.
        </p>
        <label>
          Display name
          <input name="display_name" required />
        </label>
        <label>
          Kind
          <select
            name="provider_kind"
            required
            value={kind}
            onChange={(event) => setKind(event.target.value as (typeof PROVIDER_KINDS)[number])}
          >
            {PROVIDER_KINDS.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </label>
        <label>
          Endpoint
          <input name="endpoint" placeholder="only for openai_compatible" />
        </label>
        <label>
          <input
            type="checkbox"
            name="allow_private_network"
            checked={allowPrivate}
            onChange={(event) => setAllowPrivate(event.target.checked)}
          />{" "}
          Allow private network
        </label>
        <label>
          <input
            type="checkbox"
            name="allow_insecure_http"
            checked={allowInsecure}
            onChange={(event) => setAllowInsecure(event.target.checked)}
          />{" "}
          Allow insecure HTTP
        </label>
        {needsTrust ? (
          <label>
            <input
              type="checkbox"
              name="trust_confirmed"
              checked={trustConfirmed}
              onChange={(event) => setTrustConfirmed(event.target.checked)}
            />{" "}
            I confirm this private-network or HTTP endpoint grant
          </label>
        ) : null}
        <button type="submit">Create account</button>
      </form>
      <p role="status">{message}</p>
      <table>
        <caption>Provider accounts (SecretRef shown only as present/absent)</caption>
        <thead>
          <tr>
            <th>Id</th>
            <th>Name</th>
            <th>Kind</th>
            <th>Status</th>
            <th>Secret</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={String(row.id)}>
              <td>{String(row.id)}</td>
              <td>{String(row.display_name ?? "")}</td>
              <td>{String(row.provider_kind ?? "")}</td>
              <td>{String(row.status ?? "unknown")}</td>
              <td>{secretPresence(row.secret_ref)}</td>
              <td>
                <NavLink to={`/providers/${encodeURIComponent(String(row.id))}`}>Open</NavLink>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function ProviderDetailPage() {
  const { id } = useParams();
  const [account, setAccount] = useState<LoadState>({ status: "loading" });
  const [models, setModels] = useState<LoadState>({ status: "loading" });
  const [key, setKey] = useState("");
  const [probeClass, setProbeClass] = useState("unknown");
  const [message, setMessage] = useState("Key field is memory-only and cleared after submit.");

  async function refresh() {
    if (!id) {
      return;
    }
    setAccount(
      await load(
        `/management/providers/accounts/inspect?id=${encodeURIComponent(id)}`,
        "management",
      ),
    );
    setModels(
      await load(`/management/providers/models?account_id=${encodeURIComponent(id)}`, "management"),
    );
  }

  useEffect(() => {
    void refresh();
  }, [id]);

  async function rotate(event: React.FormEvent) {
    event.preventDefault();
    const apiKey = key;
    setKey("");
    const op = secretPresence(record.secret_ref) === "present" ? "rotate" : "set";
    const body = { id, op, api_key: apiKey };
    rejectCallerHeaderInjection(body);
    const result = await readJson("/management/providers/accounts/key", "management", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const probe = classifyProbe({
      ok: result.ok,
      httpStatus: result.status,
      body: result.body,
    });
    setProbeClass(probe.class);
    setMessage(
      result.ok
        ? `Key handed to daemon SecretStore path. Probe class ${probe.label}. Response redacted.`
        : `HTTP ${result.status} ${String(asRecord(result.body).code ?? "")} · ${probe.label}`,
    );
    await refresh();
  }

  async function probe() {
    const result = await readJson("/management/providers/models/refresh", "management", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id }),
    });
    const classified = classifyProbe({
      ok: result.ok,
      httpStatus: result.status,
      body: result.body,
    });
    setProbeClass(classified.class);
    setMessage(
      result.ok
        ? `Reachability not implied. Model discovery ${classified.label} in ${result.ms} ms. Capability ${capabilityDisposition(undefined)}.`
        : `Probe HTTP ${result.status} · ${classified.label} · ${classified.nextAction}`,
    );
    await refresh();
  }

  async function removeKey() {
    const result = await readJson("/management/providers/accounts/key", "management", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id, op: "remove" }),
    });
    setMessage(result.ok ? "Key removed; account revoked." : `HTTP ${result.status}`);
    await refresh();
  }

  async function addModel(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const result = await readJson("/management/providers/models/add", "management", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        account_id: id,
        model_id: String(form.get("model_id") ?? ""),
      }),
    });
    setMessage(
      result.ok
        ? "Manual model stored. Last catalog remains on failed refresh."
        : `HTTP ${result.status} ${String(asRecord(result.body).code ?? "")}`,
    );
    event.currentTarget.reset();
    await refresh();
  }

  async function deleteAccount() {
    const result = await readJson("/management/providers/accounts/delete", "management", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id }),
    });
    setMessage(
      result.ok
        ? "Account deleted."
        : `HTTP ${result.status} ${String(asRecord(result.body).code ?? "")}. Active Agent bindings block delete.`,
    );
    await refresh();
  }

  const record = asRecord(asRecord(account.body).account ?? account.body);
  const modelRows = asList(models.body, ["models", "items"]).map(asRecord);

  return (
    <>
      <h2>Provider account</h2>
      <StateNote state={account} />
      <section className="panel">
        <p>Status: {String(record.status ?? "unknown")}</p>
        <p>Kind: {String(record.provider_kind ?? "unknown")}</p>
        <p>Endpoint: {String(record.endpoint ?? "unknown")}</p>
        <p>Network scope: {String(record.network_scope ?? "unknown")}</p>
        <p>Catalog revision: {String(record.catalog_revision ?? "unknown")}</p>
        <p>Secret: {secretPresence(record.secret_ref)}</p>
        <p>Last discovery error: {String(record.last_discovery_error ?? "none")}</p>
        <p>Probe class: {probeClass}</p>
        <p>Capability: {capabilityDisposition(undefined)}</p>
      </section>
      <form onSubmit={rotate}>
        <h3>SecretStore handoff</h3>
        <p className="muted">
          The key is sent once on the management channel and cleared from this field. SecretRef is
          not a resolvable credential in the browser.
        </p>
        <label>
          API key
          <input
            type="password"
            autoComplete="off"
            value={key}
            onChange={(event) => setKey(event.target.value)}
          />
        </label>
        <button type="submit">Set or rotate key via daemon</button>
        <button type="button" onClick={() => void removeKey()}>
          Remove key
        </button>
      </form>
      <button type="button" onClick={() => void probe()}>
        Bounded model/capability probe
      </button>
      <form onSubmit={(event) => void addModel(event)}>
        <h3>Add model manually</h3>
        <p className="muted">
          Use this when discovery is degraded. Failed refresh must keep the last catalog. Do not
          display unknown or cost_unavailable as zero or ready.
        </p>
        <label>
          Model id
          <input name="model_id" required placeholder="deepseek-chat" />
        </label>
        <button type="submit">Add model</button>
      </form>
      <button type="button" onClick={() => void deleteAccount()}>
        Delete account
      </button>
      <p role="status">{message}</p>
      <table>
        <caption>Catalog (failed refresh must keep the last catalog)</caption>
        <thead>
          <tr>
            <th>Model</th>
            <th>Source</th>
            <th>Input cost</th>
            <th>Output cost</th>
          </tr>
        </thead>
        <tbody>
          {modelRows.map((model) => (
            <tr key={String(model.model_id)}>
              <td>{String(model.model_id)}</td>
              <td>{String(model.source ?? "unknown")}</td>
              <td>{displayCost(model.price_input_per_million)}</td>
              <td>{displayCost(model.price_output_per_million)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function BindingsPage() {
  const [bindings, setBindings] = useState<LoadState>({ status: "loading" });
  const [accounts, setAccounts] = useState<LoadState>({ status: "loading" });
  const [models, setModels] = useState<LoadState>({ status: "empty" });
  const [runtime, setRuntime] = useState<LoadState>({ status: "empty" });
  const [selected, setSelected] = useState<LoadState>({ status: "empty" });
  const [agent, setAgent] = useState("pi");
  const [accountId, setAccountId] = useState("");
  const [message, setMessage] = useState("At most one active fixed account+model per Agent.");
  const [applying, setApplying] = useState(false);

  async function refresh() {
    setBindings(await load("/management/agent-bindings", "management"));
    setAccounts(await load("/management/providers/accounts", "management"));
    setRuntime(await load("/personal/dsh/runtime", "management"));
    setSelected(await load("/provider/v1/dsh/selected-model", "management"));
  }

  useEffect(() => {
    void refresh();
  }, []);

  useEffect(() => {
    if (!accountId) {
      setModels({ status: "empty" });
      return;
    }
    void (async () => {
      setModels(
        await load(
          `/management/providers/models?account_id=${encodeURIComponent(accountId)}`,
          "management",
        ),
      );
    })();
  }, [accountId]);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const modelId = String(form.get("model_id") ?? "");
    const expectedRevision = Number(form.get("expected_revision"));
    const current = asList(bindings.body, ["bindings", "items"])
      .map(asRecord)
      .find(
        (row) =>
          String(row.status) === "active" &&
          (String(row.agent).endsWith(agent) || String(row.agent) === agent),
      );
    const account = asList(accounts.body, ["accounts", "items"])
      .map(asRecord)
      .find((row) => row.id === accountId);
    const currentRevision = bindingRevisionForCas(current);
    const gate = acceptBindingMutation({
      expectedRevision: Number.isFinite(expectedRevision) ? expectedRevision : undefined,
      currentRevision,
      fallback: form.get("fallback") === "on",
      perRequestOverride: form.get("per_request") === "on",
    });
    if (!gate.ok) {
      setMessage(gate.reason);
      return;
    }
    const confirmed = form.get("confirm_binding") === "on";
    if (!confirmed) {
      setMessage(
        `Confirm the fixed binding: agent ${agent}, account ${accountId}, model ${modelId}, expected revision ${expectedRevision}. No fallback.`,
      );
      return;
    }
    const result = await readJson("/management/agent-bindings", "management", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        agent,
        account_id: accountId,
        model_id: modelId,
        expected_revision: expectedRevision,
      }),
    });
    const callable = dispatchAllowed({
      accountStatus: account ? String(account.status) : undefined,
      bindingStatus: "active",
    });
    setMessage(
      result.ok
        ? `Binding stored. Dispatch ${callable ? "allowed" : "blocked until the account is usable"}.`
        : `HTTP ${result.status} ${String(asRecord(result.body).code ?? "")}`,
    );
    await refresh();
  }

  async function remove(target: string) {
    const result = await readJson("/management/agent-bindings/remove", "management", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ agent: target }),
    });
    const code = String(asRecord(result.body).code ?? "");
    setMessage(
      result.ok
        ? "Binding removed. The next set uses expected revision 0."
        : result.status === 404 || code === "PROVIDER_CONTROL_NOT_FOUND"
          ? "No active binding to remove. Set a new model with expected revision 0."
          : `HTTP ${result.status} ${code}`,
    );
    await refresh();
  }

  async function applyDsh() {
    const dshRow = activeRows.find(
      (row) => String(row.agent).endsWith("dsh") || String(row.agent) === "dsh",
    );
    const runtimeBody = asRecord(runtime.body);
    const catalogIds = modelRows.map((model) => String(model.model_id));
    const sameAccountCatalog =
      dshRow && accountId && String(dshRow.account_id) === accountId && catalogIds.length > 0;
    const gate = acceptDshApply({
      agent: "dsh",
      bindingStatus: dshRow ? String(dshRow.status) : undefined,
      modelId: dshRow ? String(dshRow.model_id) : undefined,
      catalogModelIds: sameAccountCatalog ? catalogIds : undefined,
      runtimeState: runtimeBody.state ? String(runtimeBody.state) : undefined,
      processAlive: runtimeBody.process_alive === undefined ? undefined : Boolean(runtimeBody.process_alive),
    });
    if (!gate.ok) {
      setMessage(gate.reason);
      return;
    }
    setApplying(true);
    const result = await readJson("/personal/dsh/runtime", "management", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        schema_version: 1,
        surface: "personal-dsh-runtime",
        op: "apply",
        expected_revision: bindingRevisionForCas(dshRow),
      }),
    });
    setApplying(false);
    const applied = asRecord(result.body);
    setMessage(
      result.ok
        ? `Applied ${String(applied.applied_model ?? dshRow?.model_id)}. Conversation and Models show this Cos model after Cos-installed web restart. Path B uses the bound account (never DeepSeek for grok).`
        : `HTTP ${result.status} ${String(applied.code ?? "")}`,
    );
    await refresh();
  }

  const rows = asList(bindings.body, ["bindings", "items"]).map(asRecord);
  const activeRows = rows.filter((row) => String(row.status) === "active");
  const accountRows = asList(accounts.body, ["accounts", "items"]).map(asRecord);
  const modelRows = asList(models.body, ["models", "items"]).map(asRecord);
  const current = activeRows.find(
    (row) => String(row.agent).endsWith(agent) || String(row.agent) === agent,
  );
  const expectedDefault = bindingRevisionForCas(current);
  const dshRow = activeRows.find(
    (row) => String(row.agent).endsWith("dsh") || String(row.agent) === "dsh",
  );
  const applyGate = acceptDshApply({
    agent: "dsh",
    bindingStatus: dshRow ? String(dshRow.status) : undefined,
    modelId: dshRow ? String(dshRow.model_id) : undefined,
    catalogModelIds:
      dshRow && accountId && String(dshRow.account_id) === accountId && modelRows.length > 0
        ? modelRows.map((model) => String(model.model_id))
        : undefined,
    runtimeState: asRecord(runtime.body).state ? String(asRecord(runtime.body).state) : undefined,
    processAlive:
      asRecord(runtime.body).process_alive === undefined
        ? undefined
        : Boolean(asRecord(runtime.body).process_alive),
  });

  return (
    <>
      <h2>Agent Provider bindings</h2>
      <StateNote state={bindings} />
      <form onSubmit={submit}>
        <p className="muted">
          One active <code>account + provider + model</code> per Agent. Only an{" "}
          <code>active</code> binding occupies <code>expected_revision</code>; a revoked
          row is 0 so a new catalog model (including larger ids) can be set. Stale
          expected_revision is rejected by the daemon. Unbound, revoked, or degraded
          accounts cannot dispatch.
        </p>
        <label>
          Agent
          <select name="agent" required value={agent} onChange={(event) => setAgent(event.target.value)}>
            <option value="pi">pi</option>
            <option value="dsh">dsh</option>
          </select>
        </label>
        <label>
          Account
          <select
            name="account_id"
            required
            value={accountId}
            onChange={(event) => setAccountId(event.target.value)}
          >
            <option value="">Select account</option>
            {accountRows.map((row) => (
              <option key={String(row.id)} value={String(row.id)}>
                {String(row.display_name ?? row.id)} ({String(row.status ?? "unknown")})
              </option>
            ))}
          </select>
        </label>
        <label>
          Model
          <select name="model_id" required>
            {modelRows.map((model) => (
              <option key={String(model.model_id)} value={String(model.model_id)}>
                {String(model.model_id)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Expected revision
          <input name="expected_revision" type="number" required defaultValue={expectedDefault} key={expectedDefault} />
        </label>
        <label>
          <input type="checkbox" name="confirm_binding" /> Confirm this exact Agent, account, model,
          and revision
        </label>
        <label>
          <input type="checkbox" name="fallback" /> Request fallback (must be rejected)
        </label>
        <label>
          <input type="checkbox" name="per_request" /> Per-request override (must be rejected)
        </label>
        <button type="submit">Confirm fixed binding</button>
      </form>
      <section>
        <h3>Apply Cos model to running dsh</h3>
        <p className="muted">
          Apply publishes the Cos dsh binding. Restart Cos-installed web
          (`cognitive dsh apply`) so conversation and Models show{" "}
          <code>{String(asRecord(selected.body).selected_model ?? "unset")}</code>
          {" "}(digest{" "}
          <code>{String(asRecord(selected.body).selected_snapshot_digest ?? "none")}</code>
          ). Chat uses that bound account — grok is never posted to DeepSeek. Runtime{" "}
          <code>{String(asRecord(runtime.body).state ?? "unknown")}</code>.
        </p>
        <button
          type="button"
          disabled={applying || !applyGate.ok}
          onClick={() => void applyDsh()}
        >
          Apply to running dsh
        </button>
        {!applyGate.ok ? <p className="muted">{applyGate.reason}</p> : null}
      </section>
      <p role="status">{message}</p>
      <table>
        <caption>Active fixed bindings (revoked rows are omitted so Remove/set can proceed)</caption>
        <thead>
          <tr>
            <th>Agent</th>
            <th>Account</th>
            <th>Model</th>
            <th>Revision</th>
            <th>Status</th>
            <th>Dispatch</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {activeRows.map((row) => {
            const account = accountRows.find((item) => item.id === row.account_id);
            const callable = dispatchAllowed({
              accountStatus: account ? String(account.status) : "unknown",
              bindingStatus: String(row.status),
            });
            return (
              <tr key={String(row.agent)}>
                <td>{String(row.agent)}</td>
                <td>{String(row.account_id)}</td>
                <td>{String(row.model_id)}</td>
                <td>{String(row.revision)}</td>
                <td>{String(row.status)}</td>
                <td>{callable ? "callable" : "blocked"}</td>
                <td>
                  <button type="button" onClick={() => void remove(String(row.agent))}>
                    Remove
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </>
  );
}

function TasksPage() {
  const [effects, setEffects] = useState<LoadState>({ status: "loading" });
  const [observation, setObservation] = useState<LoadState>({ status: "loading" });
  const [evidence, setEvidence] = useState<LoadState>({ status: "empty" });
  const watch = useMemo(() => createWatchController(), []);
  const [watchState, setWatchState] = useState(watch.state);
  const [taskRef, setTaskRef] = useState("");
  const [objective, setObjective] = useState("search the workspace for needle");
  const [previewDigest, setPreviewDigest] = useState("");
  const [interpretationId, setInterpretationId] = useState("");
  const [acceptedDigest, setAcceptedDigest] = useState("");
  const [draft, setDraft] = useState<ReturnType<typeof workspaceSearchDraft> | null>(null);
  const [runMessage, setRunMessage] = useState("Admit uses the typed Task channel only.");
  const [resumeFrom, setResumeFrom] = useState<number | undefined>(undefined);

  async function refresh(ref: string) {
    if (!ref) {
      return;
    }
    const encoded = encodeURIComponent(ref);
    setEffects(await load(`/task/effects?task_ref=${encoded}`, "task"));
    setObservation(await load(`/task/observation?task_ref=${encoded}`, "task"));
    const nextEvidence = await load(`/task/evidence?task_ref=${encoded}`, "task");
    setEvidence(nextEvidence);
    const inferred = inferCompletionFromObservation({
      processExit: 0,
      providerResponse: observation.body,
      httpReceipt: nextEvidence.body,
      streamClosed: true,
    });
    if (inferred !== "unknown") {
      watch.noteGap();
    }
    setWatchState(watch.state);
  }

  async function pollWatch() {
    const path =
      resumeFrom == null ? "/task/watch" : `/task/watch?resume_from=${encodeURIComponent(String(resumeFrom))}`;
    const result = await readJson(path, "task");
    if (isWatchResumeStale(result.status, result.body)) {
      watch.noteGap();
      setWatchState(watch.state);
      setResumeFrom(undefined);
      setRunMessage("Watch cursor gap: snapshot reload required. Completion stays unknown.");
      return;
    }
    const text =
      typeof result.body === "string"
        ? result.body
        : typeof asRecord(result.body).raw === "string"
          ? String(asRecord(result.body).raw)
          : JSON.stringify(result.body ?? {});
    const frames = parseSse(text);
    for (const frame of frames) {
      const id = frame.id ?? JSON.stringify(frame.data);
      watch.accept({
        id,
        cursor: frame.id ?? String(latestSequence(frames) ?? ""),
        kind: frame.event,
      });
    }
    const latest = latestSequence(frames);
    if (latest != null) {
      setResumeFrom(latest);
    }
    setWatchState(watch.state);
  }

  async function startTask(event: React.FormEvent) {
    event.preventDefault();
    const principal = sessionPrincipal();
    const recorded = await readJson("/task/intent.record", "task", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        schema_version: "cognitiveos.task-intent-record-request/0.1",
        conversation_or_scope_ref: "conversation://personal/web-ui",
        raw_expression: objective,
      }),
    });
    if (!recorded.ok) {
      setRunMessage(`intent.record HTTP ${recorded.status}`);
      return;
    }
    const userIntentRecordId = String(asRecord(recorded.body).user_intent_record_id ?? "");
    const interpreted = await readJson("/task/intent.interpret", "task", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        schema_version: "cognitiveos.task-intent-interpret-request/0.1",
        user_intent_record_id: userIntentRecordId,
        candidate: interpretCandidate(objective),
      }),
    });
    if (!interpreted.ok) {
      setRunMessage(`intent.interpret HTTP ${interpreted.status}`);
      return;
    }
    const nextDraft = workspaceSearchDraft(objective);
    setDraft(nextDraft);
    const previewed = await readJson("/task/preview", "task", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        schema_version: "cognitiveos.task-preview-request/0.1",
        task_contract_draft: nextDraft,
      }),
    });
    if (!previewed.ok) {
      setRunMessage(`preview HTTP ${previewed.status}`);
      return;
    }
    const digest = String(asRecord(previewed.body).preview_digest ?? "");
    setPreviewDigest(digest);
    setInterpretationId(String(asRecord(interpreted.body).interpretation_id ?? ""));
    setAcceptedDigest(String(asRecord(interpreted.body).interpretation_digest ?? ""));
    setRunMessage(
      `Preview ready for ${principal}. Digest bound. Confirm admit; HTTP 200 is not Task completion.`,
    );
  }

  async function admitTask() {
    if (!draft || !previewDigest || !interpretationId) {
      setRunMessage("Preview first.");
      return;
    }
    const principal = sessionPrincipal();
    const admitted = await readJson("/task/admit", "task", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        schema_version: "cognitiveos.task-admit-request/0.1",
        expected_current_epoch: 0,
        preview_digest: previewDigest,
        task_contract_draft: draft,
        acceptance: {
          accepted_by: principal,
          accepted_digest: acceptedDigest,
          interpretation_id: interpretationId,
        },
      }),
    });
    const ref = String(asRecord(admitted.body).task_ref ?? draft.task_ref);
    setTaskRef(ref);
    setRunMessage(
      admitted.ok
        ? `Admitted ${ref}. Watch and projections are observations, not completion.`
        : `admit HTTP ${admitted.status} ${String(asRecord(admitted.body).code ?? "")}`,
    );
    if (admitted.ok) {
      await refresh(ref);
      await pollWatch();
    }
  }

  useEffect(() => {
    if (taskRef) {
      void refresh(taskRef);
    }
  }, [taskRef]);

  return (
    <>
      <h2>Tasks, Effects, Evidence</h2>
      <p className="muted">
        Cancel is {unavailableLabel("task-cancel")}. Detach does not cancel a Task or stop an Agent.
        Process/Provider/Pi/HTTP receipt is not Task completion.
      </p>
      <form onSubmit={(event) => void startTask(event)}>
        <h3>Start a governed Task</h3>
        <label>
          Objective
          <input
            name="objective"
            value={objective}
            onChange={(event) => setObjective(event.target.value)}
          />
        </label>
        <button type="submit">Record, interpret, and preview</button>
        <button type="button" onClick={() => void admitTask()}>
          Confirm admit
        </button>
      </form>
      <p className="muted">
        Preview digest: {previewDigest || "none"}. Interpretation: {interpretationId || "none"}.
      </p>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          const next = String(new FormData(event.currentTarget).get("task_ref") ?? "");
          setTaskRef(next);
        }}
      >
        <label>
          Task ref
          <input name="task_ref" defaultValue={taskRef} key={taskRef} />
        </label>
        <button type="submit">Load projections</button>
        <button
          type="button"
          onClick={() => {
            void pollWatch();
          }}
        >
          Watch poll
        </button>
        <button
          type="button"
          onClick={() => {
            watch.reconnect();
            setResumeFrom(undefined);
            setWatchState(watch.state);
          }}
        >
          Reconnect snapshot
        </button>
        <button
          type="button"
          onClick={() => {
            watch.noteGap();
            setWatchState(watch.state);
          }}
        >
          Simulate cursor gap
        </button>
        <button
          type="button"
          onClick={() => {
            watch.detach();
            setWatchState(watch.state);
          }}
        >
          Detach observation
        </button>
      </form>
      <p className="live" role="status" aria-live="polite">
        Watch {watchState}. Completion from observation remains unknown. {runMessage}
      </p>
      <StateNote state={effects} />
      <JsonPanel title="Effects" value={effects.body} />
      <JsonPanel title="Evidence" value={evidence.body} />
      <JsonPanel
        title="Observation (escaped)"
        value={escapeUntrustedText(JSON.stringify(observation.body ?? {}, null, 2))}
      />
    </>
  );
}

function ActivityPage() {
  const [usage, setUsage] = useState<LoadState>({ status: "loading" });
  const [budgets, setBudgets] = useState<LoadState>({ status: "loading" });
  const [alerts, setAlerts] = useState<LoadState>({ status: "loading" });
  const [audit, setAudit] = useState<LoadState>({ status: "loading" });

  useEffect(() => {
    void (async () => {
      setUsage(await load("/management/usage", "management"));
      setBudgets(await load("/management/budgets", "management"));
      setAlerts(await load("/management/alerts", "management"));
      setAudit(await load("/management/audit", "management"));
    })();
  }, []);

  return (
    <>
      <h2>Activity</h2>
      <StateNote state={usage} />
      <JsonPanel title="Usage" value={usage.body} />
      <JsonPanel title="Budgets" value={budgets.body} />
      <JsonPanel title="Alerts" value={alerts.body} />
      <JsonPanel title="Audit" value={audit.body} />
    </>
  );
}

function ResourcesPage() {
  const families = ["tool", "memory", "skill", "task", "context", "runtime"] as const;
  const [family, setFamily] = useState<(typeof families)[number]>("tool");
  const [list, setList] = useState<LoadState>({ status: "loading" });

  useEffect(() => {
    void (async () => {
      setList(await load(`/management/resource/v1/list?family=${family}`, "management"));
    })();
  }, [family]);

  return (
    <>
      <h2>Six-family resources</h2>
      <label>
        Family
        <select value={family} onChange={(event) => setFamily(event.target.value as typeof family)}>
          {families.map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
      </label>
      <StateNote state={list} />
      <JsonPanel title={`${family} list`} value={list.body} />
    </>
  );
}

export function App() {
  return (
    <HashRouter>
      <SessionScope>
        <Shell>
          <Routes>
            <Route path="/session" element={<SessionPage />} />
            <Route
              path="/"
              element={
                <RequireSession channel="management" title="Home">
                  <HomePage />
                </RequireSession>
              }
            />
            <Route
              path="/agents"
              element={
                <RequireSession channel="management" title="Agents">
                  <AgentsPage />
                </RequireSession>
              }
            />
            <Route
              path="/agents/:id"
              element={
                <RequireSession channel="management" title="Agent detail">
                  <AgentDetailPage />
                </RequireSession>
              }
            />
            <Route
              path="/providers"
              element={
                <RequireSession channel="management" title="Providers">
                  <ProvidersPage />
                </RequireSession>
              }
            />
            <Route
              path="/providers/:id"
              element={
                <RequireSession channel="management" title="Provider account">
                  <ProviderDetailPage />
                </RequireSession>
              }
            />
            <Route
              path="/bindings"
              element={
                <RequireSession channel="management" title="Agent Provider bindings">
                  <BindingsPage />
                </RequireSession>
              }
            />
            <Route
              path="/tasks"
              element={
                <RequireSession channel="task" title="Tasks">
                  <TasksPage />
                </RequireSession>
              }
            />
            <Route
              path="/activity"
              element={
                <RequireSession channel="management" title="Activity">
                  <ActivityPage />
                </RequireSession>
              }
            />
            <Route
              path="/resources"
              element={
                <RequireSession channel="management" title="Resources">
                  <ResourcesPage />
                </RequireSession>
              }
            />
          </Routes>
        </Shell>
      </SessionScope>
    </HashRouter>
  );
}
