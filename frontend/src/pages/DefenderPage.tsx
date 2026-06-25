/**
 * DefenderPage — soc_god autonomous blue-team control surface.
 *
 * Surfaces: status counters, enable/defended-host controls, a live SLIPS alert
 * feed, a manual plan inspector, and a best-effort WebSocket event log.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Shield,
  ShieldAlert,
  Activity,
  Bell,
  Server,
  Cpu,
  Play,
  Loader2,
  AlertTriangle,
} from 'lucide-react';
import {
  getDefenderStatus,
  enableDefender,
  getRecentAlerts,
  getDefendedHosts,
  getPlannerHealth,
  planDefender,
  getTopologies,
  getTopology,
  getErrorMessage,
  type Topology,
  type DefenderStatus,
  type DefenderAlert,
  type DefendedHost,
  type PlannerHealth,
  type PlannerPlanResponse,
} from '../api';

const POLL_STATUS_MS = 2000;
const POLL_ALERTS_MS = 3000;

function threatTone(alert: DefenderAlert): string {
  const tl = String(alert.threat_level || alert.severity || '').toLowerCase();
  const conf = Number(alert.confidence);
  if (tl === 'high' || conf >= 0.9) return 'text-red-400 border-red-500/40 bg-red-500/5 dark:text-red-300 dark:border-red-400/30';
  if (tl === 'medium' || conf >= 0.7) return 'text-amber-400 border-amber-500/40 bg-amber-500/5 dark:text-amber-300 dark:border-amber-400/30';
  return 'text-trident-muted border-trident-border bg-trident-surface';
}

function Counter({
  icon: Icon,
  label,
  value,
  tone = 'text-trident-text',
}: {
  icon: typeof Activity;
  label: string;
  value: number | string;
  tone?: string;
}) {
  return (
    <div className="rounded-lg border border-trident-border bg-trident-surface p-4">
      <div className="flex items-center gap-2 text-trident-muted">
        <Icon size={15} />
        <span className="text-xs uppercase tracking-wide">{label}</span>
      </div>
      <div className={`mt-2 font-heading text-2xl font-bold ${tone}`}>{value}</div>
    </div>
  );
}

export function DefenderPage() {
  const [status, setStatus] = useState<DefenderStatus | null>(null);
  const [alerts, setAlerts] = useState<DefenderAlert[]>([]);
  const [planner, setPlanner] = useState<PlannerHealth | null>(null);
  const [events, setEvents] = useState<{ type: string; data: any; at: number }[]>([]);

  // Topology + defended-host controls
  const [topologies, setTopologies] = useState<Topology[]>([]);
  const [topologyId, setTopologyId] = useState('');
  const [hosts, setHosts] = useState<{ id: string; name: string }[]>([]);
  const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set());
  const [defended, setDefended] = useState<DefendedHost[]>([]);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  // Plan inspector
  const [alertText, setAlertText] = useState('');
  const [plan, setPlan] = useState<PlannerPlanResponse | null>(null);
  const [planning, setPlanning] = useState(false);

  // ---- polling ----
  useEffect(() => {
    let alive = true;
    const load = () =>
      getDefenderStatus()
        .then((s) => alive && setStatus(s))
        .catch(() => {});
    load();
    const t = setInterval(load, POLL_STATUS_MS);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  useEffect(() => {
    let alive = true;
    const load = () =>
      getRecentAlerts(50)
        .then((r) => alive && setAlerts(r.alerts))
        .catch(() => {});
    load();
    const t = setInterval(load, POLL_ALERTS_MS);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  useEffect(() => {
    getPlannerHealth()
      .then(setPlanner)
      .catch(() => {});
  }, []);

  // ---- topology list ----
  useEffect(() => {
    getTopologies()
      .then((r) => setTopologies(r.topologies || []))
      .catch(() => {});
  }, []);

  // ---- when topology changes, load its hosts + current defended set ----
  useEffect(() => {
    if (!topologyId) {
      setHosts([]);
      setSelectedHosts(new Set());
      setDefended([]);
      return;
    }
    getTopology(topologyId)
      .then((t) => {
        const flat = (t.networks || []).flatMap((n) => n.hosts || []);
        setHosts(flat.map((h) => ({ id: h.id, name: h.name || h.id })));
      })
      .catch(() => setHosts([]));
    // Reflect already-saved policy from status.
    const policy = status?.policy?.[topologyId];
    if (policy) setSelectedHosts(new Set(policy.host_ids));
    getDefendedHosts(topologyId)
      .then((r) => setDefended(r.hosts))
      .catch(() => setDefended([]));
  }, [topologyId, status]);

  // ---- best-effort live event stream (raw WS; defender events are {type,data}) ----
  const wsRef = useRef<WebSocket | null>(null);
  useEffect(() => {
    const wsUrl =
      (import.meta.env.VITE_WS_BASE_URL as string | undefined) ??
      `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}`;
    let ws: WebSocket | null = null;
    try {
      ws = new WebSocket(`${wsUrl}/ws/events`);
      wsRef.current = ws;
      ws.onmessage = (ev) => {
        try {
          const m = JSON.parse(ev.data);
          if (typeof m?.type === 'string' && m.type.startsWith('defender_')) {
            setEvents((prev) =>
              [{ type: m.type, data: m.data ?? {}, at: Date.now() }, ...prev].slice(0, 50)
            );
          }
        } catch {
          /* ignore */
        }
      };
      ws.onerror = () => {};
    } catch {
      /* ignore */
    }
    return () => {
      try {
        ws?.close();
      } catch {
        /* ignore */
      }
    };
  }, []);

  const toggleHost = (id: string) =>
    setSelectedHosts((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const doEnable = async (enabled: boolean) => {
    if (!topologyId) return;
    setBusy(true);
    setMsg(null);
    try {
      await enableDefender(topologyId, Array.from(selectedHosts), enabled);
      setMsg({ kind: 'ok', text: `Defender ${enabled ? 'enabled' : 'disabled'} for ${topologyId}` });
      const r = await getDefendedHosts(topologyId);
      setDefended(r.hosts);
    } catch (e) {
      setMsg({ kind: 'err', text: getErrorMessage(e) });
    } finally {
      setBusy(false);
    }
  };

  const doPlan = async () => {
    if (!alertText.trim()) return;
    setPlanning(true);
    setPlan(null);
    try {
      const r = await planDefender(alertText, undefined, topologyId || undefined);
      setPlan(r);
    } catch (e) {
      setMsg({ kind: 'err', text: getErrorMessage(e) });
    } finally {
      setPlanning(false);
    }
  };

  const c = status?.counters;
  const policyEntry = topologyId ? status?.policy?.[topologyId] : undefined;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-trident-accent">
            <Shield className="text-white" size={20} />
          </div>
          <div>
            <h1 className="font-heading text-2xl font-bold text-trident-text">Defender</h1>
            <p className="text-sm text-trident-muted">
              Autonomous blue-team (soc_god) — IDS alerts drive containment on defended hosts.
            </p>
          </div>
        </div>
        <div className="text-right text-xs text-trident-muted">
          <div>
            run_id: <span className="font-mono text-trident-text truncate max-w-[200px] inline-block align-bottom" title={status?.run_id}>{status?.run_id ?? '—'}</span>
          </div>
          <div>
            planner:{' '}
            <span className="font-mono text-trident-text truncate max-w-[160px] inline-block align-bottom" title={planner?.model}>{planner?.model ?? '—'}</span>{' '}
            <span
              className={
                planner?.llm_configured ? 'text-emerald-400' : 'text-amber-400'
              }
            >
              {planner ? (planner.llm_configured ? 'configured' : 'misconfigured') : ''}
            </span>
          </div>
        </div>
      </div>

      {/* Counters */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
        <Counter icon={Bell} label="Alerts received" value={c?.alerts_received ?? 0} />
        <Counter
          icon={AlertTriangle}
          label="Dropped (non-defended)"
          value={c?.alerts_dropped_nondefended ?? 0}
          tone="text-amber-400"
        />
        <Counter
          icon={Activity}
          label="Dropped (duplicate)"
          value={c?.alerts_dropped_duplicate ?? 0}
          tone="text-trident-muted"
        />
        <Counter icon={Cpu} label="Plans generated" value={c?.plans_generated ?? 0} />
        <Counter
          icon={Shield}
          label="soc_god sessions"
          value={c?.soc_god_sessions_created ?? 0}
          tone="text-emerald-400"
        />
        <Counter
          icon={ShieldAlert}
          label="Session failures"
          value={c?.soc_god_sessions_failed ?? 0}
          tone={c?.soc_god_sessions_failed ? 'text-red-400' : 'text-trident-text'}
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Enable / defended hosts */}
        <section className="rounded-lg border border-trident-border bg-trident-surface p-5">
          <h2 className="mb-3 font-heading text-lg font-semibold text-trident-text">
            Defended hosts
          </h2>
          <div className="space-y-3">
            <select
              value={topologyId}
              onChange={(e) => setTopologyId(e.target.value)}
              className="w-full rounded-md border border-trident-border bg-trident-bg px-3 py-2 text-sm text-trident-text"
            >
              <option value="">Select a topology…</option>
              {topologies.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name || t.id}
                </option>
              ))}
            </select>

            {topologyId && (
              <>
                <div className="text-xs text-trident-muted">
                  Select which hosts soc_god should defend:
                </div>
                <div className="max-h-48 space-y-1 overflow-auto rounded-md border border-trident-border p-2">
                  {hosts.length === 0 && (
                    <div className="px-1 py-2 text-xs text-trident-muted">No hosts in topology.</div>
                  )}
                  {hosts.map((h) => (
                    <label
                      key={h.id}
                      className="flex cursor-pointer items-center gap-2 rounded px-1 py-1 text-sm text-trident-text hover:bg-trident-bg"
                    >
                      <input
                        type="checkbox"
                        checked={selectedHosts.has(h.id)}
                        onChange={() => toggleHost(h.id)}
                        className="accent-trident-accent"
                      />
                      <Server size={14} className="text-trident-muted" />
                      <span>{h.name}</span>
                      <span className="font-mono text-xs text-trident-muted">{h.id}</span>
                    </label>
                  ))}
                </div>

                <div className="flex items-center gap-2">
                  <button
                    disabled={busy || selectedHosts.size === 0}
                    onClick={() => doEnable(true)}
                    className="inline-flex items-center gap-2 rounded-md bg-trident-accent px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
                  >
                    {busy && <Loader2 size={14} className="animate-spin" />}
                    Enable ({selectedHosts.size})
                  </button>
                  <button
                    disabled={busy}
                    onClick={() => doEnable(false)}
                    className="rounded-md border border-trident-border px-3 py-2 text-sm text-trident-muted disabled:opacity-50"
                  >
                    Disable
                  </button>
                  {policyEntry?.enabled && (
                    <span className="text-xs text-emerald-400">
                      active ({policyEntry.host_ids.length} hosts)
                    </span>
                  )}
                </div>
              </>
            )}

            {msg && (
              <div
                className={`rounded-md px-3 py-2 text-xs break-words ${
                  msg.kind === 'ok'
                    ? 'bg-emerald-500/10 text-emerald-400'
                    : 'bg-red-500/10 text-red-400'
                }`}
              >
                {msg.text}
              </div>
            )}

            {defended.length > 0 && (
              <div className="border-t border-trident-border pt-3">
                <div className="mb-1 text-xs uppercase tracking-wide text-trident-muted">
                  Live defended hosts
                </div>
                <ul className="space-y-1">
                  {defended.map((h) => (
                    <li key={h.host_id} className="flex items-center gap-2 text-sm text-trident-text">
                      <Server size={13} className="text-trident-muted" />
                      {h.name}
                      <span className="font-mono text-xs text-trident-muted">{h.ip}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </section>

        {/* Plan inspector */}
        <section className="rounded-lg border border-trident-border bg-trident-surface p-5">
          <h2 className="mb-3 font-heading text-lg font-semibold text-trident-text">
            Plan inspector
          </h2>
          <textarea
            value={alertText}
            onChange={(e) => setAlertText(e.target.value)}
            placeholder="Paste an IDS alert (e.g. 'password guessing from 10.0.0.99 to 10.0.0.5')…"
            className="min-h-[96px] w-full resize-y rounded-md border border-trident-border bg-trident-bg px-3 py-2 font-mono text-xs text-trident-text"
          />
          <button
            disabled={planning || !alertText.trim()}
            onClick={doPlan}
            className="mt-2 inline-flex items-center gap-2 rounded-md bg-trident-accent px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
          >
            {planning ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
            Generate plan
          </button>
          {plan && (
            <div className="mt-3 rounded-md border border-trident-border bg-trident-bg p-3">
              <div className="mb-1 text-xs text-trident-muted">
                target: <span className="font-mono text-trident-text">{plan.plans[0]?.target_host}</span>{' '}
                · model: <span className="font-mono">{plan.model}</span>
              </div>
              <pre className="whitespace-pre-wrap break-words font-mono text-xs text-trident-text">
                {plan.plans[0]?.plan}
              </pre>
            </div>
          )}
        </section>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Alert feed */}
        <section className="rounded-lg border border-trident-border bg-trident-surface p-5">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="font-heading text-lg font-semibold text-trident-text">Alert feed</h2>
            <span className="text-xs text-trident-muted">
              {status?.buffered_alerts ?? 0} buffered
            </span>
          </div>
          <div className="max-h-80 space-y-2 overflow-auto">
            {alerts.length === 0 && (
              <div className="py-6 text-center text-sm text-trident-muted">No alerts yet.</div>
            )}
            {alerts.map((a, i) => (
              <div
                key={i}
                className={`rounded-md border px-3 py-2 text-xs ${threatTone(a)}`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono font-semibold truncate max-w-[200px] inline-block align-bottom" title={a.attackid || a.attack_type || a.id || 'alert'}>
                    {a.attackid || a.attack_type || a.id || 'alert'}
                  </span>
                  <span className="opacity-70">
                    {a.threat_level || a.severity || ''}
                    {a.confidence ? ` · conf ${a.confidence}` : ''}
                  </span>
                </div>
                <div className="mt-1 font-mono opacity-80 break-all">
                  {a.sourceip || a.srcip || '?'} → {a.destip || a.dstip || '?'}
                </div>
                {a.description && (
                  <div className="mt-1 line-clamp-2 opacity-80">{a.description}</div>
                )}
              </div>
            ))}
          </div>
        </section>

        {/* Event log */}
        <section className="rounded-lg border border-trident-border bg-trident-surface p-5">
          <h2 className="mb-3 font-heading text-lg font-semibold text-trident-text">
            Live defender events
          </h2>
          <div className="max-h-80 space-y-1 overflow-auto font-mono text-xs">
            {events.length === 0 && (
              <div className="py-6 text-center text-trident-muted">Listening…</div>
            )}
            {events.map((ev, i) => (
              <div key={i} className="flex gap-2 text-trident-text">
                <span className="text-trident-muted">
                  {new Date(ev.at).toLocaleTimeString()}
                </span>
                <span className="text-trident-accent">{ev.type}</span>
                <span className="truncate text-trident-muted">
                  {ev.data?.target_host || ev.data?.target || ''}
                </span>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
