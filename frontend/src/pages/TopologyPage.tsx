import { useState, useEffect, useCallback, useRef } from 'react';
import { createPortal } from 'react-dom';
import {
  ChevronDown, ChevronRight, Server, Network as NetworkIcon,
  Plus, X, Save, Play, Square, CheckCircle, AlertCircle, Loader2
} from 'lucide-react';
import api from '@/api';
import type { Topology, Network, Host, AgentTemplate } from '@/types';

// ─── Agent catalogue ────────────────────────────────────────────────────────
// Presentation only (label + colour). The *set* of available agents is fetched
// from the backend (GET /api/agents/templates) so the dropdown always reflects
// what actually exists, instead of a hardcoded list that drifts out of sync.
type TemplateMap = Record<string, AgentTemplate>;

const AGENT_STYLE: Record<string, { label?: string; color: string; bg: string }> = {
  coder56:  { label: 'Coder 5.6', color: 'text-violet-700', bg: 'bg-violet-100' },
  db_admin: { label: 'DB Admin',  color: 'text-blue-700',   bg: 'bg-blue-100'   },
  soc_god:  { label: 'SOC God',   color: 'text-red-700',    bg: 'bg-red-100'    },
};

function metaFor(type: string, templates: TemplateMap) {
  const style = AGENT_STYLE[type];
  return {
    label: style?.label ?? templates[type]?.name ?? type,
    color: style?.color ?? 'text-gray-700',
    bg: style?.bg ?? 'bg-gray-100',
  };
}

// ─── List summary type (what /api/topologies returns) ───────────────────────
interface TopologySummary {
  id: string;
  name: string;
  version: string;
  network_count: number;
  host_count: number;
  is_running: boolean;
}

// ─── Agent chip ─────────────────────────────────────────────────────────────
function AgentChip({ agent, templates, onRemove }: { agent: string; templates: TemplateMap; onRemove?: () => void }) {
  const meta = metaFor(agent, templates);
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold ${meta.bg} ${meta.color}`}>
      {meta.label}
      {onRemove && (
        <button onClick={onRemove} className="hover:opacity-60 transition-opacity" title={`Remove ${meta.label}`}>
          <X size={11} />
        </button>
      )}
    </span>
  );
}

// ─── Add-agent dropdown ──────────────────────────────────────────────────────
// Rendered through a portal (document.body) with position: fixed so it escapes
// the overflow-hidden network card and the overflow-auto scroll containers that
// otherwise clip an absolutely-positioned menu (the old "only first agent
// visible / can't scroll" bug).
function AddAgentButton({ currentAgents, agentTypes, templates, onAdd }: {
  currentAgents: string[];
  agentTypes: string[];
  templates: TemplateMap;
  onAdd: (a: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const btnRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const available = agentTypes.filter(a => !currentAgents.includes(a));

  const toggle = () => {
    if (open) { setOpen(false); return; }
    if (available.length === 0) return;
    const r = btnRef.current?.getBoundingClientRect();
    if (!r) return;
    const menuH = Math.min(available.length * 30 + 8, 240);
    let top = r.bottom + 4;
    if (top + menuH > window.innerHeight - 8) top = Math.max(8, r.top - menuH - 4); // flip up if needed
    const left = Math.min(r.left, window.innerWidth - 184);
    setPos({ top, left });
    setOpen(true);
  };

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (menuRef.current?.contains(t) || btnRef.current?.contains(t)) return;
      setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    const close = () => setOpen(false);
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    window.addEventListener('scroll', close, true);
    window.addEventListener('resize', close);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
      window.removeEventListener('scroll', close, true);
      window.removeEventListener('resize', close);
    };
  }, [open]);

  if (available.length === 0) return null;

  return (
    <div className="relative">
      <button
        ref={btnRef}
        onClick={toggle}
        className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold
                   border border-dashed border-gray-400 text-gray-500 hover:border-blue-500 hover:text-blue-600 transition-colors"
      >
        <Plus size={11} /> Add agent
      </button>
      {open && pos && createPortal(
        <div
          ref={menuRef}
          style={{ position: 'fixed', top: pos.top, left: pos.left }}
          className="z-50 max-h-60 w-44 overflow-y-auto bg-white dark:bg-gray-800 rounded-lg shadow-xl border border-gray-200 dark:border-gray-700 py-1"
        >
          {available.map(a => {
            const m = metaFor(a, templates);
            return (
              <button
                key={a}
                onClick={() => { onAdd(a); setOpen(false); }}
                className={`w-full text-left px-3 py-1.5 text-xs font-semibold hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors ${m.color}`}
              >
                {m.label}
              </button>
            );
          })}
        </div>,
        document.body
      )}
    </div>
  );
}

// ─── Host row ────────────────────────────────────────────────────────────────
function HostRow({
  host, agentTypes, templates, onAgentAdd, onAgentRemove,
}: {
  host: Host;
  agentTypes: string[];
  templates: TemplateMap;
  onAgentAdd: (agentType: string) => void;
  onAgentRemove: (agentType: string) => void;
}) {
  const agents = host.agents ?? [];
  return (
    <div className="flex flex-wrap items-center gap-2 p-2 bg-gray-50 dark:bg-gray-800/60 rounded-lg">
      <Server size={14} className="text-green-500 flex-shrink-0" />
      <span className="text-sm font-medium min-w-[100px]">{host.name}</span>
      <span className="text-xs px-2 py-0.5 bg-gray-200 dark:bg-gray-700 rounded-full text-gray-600 dark:text-gray-300">
        {host.type}
      </span>
      <div className="flex flex-wrap items-center gap-1.5 ml-auto">
        {agents.map(a => (
          <AgentChip key={a} agent={a} templates={templates} onRemove={() => onAgentRemove(a)} />
        ))}
        <AddAgentButton currentAgents={agents} agentTypes={agentTypes} templates={templates} onAdd={onAgentAdd} />
      </div>
    </div>
  );
}

// ─── Main page ───────────────────────────────────────────────────────────────
export function TopologyPage() {
  const [summaries, setSummaries] = useState<TopologySummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  // working copy — editable in-place
  const [topology, setTopology] = useState<Topology | null>(null);
  const [expandedNetworks, setExpandedNetworks] = useState<Set<string>>(new Set());

  const [listLoading, setListLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [starting, setStarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);
  // Available agents — authoritative list from /api/agents/templates (falls back
  // to the AGENT_STYLE keys below until the fetch resolves or if it fails).
  const [agentTypes, setAgentTypes] = useState<string[]>(Object.keys(AGENT_STYLE));
  const [templates, setTemplates] = useState<TemplateMap>({});

  const showToast = (msg: string, ok = true) => {
    setToast({ msg, ok });
    setTimeout(() => setToast(null), 3500);
  };

  // Load list
  const loadList = useCallback(() => {
    setListLoading(true);
    api.getTopologies()
      .then((data: any) => { setSummaries(data.topologies ?? []); setListLoading(false); })
      .catch(() => setListLoading(false));
  }, []);

  useEffect(() => { loadList(); }, [loadList]);

  // Load the authoritative list of available agents from the backend.
  const loadAgentTemplates = useCallback(() => {
    api.getAgentTemplates()
      .then((data) => {
        const t = ((data as any).agents ?? {}) as TemplateMap;
        setTemplates(t);
        const keys = Object.keys(t);
        if (keys.length) setAgentTypes(keys);
      })
      .catch(() => { /* keep AGENT_STYLE defaults */ });
  }, []);
  useEffect(() => { loadAgentTemplates(); }, [loadAgentTemplates]);

  // Load detail
  const selectTopology = async (id: string) => {
    setSelectedId(id);
    setDirty(false);
    setDetailLoading(true);
    setExpandedNetworks(new Set());
    try {
      const detail = await api.getTopology(id);
      setTopology(detail);
      // Auto-expand all networks
      setExpandedNetworks(new Set((detail.networks ?? []).map((n: Network) => n.id)));
    } catch {
      showToast('Failed to load topology detail', false);
    } finally {
      setDetailLoading(false);
    }
  };

  const toggleNetwork = (networkId: string) => {
    setExpandedNetworks(prev => {
      const next = new Set(prev);
      next.has(networkId) ? next.delete(networkId) : next.add(networkId);
      return next;
    });
  };

  // ── Mutate agents ──────────────────────────────────────────────────────────
  const mutateHost = (networkId: string, hostId: string, mutateFn: (h: Host) => Host) => {
    setTopology(prev => {
      if (!prev) return prev;
      return {
        ...prev,
        networks: (prev.networks ?? []).map(n =>
          n.id !== networkId ? n : {
            ...n,
            hosts: (n.hosts ?? []).map(h => h.id !== hostId ? h : mutateFn(h))
          }
        )
      };
    });
    setDirty(true);
  };

  const addAgent = (networkId: string, hostId: string, agentType: string) => {
    mutateHost(networkId, hostId, h => ({
      ...h,
      agents: [...(h.agents ?? []).filter(a => a !== agentType), agentType]
    }));
  };

  const removeAgent = (networkId: string, hostId: string, agentType: string) => {
    mutateHost(networkId, hostId, h => ({
      ...h,
      agents: (h.agents ?? []).filter(a => a !== agentType)
    }));
  };

  // ── Save ───────────────────────────────────────────────────────────────────
  const save = async () => {
    if (!topology || !selectedId) return;
    setSaving(true);
    try {
      const saved = await api.saveTopology(selectedId, topology.networks ?? []);
      setTopology(saved);
      setDirty(false);
      // Refresh list to update updated_at timestamp
      loadList();
      showToast('Agents saved ✓');
    } catch (e: any) {
      showToast(e?.message ?? 'Save failed', false);
    } finally {
      setSaving(false);
    }
  };

  // ── Start / Stop ───────────────────────────────────────────────────────────
  const startTopology = async () => {
    if (!selectedId) return;
    // Auto-save first if dirty
    if (dirty) await save();
    setStarting(true);
    try {
      const r = await api.startTopology(selectedId);
      showToast(r.message ?? 'Topology started');
      loadList();
    } catch (e: any) {
      showToast(e?.message ?? 'Start failed', false);
    } finally {
      setStarting(false);
    }
  };

  const stopTopology = async () => {
    if (!selectedId) return;
    setStopping(true);
    try {
      const r = await api.stopTopology(selectedId);
      showToast(r.message ?? 'Topology stopped');
      loadList();
    } catch (e: any) {
      showToast(e?.message ?? 'Stop failed', false);
    } finally {
      setStopping(false);
    }
  };

  const selectedSummary = summaries.find(s => s.id === selectedId);
  const isRunning = selectedSummary?.is_running ?? false;

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="flex h-full flex-col gap-4 overflow-hidden p-6">

      {/* Header */}
      <div className="flex items-center justify-between flex-shrink-0">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Network Topologies</h1>
          <p className="text-sm text-gray-500 mt-0.5">Select a topology, assign agents to hosts, then start.</p>
        </div>
      </div>

      {/* Toast */}
      {toast && (
        <div className={`fixed top-4 right-4 z-50 flex items-center gap-2 px-4 py-2.5 rounded-lg shadow-lg text-sm font-medium
          ${toast.ok ? 'bg-green-50 text-green-800 border border-green-200' : 'bg-red-50 text-red-800 border border-red-200'}`}
        >
          {toast.ok ? <CheckCircle size={16} /> : <AlertCircle size={16} />}
          {toast.msg}
        </div>
      )}

      <div className="grid grid-cols-3 gap-5 flex-1 min-h-0">

        {/* ── Left: topology list ── */}
        <div className="flex flex-col gap-2 overflow-auto">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-gray-500 flex-shrink-0">Topologies</h2>
          {listLoading ? (
            <p className="text-sm text-gray-400">Loading…</p>
          ) : summaries.map(s => (
            <button
              key={s.id}
              onClick={() => selectTopology(s.id)}
              className={`w-full p-3.5 rounded-xl border-2 text-left transition-all ${
                selectedId === s.id
                  ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                  : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-500'
              }`}
            >
              <div className="flex items-center justify-between">
                <h3 className="font-semibold text-sm">{s.name}</h3>
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${s.is_running ? 'bg-green-500' : 'bg-gray-300'}`} />
              </div>
              <p className="text-xs text-gray-500 mt-0.5">
                {s.network_count} network{s.network_count !== 1 ? 's' : ''} · {s.host_count} host{s.host_count !== 1 ? 's' : ''}
              </p>
              <p className="text-xs font-medium mt-1 text-gray-400">{s.is_running ? '● running' : '○ stopped'}</p>
            </button>
          ))}
        </div>

        {/* ── Right: detail + editor ── */}
        <div className="col-span-2 flex flex-col gap-3 overflow-auto">
          {!selectedId ? (
            <div className="flex items-center justify-center h-full text-gray-400">
              Select a topology to edit agents
            </div>
          ) : detailLoading ? (
            <div className="flex items-center justify-center h-full gap-2 text-gray-400">
              <Loader2 size={18} className="animate-spin" /> Loading…
            </div>
          ) : topology ? (
            <>
              {/* Action bar */}
              <div className="flex items-center justify-between flex-shrink-0 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl px-4 py-3">
                <div>
                  <h2 className="font-bold text-base">{topology.name}</h2>
                  <p className="text-xs text-gray-500">v{topology.version}
                    {dirty && <span className="ml-2 text-amber-600 font-semibold">● unsaved changes</span>}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  {dirty && (
                    <button
                      onClick={save}
                      disabled={saving}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50
                                 text-white text-sm font-semibold rounded-lg transition-colors"
                    >
                      {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
                      {saving ? 'Saving…' : 'Save agents'}
                    </button>
                  )}
                  {isRunning ? (
                    <button
                      onClick={stopTopology}
                      disabled={stopping}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-red-600 hover:bg-red-700 disabled:opacity-50
                                 text-white text-sm font-semibold rounded-lg transition-colors"
                    >
                      {stopping ? <Loader2 size={14} className="animate-spin" /> : <Square size={14} />}
                      {stopping ? 'Stopping…' : 'Stop'}
                    </button>
                  ) : (
                    <button
                      onClick={startTopology}
                      disabled={starting}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-green-600 hover:bg-green-700 disabled:opacity-50
                                 text-white text-sm font-semibold rounded-lg transition-colors"
                    >
                      {starting ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
                      {starting ? 'Starting…' : 'Start'}
                    </button>
                  )}
                </div>
              </div>

              {/* Networks + hosts */}
              <div className="space-y-2 overflow-auto">
                {(topology.networks ?? []).map((network: Network) => (
                  <div key={network.id} className="border border-gray-200 dark:border-gray-700 rounded-xl overflow-hidden">
                    {/* Network header */}
                    <button
                      onClick={() => toggleNetwork(network.id)}
                      className="w-full flex items-center gap-2 px-4 py-2.5 bg-gray-50 dark:bg-gray-800 hover:bg-gray-100 dark:hover:bg-gray-700/80 transition-colors"
                    >
                      {expandedNetworks.has(network.id) ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                      <NetworkIcon size={15} className="text-blue-500" />
                      <span className="font-semibold text-sm">{network.name}</span>
                      <span className="text-xs text-gray-400">{network.cidr}</span>
                      {network.internet && (
                        <span className="ml-1 text-xs px-1.5 py-0.5 bg-green-100 text-green-700 rounded-full">internet</span>
                      )}
                      <span className="ml-auto text-xs text-gray-400">
                        {(network.hosts ?? []).length} host{(network.hosts ?? []).length !== 1 ? 's' : ''}
                      </span>
                    </button>

                    {/* Hosts */}
                    {expandedNetworks.has(network.id) && (
                      <div className="px-4 py-3 space-y-2">
                        {(network.hosts ?? []).length === 0 ? (
                          <p className="text-xs text-gray-400">No hosts</p>
                        ) : (network.hosts ?? []).map((host: Host) => (
                          <HostRow
                            key={host.id}
                            host={host}
                            agentTypes={agentTypes}
                            templates={templates}
                            onAgentAdd={a => addAgent(network.id, host.id, a)}
                            onAgentRemove={a => removeAgent(network.id, host.id, a)}
                          />
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>

              {/* Legend */}
              <div className="flex-shrink-0 flex flex-wrap gap-2 pt-1">
                <p className="text-xs text-gray-400 w-full">Available agents:</p>
                {agentTypes.map(k => {
                  const m = metaFor(k, templates);
                  return (
                    <span key={k} className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold ${m.bg} ${m.color}`}>
                      {m.label}
                    </span>
                  );
                })}
              </div>
            </>
          ) : null}
        </div>
      </div>
    </div>
  );
}
