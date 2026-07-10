/**
 * ReplayAgentView — a single agent's replayed activity, synced to the current
 * playback position. Used by the Agents / Defender tabs when a replay is loaded.
 *
 * Timeline entries come from the replay-aware `useTimelineStream` hook (already
 * filtered by agent source-file pattern + the [startTimeMs .. positionMs+60s]
 * window). Messages are reconstructed from the OPENCODE-level timeline entries
 * (which carry real timestamps + parts) into the SessionMessage shape that
 * `SessionStream` renders.
 */
import { useState, useMemo } from 'react';
import { Radio, MessageSquare, AlignLeft } from 'lucide-react';
import { useReplayContext } from '@/contexts/ReplayContext';
import { useTimelineStream } from '@/hooks/useTimelineStream';
import { SessionStream } from './SessionStream';
import type { TimelineEntry, SessionMessage } from '@/types';

const LEVEL_STYLES: Record<string, string> = {
  INIT: 'text-blue-700 dark:text-blue-400',
  OPENCODE: 'text-purple-700 dark:text-purple-400',
  ERROR: 'text-red-700 dark:text-red-400',
  WARNING: 'text-amber-700 dark:text-amber-400',
  INFO: 'text-green-700 dark:text-green-400',
  DEBUG: 'text-trident-muted',
  ALERT: 'text-red-700 dark:text-red-500',
  SESSION: 'text-sky-700 dark:text-sky-400',
};

function isStepMarker(type: string | undefined): boolean {
  return !!type && /^(step[_-]?(start|finish))$/.test(type);
}

/** Build a concise summary from an OPENCODE timeline entry's data.part. */
function partSummary(d: Record<string, unknown> | undefined): string {
  if (!d) return '';
  const type = d.type as string | undefined;
  const part = d.part as Record<string, unknown> | undefined;
  if (type === 'text' && part) {
    const text = part.text as string | undefined;
    return text ? text.replace(/\n/g, ' ').slice(0, 160) : '';
  }
  if (type === 'tool_use' && part) {
    const tool = part.tool as string | undefined;
    const state = part.state as Record<string, unknown> | undefined;
    const input = state?.input as Record<string, unknown> | undefined;
    const desc = (input?.description ?? input?.command ?? input?.query ?? input?.content ?? input?.path ?? '') as string;
    return tool ? `${tool}${desc ? ` · ${desc.replace(/\n/g, ' ').slice(0, 120)}` : ''}` : '';
  }
  return '';
}

/** Reconstruct SessionMessage[] from OPENCODE-level timeline entries (synced). */
function timelineEntriesToSessionMessages(entries: TimelineEntry[]): SessionMessage[] {
  const msgs: SessionMessage[] = [];
  for (const e of entries) {
    if (e.level !== 'OPENCODE') continue;
    const d = e.data as Record<string, unknown> | undefined;
    if (!d) continue;
    const part = d.part as Record<string, unknown> | undefined;
    if (!part) continue;
    const partType = (part.type as string | undefined) || (d.type as string | undefined);
    if (isStepMarker(partType) || isStepMarker(d.type as string | undefined)) continue;

    const role = ((part.role as string | undefined) || (d.role as string | undefined) || 'assistant') as SessionMessage['role'];
    const isText = partType === 'text' && typeof part.text === 'string';
    const isTool = partType === 'tool_use';
    const content = isText ? (part.text as string) : '';
    const tool_calls = isTool
      ? [{
          function: {
            name: (part.tool as string | undefined) || 'tool',
            arguments: part.state && (part.state as Record<string, unknown>).input !== undefined
              ? JSON.stringify((part.state as Record<string, unknown>).input)
              : undefined,
          },
        }]
      : undefined;

    const rawTs = (d.timestamp as number | undefined) ?? e.ts;
    const timestamp = typeof rawTs === 'number'
      ? (rawTs < 1e12 ? new Date(rawTs * 1000) : new Date(rawTs)).toISOString()
      : String(rawTs);

    msgs.push({
      id: `${(d.sessionID as string | undefined) || (d.session_id as string | undefined) || 's'}_${rawTs}`,
      timestamp,
      role,
      content,
      ...(tool_calls ? { tool_calls } : {}),
    });
  }
  return msgs;
}

function TimelineEntryRow({ entry }: { entry: TimelineEntry }) {
  const [expanded, setExpanded] = useState(false);
  const levelColor = LEVEL_STYLES[entry.level] ?? 'text-trident-muted';
  const d = entry.data as Record<string, unknown> | undefined;
  const ocType = d?.type as string | undefined;

  if (entry.level === 'OPENCODE' && isStepMarker(ocType)) return null;

  const summary = entry.level === 'OPENCODE' ? partSummary(d) : null;
  const displayMsg = summary ?? (typeof entry.msg === 'string' && entry.msg ? entry.msg : '');
  const timeStr = typeof entry.ts === 'string' ? entry.ts.slice(11, 19) : '--:--:--';

  return (
    <div
      className="cursor-pointer border-b border-trident-border/40 px-3 py-1.5 hover:bg-black/5 dark:hover:bg-white/5"
      onClick={() => setExpanded((x) => !x)}
    >
      <div className="flex items-start gap-2 text-xs">
        <span className="w-16 flex-shrink-0 font-mono text-[10px] text-trident-muted">{timeStr}</span>
        <span className={`w-24 flex-shrink-0 font-mono font-bold ${levelColor}`}>{entry.level}</span>
        <span className="truncate text-trident-text">{displayMsg || '(no message)'}</span>
      </div>
      {expanded && entry.data && (
        <pre className="terminal-output mt-1 max-h-40 overflow-auto text-[10px] text-trident-muted">
          {JSON.stringify(entry.data, null, 2)}
        </pre>
      )}
    </div>
  );
}

interface Props {
  agentKey: string;          // key into useTimelineStream's AGENT_SOURCE_PATTERNS
  label: string;
  desc?: string;
  color: string;             // tailwind text-color class for the heading/icon
}

export function ReplayAgentView({ agentKey, label, desc, color }: Props) {
  const { replay } = useReplayContext();
  const { entries } = useTimelineStream(agentKey);
  const [tab, setTab] = useState<'timeline' | 'messages'>('timeline');

  const messages = useMemo(() => timelineEntriesToSessionMessages(entries), [entries]);
  const recent = entries.slice(-300);

  return (
    <div className="card flex flex-col">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Radio size={16} className={color} />
          <h3 className={`font-heading text-lg font-bold ${color}`}>{label}</h3>
        </div>
        <span className="badge badge-success">Replay</span>
      </div>

      {desc && <p className="mb-3 text-xs text-trident-muted line-clamp-2">{desc}</p>}

      <div className="mb-3 grid grid-cols-2 gap-3">
        <div className="rounded-lg bg-black/5 dark:bg-black/30 p-3 text-center">
          <p className="text-2xl font-bold text-trident-text">{entries.length}</p>
          <p className="text-[10px] uppercase tracking-wider text-trident-muted">Timeline events</p>
        </div>
        <div className="rounded-lg bg-black/5 dark:bg-black/30 p-3 text-center">
          <p className="text-2xl font-bold text-purple-700 dark:text-purple-400">{messages.length}</p>
          <p className="text-[10px] uppercase tracking-wider text-trident-muted">Messages</p>
        </div>
      </div>

      <div className="mb-2 flex gap-1 rounded-lg bg-black/20 p-1">
        <button
          onClick={() => setTab('timeline')}
          className={`flex-1 rounded-md px-2 py-1 text-xs font-medium transition-colors ${
            tab === 'timeline' ? 'bg-trident-accent/20 text-trident-accent' : 'text-trident-muted hover:text-trident-text'
          }`}
        >
          <AlignLeft size={10} className="mr-1 inline" />
          Timeline ({entries.length})
        </button>
        <button
          onClick={() => setTab('messages')}
          className={`flex-1 rounded-md px-2 py-1 text-xs font-medium transition-colors ${
            tab === 'messages' ? 'bg-trident-accent/20 text-trident-accent' : 'text-trident-muted hover:text-trident-text'
          }`}
        >
          <MessageSquare size={10} className="mr-1 inline" />
          Messages ({messages.length})
        </button>
      </div>

      {tab === 'messages' ? (
        messages.length === 0 ? (
          <p className="py-6 text-center text-sm text-trident-muted">No messages at this point in the replay.</p>
        ) : (
          <div className="flex-1 overflow-auto rounded-lg border border-trident-border bg-black/20 max-h-96">
            <SessionStream messages={messages} />
          </div>
        )
      ) : recent.length === 0 ? (
        <p className="py-6 text-center text-sm text-trident-muted">
          {replay.isPlaying ? 'Replaying…' : 'Press play to start replay.'}
        </p>
      ) : (
        <div className="flex-1 overflow-auto rounded-lg border border-trident-border bg-black/20 max-h-96">
          {recent.map((e, i) => (
            <TimelineEntryRow key={i} entry={e} />
          ))}
        </div>
      )}
    </div>
  );
}

/** Small reusable header shown at the top of each replay-aware tab. */
export function ReplayHeader({ title, subtitle }: { title: string; subtitle: string }) {
  const { replay } = useReplayContext();
  return (
    <div className="flex items-center justify-between">
      <div>
        <h2 className="font-heading text-2xl font-bold text-trident-text">{title}</h2>
        <p className="text-sm text-trident-muted">
          {subtitle} — <span className="text-trident-accent">replaying {replay.replayId}</span>
        </p>
      </div>
      <div className="flex items-center gap-2 rounded-lg border border-trident-accent/50 bg-trident-accent/20 px-3 py-1.5">
        <span className="h-2 w-2 animate-pulse rounded-full bg-trident-accent" />
        <span className="text-sm font-medium text-trident-accent">Replay Active</span>
      </div>
    </div>
  );
}
