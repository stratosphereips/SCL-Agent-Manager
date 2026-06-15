import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import type {
  SessionsMap,
  SessionMessage,
  OpenCodeStatePayload,
  ReplayEvent,
} from '@/types/index';
import { api } from '@/api-trident';
import { useReplayContext } from '@/contexts/ReplayContext';

/** Normalise status values */
function normaliseSessions(raw: Record<string, unknown>): SessionsMap {
  const out: SessionsMap = {};
  for (const [sid, val] of Object.entries(raw)) {
    out[sid] = typeof val === 'string' ? val : (val as any)?.type ?? 'unknown';
  }
  return out;
}

/** Map hosts to their expected source file patterns */
const HOST_SOURCE_PATTERNS: Record<string, string[]> = {
  compromised: [
    'coder56/',
    'benign_agent/',
    'defender/compromised/',
  ],
  server: [
    'defender/server/',
  ],
};

/** Convert replay events to OpenCode-like format */
function replayEventsToOpenCodeState(events: ReplayEvent[], host: string | undefined, positionMs: number, startTimeMs: number): {
  sessions: SessionsMap;
  messagesBySession: Record<string, SessionMessage[]>;
  sessionSources: Record<string, string>;
} {
  const sessions: SessionsMap = {};
  const sessionSources: Record<string, string> = {};
  const sourcePatterns = host ? (HOST_SOURCE_PATTERNS[host] || []) : null;
  const windowEndMs = positionMs + 60000;

  console.log(`[useOpenCodeStream] host=${host}, events=${events.length}`);

  const bySession: Record<string, Map<string, { ts: number; parts: any[] }>> = {};

  for (const event of events) {
    if (event.timestamp_ms < startTimeMs || event.timestamp_ms > windowEndMs) {
      continue;
    }

    const isOpencode = event.source_type === 'opencode' ||
                       (event.source_type === 'timeline' && event.level === 'OPENCODE');

    if (isOpencode) {
      if (sourcePatterns) {
        const sourceFile = event.source_file || '';
        const matchesHost = sourcePatterns.some(pattern => sourceFile.includes(pattern));
        if (!matchesHost) continue;
      }

      const data = event.data as Record<string, unknown> | undefined;
      const sessionId = (event.session_id ||
                        event.info?.sessionID ||
                        data?.sessionID ||
                        data?.session_id ||
                        event.exec ||
                        'default') as string;
      const source = (event.source_file || '').split('/')[0] || 'unknown';

      if (!sessions[sessionId]) {
        sessions[sessionId] = 'idle';
      }
      sessionSources[sessionId] = source;

      let parts: any[] | undefined = event.parts;
      if (!parts && Array.isArray(event.data?.part)) {
        parts = [event.data.part];
      } else if (!parts && event.data?.part) {
        parts = [event.data.part];
      }

      if (parts && parts.length === 1) {
        const partType = parts[0].type || parts[0].messageID ? parts[0].type : null;
        if (partType === 'step-start' || partType === 'step_start' || partType === 'step-finish' || partType === 'step_finish') {
          continue;
        }
      }

      if (parts && parts.length > 0) {
        const messageID = (parts[0]?.messageID || `${event.timestamp_ms}`) as string;

        if (!bySession[sessionId]) {
          bySession[sessionId] = new Map();
        }

        const msgMap = bySession[sessionId];
        if (!msgMap.has(messageID)) {
          msgMap.set(messageID, { ts: event.timestamp_ms, parts: [] });
        }
        msgMap.get(messageID)!.parts.push(...parts);
      }
    }
  }

  const messagesBySession: Record<string, SessionMessage[]> = {};
  for (const [sid, msgMap] of Object.entries(bySession)) {
    const msgs: SessionMessage[] = Array.from(msgMap.values())
      .sort((a, b) => a.ts - b.ts)
      .map(({ parts }) => ({
        info: { role: 'assistant' as const, sessionID: sid },
        parts,
      }));
    if (msgs.length > 0) messagesBySession[sid] = msgs;
  }

  return { sessions, messagesBySession, sessionSources };
}

/**
 * Live OpenCode session stream for a host.
 * When a replay is active, returns data from the replay instead of live data.
 */
export function useOpenCodeStream(_host?: string, timelineEntries?: Array<{ level: string; data?: any }>) {
  const { replay } = useReplayContext();
  const [sessions, setSessions] = useState<SessionsMap>({});
  const [messagesBySession, setMessagesBySession] = useState<Record<string, SessionMessage[]>>({});
  const [sessionSources, setSessionSources] = useState<Record<string, string>>({});
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>();
  const backoffRef = useRef(1000);

  const isReplayActive = replay.replayId !== null;
  const replayIdRef = useRef<string | null>(replay.replayId);
  replayIdRef.current = replay.replayId;

  const replayData = useMemo(() => {
    if (!isReplayActive) return null;
    return replayEventsToOpenCodeState(replay.events, _host, replay.positionMs, replay.startTimeMs);
  }, [isReplayActive, replay.events, _host, replay.positionMs, replay.startTimeMs]);

  const timelineMessages = useMemo(() => {
    if (!timelineEntries || timelineEntries.length === 0) return {};
    return reconstructTimelineMessages(timelineEntries, undefined);
  }, [timelineEntries]);

  useEffect(() => {
    if (replayData) {
      setSessions(replayData.sessions);
      setMessagesBySession(replayData.messagesBySession);
      setSessionSources(replayData.sessionSources);
      setConnected(true);
    } else if (replay.replayId !== null) {
      setSessions({});
      setMessagesBySession({});
      setSessionSources({});
      setConnected(false);
    }
  }, [replayData, replay.replayId]);

  useEffect(() => {
    if (replay.replayId !== null) return;

    let cancelled = false;

    const load = async () => {
      try {
        const state = (await api.openCodeState()) as OpenCodeStatePayload;
        if (cancelled) return;
        const normalised = normaliseSessions((state?.sessions ?? {}) as Record<string, unknown>);
        setSessions(normalised);

        const bySession = (state?.messages_by_session ?? {}) as Record<string, SessionMessage[]>;
        setMessagesBySession(bySession);
        setSessionSources((state?.session_sources ?? {}) as Record<string, string>);
      } catch {
        // host unreachable
      }
    };

    load();
    const interval = setInterval(load, 5_000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [replay.replayId]);

  const connect = useCallback(() => {
    if (replay.replayId !== null) return;

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${window.location.host}/api/opencode/ws`;
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      backoffRef.current = 1000;
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'state') {
          const sessionsRaw = (msg as any)?.data?.sessions ?? {};
          const messagesRaw = (msg as any)?.data?.messages_by_session ?? {};
          const sourcesRaw = (msg as any)?.data?.session_sources ?? {};
          setSessions(normaliseSessions(sessionsRaw));
          setMessagesBySession(messagesRaw);
          setSessionSources(sourcesRaw);
        }
      } catch {}
    };

    ws.onclose = () => {
      if (replayIdRef.current === null) {
        setConnected(false);
        const delay = backoffRef.current;
        backoffRef.current = Math.min(delay * 2, 30000);
        reconnectTimer.current = setTimeout(connect, delay);
      }
    };
    ws.onerror = () => ws.close();
  }, [replay.replayId]);

  useEffect(() => {
    if (replay.replayId === null) {
      connect();
    }
    return () => {
      clearTimeout(reconnectTimer.current);
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [connect, replay.replayId]);

  return { sessions, messagesBySession, sessionSources, connected, isReplayActive, timelineMessages };
}

/**
 * Reconstruct messages from timeline OPENCODE entries grouped by messageID.
 */
export function reconstructTimelineMessages(
  entries: Array<{ level: string; data?: any }>,
  sessionFilter?: string,
): Record<string, SessionMessage[]> {
  const bySession: Record<string, Map<string, { ts: number; parts: any[] }>> = {};

  for (const e of entries) {
    if (e.level !== 'OPENCODE') continue;
    const d = e.data;
    if (!d) continue;

    const part = d.part;
    if (!part) continue;

    const sid = d.sessionID ?? d.session_id;
    const mid = part.messageID;

    if (sessionFilter && sid !== sessionFilter) continue;

    if (!sid || !mid) continue;

    if (!bySession[sid]) bySession[sid] = new Map();
    const msgMap = bySession[sid];
    if (!msgMap.has(mid)) msgMap.set(mid, { ts: d.timestamp ?? 0, parts: [] });
    msgMap.get(mid)!.parts.push(part);
  }

  const result: Record<string, SessionMessage[]> = {};
  for (const [sid, msgMap] of Object.entries(bySession)) {
    const msgs: SessionMessage[] = Array.from(msgMap.values())
      .sort((a, b) => a.ts - b.ts)
      .map(({ parts }) => ({
        info: { role: 'assistant' as const, sessionID: sid },
        parts,
      }));
    if (msgs.length > 0) result[sid] = msgs;
  }

  return result;
}
