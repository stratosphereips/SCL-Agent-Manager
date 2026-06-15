import React, { createContext, useContext, useState, useCallback, useRef, useEffect } from 'react';
import type { ReplayState, ReplayMetadata } from '@/types/index';

interface ReplayControls {
  loadReplay: (path?: string, runId?: string) => Promise<void>;
  play: (speed?: number) => void;
  pause: () => void;
  stop: () => void;
  seek: (positionMs: number) => void;
  setSpeed: (speed: number) => void;
  togglePlay: () => void;
}

interface ReplayContextValue {
  replay: ReplayState;
  controls: ReplayControls;
  isLoading: boolean;
  error: string | null;
}

const ReplayContext = createContext<ReplayContextValue | undefined>(undefined);

export function useReplayContext() {
  const ctx = useContext(ReplayContext);
  if (!ctx) throw new Error('useReplayContext must be used within ReplayProvider');
  return ctx;
}

interface ReplayProviderProps {
  children: React.ReactNode;
}

export function ReplayProvider({ children }: ReplayProviderProps) {
  const [replay, setReplay] = useState<ReplayState>({
    replayId: null,
    path: null,
    positionMs: 0,
    durationMs: 0,
    startTimeMs: 0,
    endTimeMs: 0,
    eventCount: 0,
    isPlaying: false,
    speed: 1,
    events: [],
    error: null,
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout>>();
  const backoffRef = useRef(1000);

  const stop = useCallback(() => {
    // Close WebSocket
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    clearTimeout(reconnectTimerRef.current);

    // Reset state
    setReplay((prev) => ({
      ...prev,
      replayId: null,
      path: null,
      positionMs: 0,
      isPlaying: false,
      events: [],
    }));
    setError(null);
  }, []);

  const loadReplay = useCallback(async (path?: string, runId?: string) => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/replay/load', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...(path ? { path } : {}),
          ...(runId ? { run_id: runId } : {}),
        }),
      });

      if (!response.ok) {
        throw new Error(`Failed to load replay: ${response.statusText}`);
      }

      const metadata: ReplayMetadata = await response.json();

      // Set initial replay state
      setReplay({
        replayId: metadata.replay_id,
        path: metadata.path,
        positionMs: metadata.start_time_ms,
        durationMs: metadata.duration_ms,
        startTimeMs: metadata.start_time_ms,
        endTimeMs: metadata.end_time_ms,
        eventCount: metadata.event_count,
        isPlaying: false,
        speed: 1,
        events: metadata.initial_events || [],
        error: null,
      });

      // Connect to WebSocket for live updates
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const url = `${proto}//${window.location.host}/api/replay/ws`;
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        backoffRef.current = 1000;
        // Request state update
        ws.send(JSON.stringify({ type: 'subscribe', replay_id: metadata.replay_id }));
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);

          switch (msg.type) {
            case 'state':
              setReplay((prev) => ({
                ...prev,
                positionMs: msg.position_ms,
                isPlaying: msg.playing,
                speed: msg.speed,
                durationMs: msg.duration_ms,
                startTimeMs: msg.start_time_ms || prev.startTimeMs,
                endTimeMs: msg.end_time_ms || prev.endTimeMs,
              }));
              break;

            case 'events':
              setReplay((prev) => ({
                ...prev,
                events: msg.events || [],
              }));
              break;

            case 'playback_complete':
              setReplay((prev) => ({
                ...prev,
                isPlaying: false,
              }));
              break;

            case 'error':
              setReplay((prev) => ({
                ...prev,
                error: msg.message,
              }));
              setError(msg.message);
              break;
          }
        } catch (e) {
          console.error('Failed to parse WebSocket message:', e);
        }
      };

      ws.onclose = () => {
        // Auto-reconnect with backoff
        const delay = backoffRef.current;
        backoffRef.current = Math.min(delay * 2, 30000);
        reconnectTimerRef.current = setTimeout(() => {
          if (replay.replayId) {
            loadReplay(replay.path || undefined, replay.replayId);
          }
        }, delay);
      };

      ws.onerror = () => ws.close();
    } catch (e) {
      const message = e instanceof Error ? e.message : 'Failed to load replay';
      setError(message);
      setReplay((prev) => ({ ...prev, error: message }));
    } finally {
      setIsLoading(false);
    }
  }, [replay.replayId, replay.path]);

  const play = useCallback((speed = 1) => {
    if (!wsRef.current) return;

    wsRef.current.send(JSON.stringify({
      type: 'play',
      speed,
    }));

    setReplay((prev) => ({ ...prev, isPlaying: true, speed }));
  }, []);

  const pause = useCallback(() => {
    if (!wsRef.current) return;

    wsRef.current.send(JSON.stringify({ type: 'pause' }));
    setReplay((prev) => ({ ...prev, isPlaying: false }));
  }, []);

  const seek = useCallback((positionMs: number) => {
    if (!wsRef.current) return;

    wsRef.current.send(JSON.stringify({
      type: 'seek',
      position_ms: positionMs,
    }));

    setReplay((prev) => ({ ...prev, positionMs }));
  }, []);

  const setSpeed = useCallback((speed: number) => {
    if (!wsRef.current) return;

    wsRef.current.send(JSON.stringify({
      type: 'speed',
      speed,
    }));

    setReplay((prev) => ({ ...prev, speed }));
  }, []);

  const togglePlay = useCallback(() => {
    if (replay.isPlaying) {
      pause();
    } else {
      play(replay.speed);
    }
  }, [replay.isPlaying, replay.speed, play, pause]);

  const controls: ReplayControls = {
    loadReplay,
    play,
    pause,
    stop,
    seek,
    setSpeed,
    togglePlay,
  };

  const value: ReplayContextValue = {
    replay,
    controls,
    isLoading,
    error,
  };

  return (
    <ReplayContext.Provider value={value}>
      {children}
    </ReplayContext.Provider>
  );
}
