import { useState, useEffect } from 'react';
import { getContainers } from '@/api';
import { ContainerState } from '@/types';

export function ContainerStatusBar() {
  const [containers, setContainers] = useState<number>(0);
  const [running, setRunning] = useState<number>(0);

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;

    const load = async () => {
      try {
        const data = await getContainers();
        if (cancelled) return;
        const all = data.containers ?? [];
        setContainers(all.length);
        setRunning(
          all.filter((c) => c.state === ContainerState.RUNNING).length,
        );
      } catch {
        // Keep the last known counts during a transient backend failure.
      } finally {
        if (!cancelled) timer = window.setTimeout(load, 10000);
      }
    };

    load();
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, []);

  return (
    <div className="px-3 py-2 border-t border-trident-border bg-trident-surface">
      <div className="flex items-center justify-between text-xs">
        <div className="flex items-center gap-3">
          <span className="text-trident-muted">Containers:</span>
          <span className="font-mono text-trident-text">{containers}</span>
          <span className={`badge ${running === containers ? 'badge-success' : 'badge-warning'}`}>
            {running} running
          </span>
        </div>
        <div className="text-trident-muted">
          Agent Manager
        </div>
      </div>
    </div>
  );
}
