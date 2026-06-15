import { useState, useEffect } from 'react';
import { api } from '@/api-trident';

export function ContainerStatusBar() {
  const [containers, setContainers] = useState<number>(0);
  const [running, setRunning] = useState<number>(0);

  useEffect(() => {
    const load = () => {
      api.containers()
        .then((data: any) => {
          const all: unknown[] = data?.containers || data || [];
          setContainers(all.length);
          setRunning(
            all.filter((c: any) => c.state === 'running').length
          );
        })
        .catch(() => {});
    };
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
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

