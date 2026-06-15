import { useReplayContext } from '@/contexts/ReplayContext';

export function SettingsPage() {
  const { replay } = useReplayContext();

  return (
    <div className="flex h-full flex-col gap-6 overflow-auto">
      <div>
        <h2 className="font-heading text-2xl font-bold text-trident-text">Settings</h2>
        <p className="text-sm text-trident-muted">
          Configure the Agent Manager dashboard
        </p>
      </div>

      <div className="card">
        <h3 className="font-heading text-lg font-bold text-trident-text mb-4">Replay Status</h3>
        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-trident-muted">Active Replay:</span>
            <span className="font-mono">{replay.replayId || 'None'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-trident-muted">Position:</span>
            <span className="font-mono">{Math.floor(replay.positionMs / 1000)}s</span>
          </div>
          <div className="flex justify-between">
            <span className="text-trident-muted">Speed:</span>
            <span className="font-mono">{replay.speed}x</span>
          </div>
        </div>
      </div>

      <div className="card">
        <h3 className="font-heading text-lg font-bold text-trident-text mb-4">Agent Configuration</h3>
        <p className="text-sm text-trident-muted">
          Configure which agents are available for assignment to hosts.
        </p>
        <div className="mt-4 space-y-2">
          <div className="flex items-center justify-between p-2 rounded bg-black/5 dark:bg-white/5">
            <span className="text-sm">coder56</span>
            <span className="badge badge-success">Enabled</span>
          </div>
          <div className="flex items-center justify-between p-2 rounded bg-black/5 dark:bg-white/5">
            <span className="text-sm">db_admin</span>
            <span className="badge badge-success">Enabled</span>
          </div>

        </div>
      </div>
    </div>
  );
}
