import type { SessionMessage } from '@/types';

interface SessionStreamProps {
  messages: SessionMessage[];
}

export function SessionStream({ messages }: SessionStreamProps) {
  if (messages.length === 0) {
    return (
      <p className="text-sm text-trident-muted py-4">
        No messages yet
      </p>
    );
  }

  return (
    <div className="space-y-4 p-4">
      {messages.map((msg, idx) => {
        const role = msg.role || 'unknown';
        const timestamp = msg.timestamp;
        const toolCalls = msg.tool_calls || [];

        return (
          <div
            key={msg.id || idx}
            className={`p-3 rounded-lg border ${
              role === 'assistant'
                ? 'bg-purple-50 dark:bg-purple-900/20 border-purple-200 dark:border-purple-800'
                : role === 'user'
                  ? 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800'
                  : 'bg-gray-50 dark:bg-gray-800 border-gray-200 dark:border-gray-700'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <span className="badge badge-info">
                  {role}
                </span>
                <span className="text-xs text-trident-muted font-mono">
                  {new Date(timestamp).toLocaleString()}
                </span>
              </div>
            </div>

            {/* Render Content */}
            {msg.content && (
              <div className="text-sm whitespace-pre-wrap break-words text-trident-text mb-2">
                {msg.content}
              </div>
            )}

            {/* Render Tool Calls */}
            {toolCalls.length > 0 && (
              <div className="space-y-2 mt-2">
                {toolCalls.map((tc, tcIdx) => (
                  <div key={tcIdx} className="mb-2 rounded-lg bg-black/5 dark:bg-white/5 p-3">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="badge badge-info">
                        Tool Call
                      </span>
                      <span className="font-mono text-sm text-trident-accent">
                        {tc.function?.name || 'unknown_tool'}
                      </span>
                    </div>
                    {tc.function?.arguments && (
                      <div className="mt-2">
                        <p className="text-xs text-trident-muted mb-1">Input:</p>
                        <pre className="text-xs bg-trident-bg p-2 rounded overflow-x-auto whitespace-pre-wrap">
                          {tc.function.arguments}
                        </pre>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
