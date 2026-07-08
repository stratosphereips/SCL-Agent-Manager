import { useMemo, useState } from 'react';
import { ChevronDown, ChevronRight, Wrench, Maximize2, X, Terminal } from 'lucide-react';
import type { SessionMessage } from '@/types';

interface SessionStreamProps {
  messages: SessionMessage[];
}

interface ToolCall {
  id?: string;
  type?: string;
  function?: {
    name?: string;
    arguments?: string;
  };
  result?: string;
}

function tryParseJson(value: unknown): unknown {
  if (typeof value !== 'string' || !value.trim()) return value;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function toolInputSummary(input: unknown): string {
  if (typeof input === 'string') return input.trim().replace(/\n/g, ' ').slice(0, 120);
  if (!input || typeof input !== 'object') return '';
  const obj = input as Record<string, unknown>;
  const priorityKeys = ['description', 'title', 'command', 'cmd', 'query', 'message',
    'content', 'path', 'url', 'file', 'filename', 'text', 'code', 'script', 'input'];
  for (const key of priorityKeys) {
    const val = obj[key];
    if (typeof val === 'string' && val.trim()) {
      return val.trim().replace(/\n/g, ' ').slice(0, 120);
    }
  }
  for (const val of Object.values(obj)) {
    if (typeof val === 'string' && val.trim()) {
      return val.trim().replace(/\n/g, ' ').slice(0, 120);
    }
  }
  return '';
}

function formatOutput(output: unknown): string {
  if (output === undefined || output === null) return '';
  if (typeof output === 'string') return output;
  return JSON.stringify(output, null, 2);
}

function isRefusedOrFailed(result?: string): boolean {
  if (!result) return false;
  return /refused|escalated|Exit:\s*(?!0\b)\d+/i.test(result);
}

function ToolCallCard({ tc }: { tc: ToolCall }) {
  const [expanded, setExpanded] = useState(true);
  const toolName = tc.function?.name || 'unknown_tool';
  const rawInput = useMemo(() => tryParseJson(tc.function?.arguments), [tc.function?.arguments]);
  const inputObj = typeof rawInput === 'object' && rawInput !== null ? rawInput as Record<string, unknown> : {};
  const summary = toolInputSummary(rawInput);
  const output = formatOutput(tc.result);
  const failed = isRefusedOrFailed(output);

  return (
    <div className="my-2 rounded-lg border border-trident-border bg-black/5 dark:bg-black/30 overflow-hidden">
      <button
        onClick={() => setExpanded((e) => !e)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left text-xs hover:bg-black/5 dark:hover:bg-white/5"
      >
        {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        <Wrench size={12} className="text-amber-700 dark:text-amber-400 flex-shrink-0" />
        <span className="font-mono font-medium text-amber-700 dark:text-amber-400 flex-shrink-0">
          {toolName}
        </span>
        {summary && <span className="truncate text-trident-muted font-mono">{summary}</span>}
        {failed && (
          <span className="ml-auto badge badge-danger text-[10px]">failed/refused</span>
        )}
      </button>
      {expanded && (
        <div className="space-y-2 border-t border-trident-border px-3 py-2">
          {Object.keys(inputObj).length > 0 && (
            <div>
              <span className="text-[10px] uppercase tracking-wider text-trident-muted">Input</span>
              <pre className="terminal-output mt-1 max-h-40 overflow-auto text-[11px]">
                {JSON.stringify(inputObj, null, 2)}
              </pre>
            </div>
          )}
          {tc.function?.arguments && Object.keys(inputObj).length === 0 && (
            <div>
              <span className="text-[10px] uppercase tracking-wider text-trident-muted">Input</span>
              <pre className="terminal-output mt-1 max-h-40 overflow-auto text-[11px]">
                {tc.function.arguments}
              </pre>
            </div>
          )}
          {output && (
            <div>
              <span className="text-[10px] uppercase tracking-wider text-trident-muted">Output</span>
              <pre className={`terminal-output mt-1 max-h-60 overflow-auto text-[11px] ${failed ? 'text-red-600 dark:text-red-400' : ''}`}>
                {output}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function MessageCard({
  msg,
  onMaximize,
}: {
  msg: SessionMessage;
  onMaximize: (msg: SessionMessage) => void;
}) {
  const role = msg.role || 'unknown';
  const toolCalls = (msg.tool_calls || []) as ToolCall[];

  const roleBadgeClass =
    role === 'assistant'
      ? 'badge-info'
      : role === 'user'
      ? 'badge-success'
      : role === 'tool'
      ? 'badge-warning'
      : 'badge-muted';

  return (
    <div className="group relative rounded-lg border border-trident-border bg-trident-surface/50 p-3">
      <div className="mb-2 flex items-center gap-2 text-[10px] uppercase tracking-wider text-trident-muted">
        <span className={`badge ${roleBadgeClass}`}>{role}</span>
        {typeof msg.tokens_used === 'number' && msg.tokens_used > 0 && (
          <span>{msg.tokens_used.toLocaleString()} tokens</span>
        )}
        {msg.timestamp && (
          <span className="ml-auto">{new Date(msg.timestamp).toLocaleString()}</span>
        )}
      </div>

      <div className="space-y-1">
        {msg.content && (
          <div className="whitespace-pre-wrap break-words text-sm text-trident-text">
            {msg.content}
          </div>
        )}
        {toolCalls.map((tc, idx) => (
          <ToolCallCard key={tc.id || idx} tc={tc} />
        ))}
      </div>

      <button
        onClick={() => onMaximize(msg)}
        className="absolute right-2 top-2 flex h-7 w-7 items-center justify-center rounded border border-trident-border bg-trident-surface text-trident-muted opacity-0 transition-all hover:border-trident-accent hover:text-trident-accent group-hover:opacity-100"
        title="Expand message"
      >
        <Maximize2 size={14} />
      </button>
    </div>
  );
}

function MessageModal({
  msg,
  onClose,
}: {
  msg: SessionMessage;
  onClose: () => void;
}) {
  if (!msg) return null;
  const toolCalls = (msg.tool_calls || []) as ToolCall[];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="flex max-h-[90vh] w-full max-w-4xl flex-col rounded-xl border border-trident-border bg-trident-bg shadow-xl">
        <div className="flex items-center justify-between border-b border-trident-border px-5 py-3">
          <div className="flex items-center gap-2 text-xs text-trident-muted">
            <span className={`badge ${msg.role === 'assistant' ? 'badge-info' : msg.role === 'user' ? 'badge-success' : 'badge-muted'}`}>
              {msg.role}
            </span>
            {msg.timestamp && <span>{new Date(msg.timestamp).toLocaleString()}</span>}
            {typeof msg.tokens_used === 'number' && msg.tokens_used > 0 && (
              <span>{msg.tokens_used.toLocaleString()} tokens</span>
            )}
          </div>
          <button onClick={onClose} className="rounded p-1 hover:bg-trident-surface">
            <X size={18} />
          </button>
        </div>
        <div className="space-y-4 overflow-auto p-5">
          {msg.content && (
            <div className="whitespace-pre-wrap break-words text-sm text-trident-text">
              {msg.content}
            </div>
          )}
          {toolCalls.map((tc, idx) => {
            const rawInput = tryParseJson(tc.function?.arguments);
            const inputObj = typeof rawInput === 'object' && rawInput !== null ? rawInput : {};
            const output = formatOutput(tc.result);
            const failed = isRefusedOrFailed(output);
            return (
              <div key={tc.id || idx} className="rounded-xl border border-trident-border dark:border-white/10 bg-gray-100 dark:bg-black/40">
                <div className="flex items-center gap-3 border-b border-trident-border dark:border-white/10 px-5 py-3">
                  <Terminal size={16} className="text-amber-700 dark:text-amber-500 flex-shrink-0" />
                  <span className="font-mono text-sm font-semibold text-amber-700 dark:text-amber-500">
                    {tc.function?.name || 'unknown_tool'}
                  </span>
                </div>
                <div className="space-y-4 p-5">
                  {Object.keys(inputObj).length > 0 && (
                    <div>
                      <span className="mb-2 block text-xs uppercase tracking-wider text-trident-muted">Input</span>
                      <pre className="terminal-output">
                        {JSON.stringify(inputObj, null, 2)}
                      </pre>
                    </div>
                  )}
                  {tc.function?.arguments && Object.keys(inputObj).length === 0 && (
                    <div>
                      <span className="mb-2 block text-xs uppercase tracking-wider text-trident-muted">Input</span>
                      <pre className="terminal-output">{tc.function.arguments}</pre>
                    </div>
                  )}
                  {output && (
                    <div>
                      <span className="mb-2 block text-xs uppercase tracking-wider text-trident-muted">Output</span>
                      <pre className={`terminal-output ${failed ? 'text-red-600 dark:text-red-400' : ''}`}>
                        {output}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export function SessionStream({ messages }: SessionStreamProps) {
  const [maximized, setMaximized] = useState<SessionMessage | null>(null);

  if (messages.length === 0) {
    return (
      <p className="text-sm text-trident-muted py-4">
        No messages yet
      </p>
    );
  }

  return (
    <>
      <div className="space-y-4 p-4">
        {messages.map((msg) => (
          <MessageCard key={msg.id} msg={msg} onMaximize={setMaximized} />
        ))}
      </div>
      {maximized && <MessageModal msg={maximized} onClose={() => setMaximized(null)} />}
    </>
  );
}
