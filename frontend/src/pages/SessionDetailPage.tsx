/**
 * SessionDetailPage - Detailed View for Agent Sessions
 *
 * Features:
 * - Message stream with markdown formatting and syntax highlighting
 * - Tool calls display with expandable details
 * - Timeline view showing session events
 * - Session metrics (token usage, cost, duration)
 * - Real-time log streaming via WebSocket
 * - Session status and metadata display
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  SessionInfo,
  SessionMessage,
  SessionState,
  LogEntry,
  LogLevel,
  AgentEvent,
  EventType,
  SessionMetrics,
} from '../types';
import {
  getSession,
  getSessionMessages,
  getSessionLogs,
  createSessionWebSocket,
  AgentWebSocket,
  WebSocketCallbacks,
} from '../api';

// =============================================================================
// Types
// =============================================================================

interface TimelineItem {
  id: string;
  timestamp: string;
  type: 'message' | 'tool_call' | 'log' | 'status_change';
  role?: string;
  content?: string;
  toolName?: string;
  toolInput?: Record<string, any>;
  toolOutput?: any;
  logLevel?: LogLevel;
  status?: SessionState;
  tokensUsed?: number;
}

interface ViewMode {
  type: 'timeline' | 'messages' | 'tools' | 'logs';
  label: string;
}

// =============================================================================
// Helper Components
// =============================================================================

const StatusBadge: React.FC<{ state: SessionState }> = ({ state }) => {
  const colors: Record<SessionState, string> = {
    [SessionState.CREATED]: 'bg-blue-100 text-blue-800',
    [SessionState.RUNNING]: 'bg-green-100 text-green-800',
    [SessionState.WAITING]: 'bg-yellow-100 text-yellow-800',
    [SessionState.COMPLETED]: 'bg-gray-100 text-gray-800',
    [SessionState.FAILED]: 'bg-red-100 text-red-800',
    [SessionState.CANCELLED]: 'bg-gray-100 text-gray-800',
    [SessionState.TIMEOUT]: 'bg-red-100 text-red-800',
  };

  return (
    <span className={`px-3 py-1 text-sm font-medium rounded-full ${colors[state] || 'bg-gray-100 text-gray-800'}`}>
      {state}
    </span>
  );
};

const LogLevelBadge: React.FC<{ level: LogLevel }> = ({ level }) => {
  const colors: Record<LogLevel, string> = {
    [LogLevel.DEBUG]: 'bg-gray-100 text-gray-700',
    [LogLevel.INFO]: 'bg-blue-100 text-blue-800',
    [LogLevel.WARNING]: 'bg-yellow-100 text-yellow-800',
    [LogLevel.ERROR]: 'bg-red-100 text-red-800',
    [LogLevel.CRITICAL]: 'bg-red-200 text-red-900',
  };

  return (
    <span className={`px-2 py-0.5 text-xs font-mono rounded ${colors[level]}`}>
      {level}
    </span>
  );
};

const MetricCard: React.FC<{
  label: string;
  value: string | number;
  unit?: string;
  icon?: React.ReactNode;
}> = ({ label, value, unit, icon }) => (
  <div className="bg-white rounded-lg border p-4 shadow-sm">
    <div className="flex items-center justify-between">
      <span className="text-sm text-gray-600">{label}</span>
      {icon && <span className="text-gray-400">{icon}</span>}
    </div>
    <div className="mt-2 flex items-baseline">
      <span className="text-2xl font-semibold text-gray-900">{value}</span>
      {unit && <span className="ml-1 text-sm text-gray-500">{unit}</span>}
    </div>
  </div>
);

const MessageBubble: React.FC<{
  message: SessionMessage;
  isExpanded?: boolean;
  onToggle?: () => void;
}> = ({ message, isExpanded = true, onToggle }) => {
  const roleColors: Record<string, string> = {
    user: 'bg-blue-500 text-white',
    assistant: 'bg-gray-100 text-gray-900',
    system: 'bg-yellow-100 text-gray-900',
    tool: 'bg-green-100 text-gray-900',
  };

  const formatContent = (content: string) => {
    // Simple markdown-like formatting
    return content
      .split('\n')
      .map((line, i) => {
        // Code blocks
        if (line.trim().startsWith('```')) {
          return <span key={i} className="text-sm font-mono bg-gray-800 text-green-400 px-2 py-1 rounded block my-1">{line}</span>;
        }
        // Bold
        if (line.startsWith('**') && line.endsWith('**')) {
          return <p key={i} className="font-bold">{line.slice(2, -2)}</p>;
        }
        return <p key={i} className="mb-1 last:mb-0">{line || ' '}</p>;
      });
  };

  return (
    <div
      className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'} mb-4`}
    >
      <div
        className={`max-w-3xl rounded-lg px-4 py-3 ${
          roleColors[message.role] || 'bg-gray-100'
        }`}
      >
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-medium uppercase opacity-70">
            {message.role}
          </span>
          <div className="flex items-center gap-2">
            {message.tokens_used && (
              <span className="text-xs opacity-60">
                {message.tokens_used} tokens
              </span>
            )}
            <span className="text-xs opacity-60">
              {new Date(message.timestamp).toLocaleTimeString()}
            </span>
          </div>
        </div>
        <div className="text-sm whitespace-pre-wrap">
          {formatContent(message.content)}
        </div>
        {message.tool_calls && message.tool_calls.length > 0 && (
          <div className="mt-2 pt-2 border-t border-current opacity-60">
            <span className="text-xs">
              {message.tool_calls.length} tool call(s)
            </span>
          </div>
        )}
      </div>
    </div>
  );
};

const ToolCallCard: React.FC<{
  toolCall: Record<string, any>;
  index: number;
}> = ({ toolCall, index }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <div className="bg-white border rounded-lg shadow-sm mb-2 overflow-hidden">
      <div
        className="flex items-center justify-between p-3 cursor-pointer hover:bg-gray-50"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="flex items-center gap-3">
          <span className="bg-purple-100 text-purple-800 px-2 py-1 rounded text-sm font-medium">
            {index + 1}
          </span>
          <span className="font-medium text-gray-900">
            {toolCall.name || toolCall.function?.name || 'Unknown Tool'}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {toolCall.execution_time_ms && (
            <span className="text-xs text-gray-500">
              {toolCall.execution_time_ms}ms
            </span>
          )}
          <svg
            className={`w-4 h-4 text-gray-400 transition-transform ${
              isExpanded ? 'transform rotate-180' : ''
            }`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </div>
      {isExpanded && (
        <div className="border-t bg-gray-50 p-3">
          {toolCall.arguments && (
            <div className="mb-2">
              <span className="text-xs font-medium text-gray-500 uppercase">Arguments</span>
              <pre className="mt-1 text-xs bg-gray-100 p-2 rounded overflow-x-auto">
                {JSON.stringify(toolCall.arguments, null, 2)}
              </pre>
            </div>
          )}
          {toolCall.result && (
            <div>
              <span className="text-xs font-medium text-gray-500 uppercase">Result</span>
              <pre className="mt-1 text-xs bg-gray-100 p-2 rounded overflow-x-auto max-h-32 overflow-y-auto">
                {typeof toolCall.result === 'string'
                  ? toolCall.result
                  : JSON.stringify(toolCall.result, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

const TimelineItem: React.FC<{
  item: TimelineItem;
}> = ({ item }) => {
  const getItemColor = () => {
    switch (item.type) {
      case 'message':
        return item.role === 'user' ? 'bg-blue-50 border-blue-200' : 'bg-gray-50 border-gray-200';
      case 'tool_call':
        return 'bg-purple-50 border-purple-200';
      case 'log':
        return item.logLevel === LogLevel.ERROR || item.logLevel === LogLevel.CRITICAL
          ? 'bg-red-50 border-red-200'
          : 'bg-yellow-50 border-yellow-200';
      case 'status_change':
        return 'bg-green-50 border-green-200';
      default:
        return 'bg-gray-50 border-gray-200';
    }
  };

  return (
    <div className={`flex items-start gap-3 p-3 rounded-lg border ${getItemColor()}`}>
      <div className="flex-shrink-0 w-24 text-xs text-gray-500 font-mono">
        {new Date(item.timestamp).toLocaleTimeString()}
      </div>
      <div className="flex-shrink-0">
        {item.type === 'message' && (
          <span className={`px-2 py-0.5 rounded text-xs ${
            item.role === 'user' ? 'bg-blue-500 text-white' : 'bg-gray-200'
          }`}>
            {item.role}
          </span>
        )}
        {item.type === 'tool_call' && (
          <span className="bg-purple-100 text-purple-800 px-2 py-0.5 rounded text-xs">
            {item.toolName}
          </span>
        )}
        {item.type === 'log' && item.logLevel && (
          <LogLevelBadge level={item.logLevel} />
        )}
        {item.type === 'status_change' && (
          <StatusBadge state={item.status!} />
        )}
      </div>
      <div className="flex-1 min-w-0">
        {item.content && (
          <p className="text-sm text-gray-700 line-clamp-2">{item.content}</p>
        )}
        {item.type === 'tool_call' && item.toolInput && (
          <p className="text-xs text-gray-500">
            Input: {JSON.stringify(item.toolInput).slice(0, 100)}...
          </p>
        )}
        {item.tokensUsed && (
          <span className="text-xs text-gray-500">+{item.tokensUsed} tokens</span>
        )}
      </div>
    </div>
  );
};

const LogStream: React.FC<{
  logs: LogEntry[];
  isStreaming: boolean;
}> = ({ logs, isStreaming }) => {
  const logContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="relative">
      {isStreaming && (
        <div className="absolute top-2 right-2 flex items-center gap-2 bg-green-100 text-green-800 px-2 py-1 rounded text-xs">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
          </span>
          Live
        </div>
      )}
      <div
        ref={logContainerRef}
        className="bg-gray-900 text-gray-100 rounded-lg p-4 h-96 overflow-y-auto font-mono text-xs"
      >
        {logs.length === 0 ? (
          <div className="text-gray-500 text-center py-8">No logs available</div>
        ) : (
          logs.map((log) => (
            <div key={log.id} className="mb-1 last:mb-0">
              <span className="text-gray-500">[{new Date(log.timestamp).toLocaleTimeString()}]</span>
              {' '}
              <LogLevelBadge level={log.level} />
              {' '}
              <span className={log.level === LogLevel.ERROR || log.level === LogLevel.CRITICAL ? 'text-red-400' : ''}>
                {log.message}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

// =============================================================================
// Main Component
// =============================================================================

export const SessionDetailPage: React.FC = () => {
  const { sessionId } = useParams<{ sessionId: string }>();
  const navigate = useNavigate();

  // State
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [messages, setMessages] = useState<SessionMessage[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [timelineItems, setTimelineItems] = useState<TimelineItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'timeline' | 'messages' | 'tools' | 'logs'>('timeline');
  const [isStreaming, setIsStreaming] = useState(false);
  const [wsConnected, setWsConnected] = useState(false);

  // WebSocket ref
  const wsRef = useRef<AgentWebSocket | null>(null);

  // View modes configuration
  const viewModes: ViewMode[] = [
    { type: 'timeline', label: 'Timeline' },
    { type: 'messages', label: 'Messages' },
    { type: 'tools', label: 'Tool Calls' },
    { type: 'logs', label: 'Live Logs' },
  ];

  // Fetch session data
  const fetchSessionData = useCallback(async () => {
    if (!sessionId) return;

    setIsLoading(true);
    setError(null);

    try {
      const [sessionData, messagesData, logsData] = await Promise.all([
        getSession(sessionId),
        getSessionMessages(sessionId, 100, 0),
        getSessionLogs(sessionId, { levelFilter: undefined, since: undefined }),
      ]);

      setSession(sessionData);
      setMessages(messagesData);
      setLogs(logsData.logs);

      // Build timeline items
      const items: TimelineItem[] = [];

      // Add messages to timeline
      messagesData.forEach((msg) => {
        items.push({
          id: msg.id,
          timestamp: msg.timestamp,
          type: 'message',
          role: msg.role,
          content: msg.content,
          tokensUsed: msg.tokens_used,
        });

        // Add tool calls
        if (msg.tool_calls) {
          msg.tool_calls.forEach((tool, idx) => {
            items.push({
              id: `${msg.id}-tool-${idx}`,
              timestamp: msg.timestamp,
              type: 'tool_call',
              toolName: tool.name || tool.function?.name,
              toolInput: tool.arguments || tool.function?.arguments,
              toolOutput: tool.result,
            });
          });
        }
      });

      // Add logs to timeline (non-debug logs)
      logsData.logs
        .filter((log) => log.level !== LogLevel.DEBUG)
        .forEach((log) => {
          items.push({
            id: log.id,
            timestamp: log.timestamp,
            type: 'log',
            logLevel: log.level,
            content: log.message,
          });
        });

      // Sort by timestamp
      items.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

      setTimelineItems(items);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load session');
    } finally {
      setIsLoading(false);
    }
  }, [sessionId]);

  // Setup WebSocket for real-time updates
  useEffect(() => {
    if (!sessionId) return;

    const callbacks: WebSocketCallbacks = {
      onOpen: () => {
        setWsConnected(true);
        setIsStreaming(true);
      },
      onClose: () => {
        setWsConnected(false);
        setIsStreaming(false);
      },
      onError: (err) => {
        console.error('WebSocket error:', err);
        setWsConnected(false);
      },
      onMessage: (event: AgentEvent) => {
        if (event.session_id === sessionId) {
          switch (event.event_type) {
            case EventType.SESSION_UPDATED:
            case EventType.LOG_ENTRY:
              // Fetch updated logs
              getSessionLogs(sessionId).then((logData) => {
                setLogs(logData.logs);
              });
              break;
            case EventType.SESSION_COMPLETED:
            case EventType.SESSION_FAILED:
              // Refresh session data
              fetchSessionData();
              break;
          }
        }
      },
    };

    wsRef.current = createSessionWebSocket(sessionId, callbacks);
    wsRef.current.connect();

    return () => {
      wsRef.current?.disconnect();
    };
  }, [sessionId, fetchSessionData]);

  // Initial data fetch
  useEffect(() => {
    fetchSessionData();
  }, [fetchSessionData]);

  // Calculate aggregated metrics
  const getAggregatedMetrics = useCallback((): SessionMetrics => {
    if (!session) {
      return {
        total_messages: 0,
        total_tokens_used: 0,
        execution_time_seconds: 0,
        tool_calls_count: 0,
      };
    }
    return session.metrics;
  }, [session]);

  // Extract all tool calls
  const getAllToolCalls = useCallback(() => {
    const calls: Record<string, any>[] = [];
    messages.forEach((msg) => {
      if (msg.tool_calls) {
        msg.tool_calls.forEach((tool) => {
          calls.push({ ...tool, messageId: msg.id, timestamp: msg.timestamp });
        });
      }
    });
    return calls;
  }, [messages]);

  // Handle loading state
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  // Handle error state
  if (error || !session) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <div className="text-red-600 mb-2">Error loading session</div>
          <div className="text-gray-600">{error || 'Session not found'}</div>
          <button
            onClick={() => navigate(-1)}
            className="mt-4 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
          >
            Go Back
          </button>
        </div>
      </div>
    );
  }

  const metrics = getAggregatedMetrics();
  const toolCalls = getAllToolCalls();

  return (
    <div className="container mx-auto px-4 py-6 max-w-7xl">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate(-1)}
              className="text-gray-600 hover:text-gray-900"
            >
              <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </button>
            <div>
              <h1 className="text-2xl font-bold text-gray-900">Session Details</h1>
              <p className="text-sm text-gray-600">
                ID: <span className="font-mono">{sessionId}</span>
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <StatusBadge state={session.state} />
            {wsConnected && (
              <div className="flex items-center gap-1 text-green-600 text-sm">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
                </span>
                Connected
              </div>
            )}
          </div>
        </div>

        {/* Session Metadata */}
        <div className="bg-white rounded-lg border p-4 shadow-sm">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <span className="text-gray-600">Agent Type:</span>
              <span className="ml-2 font-medium">{session.agent_type}</span>
            </div>
            <div>
              <span className="text-gray-600">Container:</span>
              <span className="ml-2 font-mono">{session.container_id.slice(0, 12)}...</span>
            </div>
            <div>
              <span className="text-gray-600">Host:</span>
              <span className="ml-2 font-medium">{session.host_id}</span>
            </div>
            <div>
              <span className="text-gray-600">Created:</span>
              <span className="ml-2">{new Date(session.created_at).toLocaleString()}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <MetricCard
          label="Total Messages"
          value={metrics.total_messages}
        />
        <MetricCard
          label="Total Tokens"
          value={metrics.total_tokens_used.toLocaleString()}
          icon={<svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>}
        />
        <MetricCard
          label="Estimated Cost"
          value={`$${(metrics.estimated_cost || 0).toFixed(4)}`}
          icon={<svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>}
        />
        <MetricCard
          label="Duration"
          value={Math.floor(metrics.execution_time_seconds / 60)}
          unit="min"
          icon={<svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>}
        />
      </div>

      {/* View Mode Tabs */}
      <div className="mb-4 border-b">
        <div className="flex gap-4">
          {viewModes.map((mode) => (
            <button
              key={mode.type}
              onClick={() => setViewMode(mode.type)}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                viewMode === mode.type
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-gray-600 hover:text-gray-900 hover:border-gray-300'
              }`}
            >
              {mode.label}
              {mode.type === 'tools' && ` (${toolCalls.length})`}
              {mode.type === 'logs' && logs.length > 0 && ` (${logs.length})`}
            </button>
          ))}
        </div>
      </div>

      {/* Content Area */}
      <div className="bg-white rounded-lg border shadow-sm">
        {viewMode === 'timeline' && (
          <div className="p-4">
            <h2 className="text-lg font-semibold mb-4">Session Timeline</h2>
            {timelineItems.length === 0 ? (
              <div className="text-center text-gray-500 py-8">No timeline events</div>
            ) : (
              <div className="space-y-2 max-h-[600px] overflow-y-auto">
                {timelineItems.map((item) => (
                  <TimelineItem key={item.id} item={item} />
                ))}
              </div>
            )}
          </div>
        )}

        {viewMode === 'messages' && (
          <div className="p-4">
            <h2 className="text-lg font-semibold mb-4">Message Stream</h2>
            {messages.length === 0 ? (
              <div className="text-center text-gray-500 py-8">No messages</div>
            ) : (
              <div className="max-h-[600px] overflow-y-auto">
                {messages.map((msg) => (
                  <MessageBubble key={msg.id} message={msg} />
                ))}
              </div>
            )}
          </div>
        )}

        {viewMode === 'tools' && (
          <div className="p-4">
            <h2 className="text-lg font-semibold mb-4">
              Tool Calls ({toolCalls.length})
            </h2>
            {toolCalls.length === 0 ? (
              <div className="text-center text-gray-500 py-8">No tool calls</div>
            ) : (
              <div className="max-h-[600px] overflow-y-auto">
                {toolCalls.map((tool, idx) => (
                  <ToolCallCard key={`${tool.messageId}-${idx}`} toolCall={tool} index={idx} />
                ))}
              </div>
            )}
          </div>
        )}

        {viewMode === 'logs' && (
          <div className="p-4">
            <h2 className="text-lg font-semibold mb-4">Real-time Log Stream</h2>
            <LogStream logs={logs} isStreaming={isStreaming} />
          </div>
        )}
      </div>

      {/* Error Display */}
      {session.error_message && (
        <div className="mt-6 bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <svg className="w-5 h-5 text-red-600 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <h3 className="font-medium text-red-900">Session Error</h3>
              <p className="text-sm text-red-700 mt-1">{session.error_message}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SessionDetailPage;
