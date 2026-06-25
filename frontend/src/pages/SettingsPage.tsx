import { useState, useEffect, useCallback } from 'react';
import {
  Save,
  CheckCircle,
  AlertCircle,
  Eye,
  EyeOff,
  Zap,
  Plug,
  Loader2,
} from 'lucide-react';
import { httpClient } from '@/api';
import { useReplayContext } from '@/contexts/ReplayContext';

interface Variable {
  key: string;
  label: string;
  group: string;
  type: string;
  required?: boolean;
  default?: string;
  placeholder?: string;
  description?: string;
  options?: string[];
}

interface Group {
  id: string;
  title: string;
  description: string;
}

interface Schema {
  groups: Group[];
  variables: Variable[];
  presets: Record<string, Record<string, string>>;
}

export function SettingsPage() {
  const { replay } = useReplayContext();

  const [schema, setSchema] = useState<Schema | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [originalValues, setOriginalValues] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveStatus, setSaveStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const [saveMessage, setSaveMessage] = useState('');
  const [showPasswords, setShowPasswords] = useState<Record<string, boolean>>({});
  const [validation, setValidation] = useState<{ valid: boolean; missing: string[] } | null>(null);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{
    success: boolean;
    reply?: string;
    model?: string;
    latency_s?: number;
    error?: string;
  } | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const [schemaRes, credRes, validRes] = await Promise.all([
        httpClient.get('/api/settings/schema'),
        httpClient.get('/api/settings/credentials'),
        httpClient.get('/api/settings/validate'),
      ]);
      setSchema(schemaRes.data);
      setValues(credRes.data.values);
      setOriginalValues(credRes.data.values);
      setValidation(validRes.data);
    } catch (e) {
      console.error('Failed to load settings', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleChange = (key: string, value: string) => {
    setValues((prev) => ({ ...prev, [key]: value }));
    setSaveStatus('idle');
  };

  const handleSave = async () => {
    setSaving(true);
    setSaveStatus('idle');
    try {
      const updates: Record<string, string> = {};
      for (const [key, val] of Object.entries(values)) {
        if (val !== originalValues[key]) {
          updates[key] = val;
        }
      }

      const res = await httpClient.post('/api/settings/credentials', { values: updates });

      if (res.status === 200) {
        setSaveStatus('success');
        setSaveMessage('Credentials saved. Restart the dashboard to apply to new agent containers.');
        const [credRes, validRes] = await Promise.all([
          httpClient.get('/api/settings/credentials'),
          httpClient.get('/api/settings/validate'),
        ]);
        setValues(credRes.data.values);
        setOriginalValues(credRes.data.values);
        setValidation(validRes.data);
      } else {
        setSaveStatus('error');
        setSaveMessage('Failed to save credentials.');
      }
    } catch (e) {
      setSaveStatus('error');
      setSaveMessage('Network error. Is the dashboard running?');
    } finally {
      setSaving(false);
    }
  };

  const handlePreset = (presetKey: string) => {
    if (!schema) return;
    const preset = schema.presets[presetKey];
    if (!preset) return;
    setValues((prev) => ({ ...prev, ...preset }));
    setSaveStatus('idle');
  };

  const handleTestConnection = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await httpClient.post('/api/settings/test-connection', {
        api_key: values.OPENCODE_API_KEY || undefined,
        base_url: values.LLM_URL || undefined,
        model: values.LLM_MODEL || undefined,
      });
      setTestResult(res.data);
    } catch (e) {
      setTestResult({ success: false, error: 'Network error. Is the dashboard running?' });
    } finally {
      setTesting(false);
    }
  };

  const hasChanges = JSON.stringify(values) !== JSON.stringify(originalValues);

  const togglePassword = (key: string) => {
    setShowPasswords((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="text-trident-muted">Loading settings...</div>
      </div>
    );
  }

  if (!schema) {
    return (
      <div className="flex h-full items-center justify-center">
          <div className="text-red-400 dark:text-red-300">Failed to load settings schema.</div>
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col gap-6 overflow-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="font-heading text-2xl font-bold text-trident-text">Settings</h2>
          <p className="text-sm text-trident-muted">
            Configure LLM provider credentials for OpenCode agents
          </p>
        </div>
        <button
          onClick={handleSave}
          disabled={saving || !hasChanges}
          className={`btn-primary gap-2 ${!hasChanges ? 'opacity-50 cursor-not-allowed' : ''}`}
        >
          <Save size={16} />
          {saving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>

      {/* Status message */}
      {saveStatus !== 'idle' && (
        <div
          className={`flex items-center gap-2 rounded-lg px-4 py-2 text-sm ${
            saveStatus === 'success'
              ? 'bg-emerald-50 text-emerald-700 border border-emerald-300 dark:bg-emerald-950 dark:text-emerald-200 dark:border-emerald-700'
              : 'bg-red-50 text-red-700 border border-red-300 dark:bg-red-950 dark:text-red-200 dark:border-red-700'
          }`}
        >
          {saveStatus === 'success' ? <CheckCircle size={16} /> : <AlertCircle size={16} />}
          {saveMessage}
        </div>
      )}

      {/* Validation warnings */}
      {validation && !validation.valid && (
        <div className="flex items-center gap-2 rounded-lg px-4 py-2 text-sm bg-amber-50 text-amber-700 border border-amber-300 dark:bg-amber-950 dark:text-amber-200 dark:border-amber-700">
          <AlertCircle size={16} />
          Missing required credentials: {validation.missing.join(', ')}
        </div>
      )}

      {/* Provider presets */}
      <div className="card">
        <h3 className="text-sm font-semibold text-trident-text mb-3 flex items-center gap-2">
          <Zap size={16} className="text-trident-accent" />
          Quick Presets
        </h3>
        <div className="flex flex-wrap gap-2">
          {Object.entries(schema.presets).map(([key]) => (
            <button
              key={key}
              onClick={() => handlePreset(key)}
              className="btn-ghost text-xs gap-1.5"
            >
              <span className="font-mono">{key}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Credentials form */}
      {schema.groups.map((group) => {
        const groupVars = schema.variables.filter((v) => v.group === group.id);
        if (groupVars.length === 0) return null;

        return (
          <div key={group.id} className="card">
            <h3 className="text-base font-semibold text-trident-text mb-1">{group.title}</h3>
            <p className="text-xs text-trident-muted mb-4">{group.description}</p>

            <div className="space-y-4">
              {groupVars.map((v) => (
                <div key={v.key}>
                  <label className="block text-sm font-medium text-trident-text mb-1">
                    {v.label}
                    {v.required && <span className="text-red-400 dark:text-red-300 ml-1">*</span>}
                  </label>

                  {v.type === 'select' ? (
                    <select
                      value={values[v.key] || ''}
                      onChange={(e) => handleChange(v.key, e.target.value)}
                      className="w-full rounded-lg border border-trident-border bg-trident-surface px-3 py-2 text-sm text-trident-text font-mono focus:border-trident-accent focus:outline-none focus:ring-1 focus:ring-trident-accent"
                    >
                      <option value="">Select...</option>
                      {v.options?.map((opt) => (
                        <option key={opt} value={opt}>
                          {opt}
                        </option>
                      ))}
                    </select>
                  ) : v.type === 'password' ? (
                    <div className="relative">
                      <input
                        type={showPasswords[v.key] ? 'text' : 'password'}
                        value={values[v.key] || ''}
                        onChange={(e) => handleChange(v.key, e.target.value)}
                        placeholder={v.placeholder}
                        className="w-full rounded-lg border border-trident-border bg-trident-surface px-3 py-2 pr-10 text-sm text-trident-text font-mono focus:border-trident-accent focus:outline-none focus:ring-1 focus:ring-trident-accent"
                      />
                      <button
                        type="button"
                        onClick={() => togglePassword(v.key)}
                        className="absolute right-2 top-1/2 -translate-y-1/2 text-trident-muted hover:text-trident-text"
                      >
                        {showPasswords[v.key] ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                  ) : (
                    <input
                      type="text"
                      value={values[v.key] || ''}
                      onChange={(e) => handleChange(v.key, e.target.value)}
                      placeholder={v.placeholder}
                      className="w-full rounded-lg border border-trident-border bg-trident-surface px-3 py-2 text-sm text-trident-text font-mono focus:border-trident-accent focus:outline-none focus:ring-1 focus:ring-trident-accent"
                    />
                  )}

                  {v.description && (
                    <p className="text-xs text-trident-muted/70 mt-1">{v.description}</p>
                  )}
                </div>
              ))}

              {/* Test Connection button */}
              {group.id === 'provider' && (
                <div className="pt-2">
                  <button
                    onClick={handleTestConnection}
                    disabled={testing}
                    className="btn-ghost gap-2 text-sm"
                  >
                    {testing ? (
                      <Loader2 size={16} className="animate-spin" />
                    ) : (
                      <Plug size={16} />
                    )}
                    {testing ? 'Testing...' : 'Test Connection'}
                  </button>

                  {testResult && (
                    <div
                      className={`mt-3 rounded-lg px-4 py-3 text-sm ${
                        testResult.success
                          ? 'bg-emerald-50 text-emerald-700 border border-emerald-300 dark:bg-emerald-950 dark:text-emerald-200 dark:border-emerald-700'
                          : 'bg-red-50 text-red-700 border border-red-300 dark:bg-red-950 dark:text-red-200 dark:border-red-700'
                      }`}
                    >
                      {testResult.success ? (
                        <div className="space-y-1">
                          <div className="flex items-center gap-2 font-medium">
                            <CheckCircle size={16} /> Connected
                          </div>
                          <div className="text-xs opacity-80">
                            Model: <span className="font-mono">{testResult.model}</span>
                            {' · '}Latency: {testResult.latency_s}s
                          </div>
                          {testResult.reply && (
                            <div className="text-xs opacity-80">
                              Response: <span className="font-mono">"{testResult.reply}"</span>
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="space-y-1">
                          <div className="flex items-center gap-2 font-medium">
                            <AlertCircle size={16} /> Connection failed
                          </div>
                          <div className="text-xs font-mono break-all opacity-80">
                            {testResult.error}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        );
      })}

      {/* Replay Status (preserved from original) */}
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

      {/* Agent Configuration (preserved from original) */}
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

      {/* Footer hint */}
      <p className="text-center text-xs text-trident-muted/50 pb-4">
        Credentials are saved to <code className="font-mono">credentials.env</code> and injected
        into agent containers.
      </p>
    </div>
  );
}
