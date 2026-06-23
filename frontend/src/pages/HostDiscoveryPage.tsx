/**
 * HostDiscoveryPage - Container Discovery and Agent Assignment
 *
 * Features:
 * - Container list/table with filters (topology, network, host type)
 * - Current agent assignments display
 * - Assignment dialog for host + agent type selection
 * - Status indicators (OpenCode health, session status)
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  ContainerInfo,
  ContainerDiscoveryResponse,
  ContainerState,
  HostType,
  AgentType,
  AgentTemplate,
  AgentTemplatesResponse,
  AgentAssignment,
  AgentAssignmentResponse,
  AgentAssignmentState,
  SessionState,
  HealthResponse,
} from '../types';
import {
  discoverContainers,
  getAgentTemplates,
  assignAgent,
  getHealth,
  getContainerByHost,
  getJobStatus,
  getErrorMessage,
} from '../api';

// =============================================================================
// Types
// =============================================================================

interface HostDiscoveryFilters {
  topologyId: string;
  networkId: string;
  hostType: HostType | 'all';
  state: ContainerState | 'all';
  hasAgents: boolean | 'all';
  searchQuery: string;
}

interface AssignmentDialogState {
  isOpen: boolean;
  selectedContainer: ContainerInfo | null;
  selectedAgentType: AgentType | null;
  isAssigning: boolean;
  error: string | null;
  jobId: string | null;
}

interface ContainerWithStatus extends ContainerInfo {
  opencodeHealth?: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  activeSessions?: number;
}

// =============================================================================
// Helper Components
// =============================================================================

const ContainerStateBadge: React.FC<{ state: ContainerState }> = ({ state }) => {
  const colors: Record<ContainerState, string> = {
    [ContainerState.RUNNING]: 'bg-green-100 text-green-800 border-green-200',
    [ContainerState.STOPPED]: 'bg-gray-100 text-gray-800 border-gray-200',
    [ContainerState.PAUSED]: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    [ContainerState.RESTARTING]: 'bg-blue-100 text-blue-800 border-blue-200',
    [ContainerState.EXITED]: 'bg-red-100 text-red-800 border-red-200',
    [ContainerState.DEAD]: 'bg-red-100 text-red-800 border-red-200',
    [ContainerState.REMOVING]: 'bg-orange-100 text-orange-800 border-orange-200',
    [ContainerState.RECREATING]: 'bg-purple-100 text-purple-800 border-purple-200',
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded-full border ${colors[state]}`}>
      {state}
    </span>
  );
};

const OpenCodeHealthIndicator: React.FC<{
  opencodeReady: boolean;
  health?: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  port?: number;
}> = ({ opencodeReady, health = 'unknown', port }) => {
  if (!opencodeReady) {
    return (
      <div className="flex items-center space-x-2">
        <div className="w-2 h-2 rounded-full bg-gray-400" />
        <span className="text-xs text-gray-500">Not Ready</span>
      </div>
    );
  }

  const healthColors = {
    healthy: 'bg-green-500',
    degraded: 'bg-yellow-500',
    unhealthy: 'bg-red-500',
    unknown: 'bg-gray-400',
  };

  return (
    <div className="flex items-center space-x-2">
      <div className={`w-2 h-2 rounded-full ${healthColors[health]} animate-pulse`} />
      <span className="text-xs text-gray-600">
        {port ? `Port ${port}` : 'Ready'}
      </span>
    </div>
  );
};

const AgentTypeBadge: React.FC<{ agentType: AgentType; isRemovable?: boolean }> = ({
  agentType,
  isRemovable = true
}) => {
  const colors: Record<AgentType, string> = {
    [AgentType.CODER56]: 'bg-blue-100 text-blue-800 border-blue-200',
    [AgentType.DB_ADMIN]: 'bg-green-100 text-green-800 border-green-200',
    [AgentType.SOC_GOD]: 'bg-red-100 text-red-800 border-red-200',
  };

  const labels: Record<AgentType, string> = {
    [AgentType.CODER56]: 'Coder',
    [AgentType.DB_ADMIN]: 'DB Admin',
    [AgentType.SOC_GOD]: 'Defender',
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded-full border ${colors[agentType]}`}>
      {labels[agentType] || agentType}
    </span>
  );
};

const HostTypeBadge: React.FC<{ hostType: HostType }> = ({ hostType }) => {
  const colors: Record<HostType, string> = {
    [HostType.WEB_SERVER]: 'bg-blue-50 text-blue-700 border-blue-200',
    [HostType.DATABASE_SERVER]: 'bg-green-50 text-green-700 border-green-200',
    [HostType.WORKSTATION]: 'bg-purple-50 text-purple-700 border-purple-200',
    [HostType.FIREWALL]: 'bg-red-50 text-red-700 border-red-200',
    [HostType.ROUTER]: 'bg-orange-50 text-orange-700 border-orange-200',
    [HostType.SERVER]: 'bg-gray-50 text-gray-700 border-gray-200',
    [HostType.DOMAIN_ADMIN]: 'bg-indigo-50 text-indigo-700 border-indigo-200',
    [HostType.NORMAL_USER]: 'bg-yellow-50 text-yellow-700 border-yellow-200',
  };

  const labels: Record<HostType, string> = {
    [HostType.WEB_SERVER]: 'Web Server',
    [HostType.DATABASE_SERVER]: 'Database',
    [HostType.WORKSTATION]: 'Workstation',
    [HostType.FIREWALL]: 'Firewall',
    [HostType.ROUTER]: 'Router',
    [HostType.SERVER]: 'Server',
    [HostType.DOMAIN_ADMIN]: 'Domain Admin',
    [HostType.NORMAL_USER]: 'Normal User',
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded border ${colors[hostType]}`}>
      {labels[hostType] || hostType}
    </span>
  );
};

const AssignmentDialog: React.FC<{
  state: AssignmentDialogState;
  agentTemplates: AgentTemplate[];
  onClose: () => void;
  onAgentTypeSelect: (agentType: AgentType) => void;
  onConfirm: () => void;
}> = ({ state, agentTemplates, onClose, onAgentTypeSelect, onConfirm }) => {
  const [selectedTemplate, setSelectedTemplate] = useState<AgentTemplate | null>(null);

  useEffect(() => {
    if (state.selectedAgentType) {
      const template = agentTemplates.find(t => t.agent_type === state.selectedAgentType);
      setSelectedTemplate(template || null);
    }
  }, [state.selectedAgentType, agentTemplates]);

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-[80vh] overflow-y-auto">
        <div className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-semibold">Assign Agent to Host</h3>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 text-2xl"
              disabled={state.isAssigning}
            >
              ×
            </button>
          </div>

          {state.selectedContainer && (
            <div className="mb-6 p-4 bg-gray-50 rounded-lg">
              <h4 className="font-medium mb-2">Target Container</h4>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div>
                  <span className="text-gray-500">Host:</span>
                  <span className="ml-2 font-medium">{state.selectedContainer.host_name}</span>
                </div>
                <div>
                  <span className="text-gray-500">Type:</span>
                  <span className="ml-2"><HostTypeBadge hostType={state.selectedContainer.host_type} /></span>
                </div>
                <div>
                  <span className="text-gray-500">Image:</span>
                  <span className="ml-2 font-mono text-xs">{state.selectedContainer.image}</span>
                </div>
                <div>
                  <span className="text-gray-500">State:</span>
                  <span className="ml-2"><ContainerStateBadge state={state.selectedContainer.state} /></span>
                </div>
              </div>

              {state.selectedContainer.current_agents.length > 0 && (
                <div className="mt-3">
                  <span className="text-gray-500 text-sm">Current Agents:</span>
                  <div className="flex flex-wrap gap-2 mt-1">
                    {state.selectedContainer.current_agents.map(agent => (
                      <AgentTypeBadge key={agent} agentType={agent} />
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          <div className="mb-6">
            <h4 className="font-medium mb-3">Select Agent Type</h4>
            <div className="grid grid-cols-1 gap-3">
              {agentTemplates.map((template) => (
                <button
                  key={template.agent_type}
                  onClick={() => onAgentTypeSelect(template.agent_type)}
                  disabled={state.isAssigning || !template.opencode_image_required}
                  className={`p-4 rounded-lg border-2 text-left transition-all ${
                    state.selectedAgentType === template.agent_type
                      ? 'border-blue-500 bg-blue-50'
                      : 'border-gray-200 hover:border-gray-300'
                  } ${
                    !template.opencode_image_required
                      ? 'opacity-50 cursor-not-allowed'
                      : ''
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="font-medium text-gray-900">{template.name}</div>
                      <div className="text-sm text-gray-500 mt-1">{template.description}</div>
                      <div className="flex flex-wrap gap-1 mt-2">
                        {template.capabilities.slice(0, 3).map((cap, idx) => (
                          <span key={idx} className="text-xs bg-gray-100 px-2 py-1 rounded">
                            {cap.name}
                          </span>
                        ))}
                        {template.capabilities.length > 3 && (
                          <span className="text-xs text-gray-400">
                            +{template.capabilities.length - 3} more
                          </span>
                        )}
                      </div>
                    </div>
                    {state.selectedAgentType === template.agent_type && (
                      <div className="text-blue-500 text-xl">✓</div>
                    )}
                  </div>
                </button>
              ))}
            </div>
          </div>

          {selectedTemplate && state.selectedAgentType && (
            <div className="mb-6 p-4 bg-blue-50 rounded-lg">
              <h4 className="font-medium text-blue-900 mb-2">Selected Agent Details</h4>
              <div className="text-sm text-blue-800 space-y-1">
                <p><strong>Type:</strong> {selectedTemplate.name}</p>
                <p><strong>Base Image:</strong> {selectedTemplate.supported_base_images.join(', ')}</p>
                <p><strong>Capabilities:</strong></p>
                <ul className="list-disc list-inside ml-2">
                  {selectedTemplate.capabilities.map((cap, idx) => (
                    <li key={idx}>{cap.name}: {cap.description}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}

          {state.error && (
            <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
              {state.error}
            </div>
          )}

          {state.jobId && (
            <div className="mb-4 p-3 bg-blue-50 border border-blue-200 rounded-lg text-blue-700 text-sm">
              <div className="flex items-center space-x-2">
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600" />
                <span>Assignment in progress... Job ID: {state.jobId}</span>
              </div>
            </div>
          )}

          <div className="flex justify-end space-x-3">
            <button
              onClick={onClose}
              disabled={state.isAssigning}
              className="px-4 py-2 text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              onClick={onConfirm}
              disabled={!state.selectedAgentType || state.isAssigning}
              className="px-4 py-2 text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {state.isAssigning ? 'Assigning...' : 'Assign Agent'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

const ContainerRow: React.FC<{
  container: ContainerWithStatus;
  onAssignClick: (container: ContainerInfo) => void;
}> = ({ container, onAssignClick }) => {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border border-gray-200 rounded-lg mb-3 overflow-hidden">
      <div
        className="p-4 cursor-pointer hover:bg-gray-50 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center justify-between">
          <div className="flex-1 grid grid-cols-12 gap-4 items-center">
            {/* Expand Button */}
            <div className="col-span-1">
              <button className="text-gray-400 hover:text-gray-600">
                {expanded ? '▼' : '▶'}
              </button>
            </div>

            {/* Container Name */}
            <div className="col-span-2">
              <div className="font-medium text-gray-900">{container.container_name}</div>
              <div className="text-xs text-gray-500 truncate">{container.container_id.slice(0, 12)}</div>
            </div>

            {/* Host Info */}
            <div className="col-span-2">
              <div className="text-sm font-medium">{container.host_name}</div>
              <div className="mt-1"><HostTypeBadge hostType={container.host_type} /></div>
            </div>

            {/* Network/Topology */}
            <div className="col-span-2">
              <div className="text-xs text-gray-500">Topology</div>
              <div className="text-sm font-mono">{container.topology_id.slice(0, 8)}...</div>
              <div className="text-xs text-gray-500 mt-1">Network</div>
              <div className="text-sm font-mono">{container.network_id.slice(0, 8)}...</div>
            </div>

            {/* IP Address */}
            <div className="col-span-1">
              <div className="text-sm font-mono">{container.ip_address || 'N/A'}</div>
            </div>

            {/* State */}
            <div className="col-span-1">
              <ContainerStateBadge state={container.state} />
            </div>

            {/* OpenCode Status */}
            <div className="col-span-1">
              <OpenCodeHealthIndicator
                opencodeReady={container.opencode_ready}
                health={container.opencodeHealth}
                port={container.opencode_port}
              />
            </div>

            {/* Current Agents */}
            <div className="col-span-1">
              <div className="flex flex-wrap gap-1">
                {container.current_agents.length > 0 ? (
                  container.current_agents.map(agent => (
                    <AgentTypeBadge key={agent} agentType={agent} />
                  ))
                ) : (
                  <span className="text-xs text-gray-400">None</span>
                )}
              </div>
              {container.activeSessions !== undefined && container.activeSessions > 0 && (
                <div className="text-xs text-green-600 mt-1">
                  {container.activeSessions} active session{container.activeSessions > 1 ? 's' : ''}
                </div>
              )}
            </div>

            {/* Actions */}
            <div className="col-span-1">
              {container.can_assign_agent && (
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onAssignClick(container);
                  }}
                  className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
                >
                  Assign Agent
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {expanded && (
        <div className="p-4 bg-gray-50 border-t border-gray-200">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="font-medium text-gray-700">Image:</span>
              <span className="ml-2 font-mono text-gray-600">{container.image}</span>
            </div>
            <div>
              <span className="font-medium text-gray-700">Container ID:</span>
              <span className="ml-2 font-mono text-gray-600">{container.container_id}</span>
            </div>
            <div>
              <span className="font-medium text-gray-700">Host ID:</span>
              <span className="ml-2 font-mono text-gray-600">{container.host_id}</span>
            </div>
            <div>
              <span className="font-medium text-gray-700">Labels:</span>
              <div className="ml-2 mt-1">
                {Object.entries(container.labels).map(([key, value]) => (
                  <span key={key} className="inline-block bg-gray-200 px-2 py-0.5 rounded text-xs mr-1 mb-1">
                    {key}={value}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const FiltersPanel: React.FC<{
  filters: HostDiscoveryFilters;
  onFilterChange: (filters: Partial<HostDiscoveryFilters>) => void;
  onRefresh: () => void;
  isLoading: boolean;
  containerCount: number;
}> = ({ filters, onFilterChange, onRefresh, isLoading, containerCount }) => {
  return (
    <div className="bg-white rounded-lg shadow-sm p-4 mb-4">
      <div className="flex flex-wrap items-center gap-4">
        {/* Search Query */}
        <div className="flex-1 min-w-[200px]">
          <input
            type="text"
            placeholder="Search containers or hosts..."
            value={filters.searchQuery}
            onChange={(e) => onFilterChange({ searchQuery: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          />
        </div>

        {/* Topology Filter */}
        <div>
          <input
            type="text"
            placeholder="Topology ID"
            value={filters.topologyId}
            onChange={(e) => onFilterChange({ topologyId: e.target.value })}
            className="w-40 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          />
        </div>

        {/* Network Filter */}
        <div>
          <input
            type="text"
            placeholder="Network ID"
            value={filters.networkId}
            onChange={(e) => onFilterChange({ networkId: e.target.value })}
            className="w-40 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          />
        </div>

        {/* Host Type Filter */}
        <div>
          <select
            value={filters.hostType}
            onChange={(e) => onFilterChange({ hostType: e.target.value as HostType | 'all' })}
            className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          >
            <option value="all">All Types</option>
            <option value={HostType.WEB_SERVER}>Web Server</option>
            <option value={HostType.DATABASE_SERVER}>Database</option>
            <option value={HostType.WORKSTATION}>Workstation</option>
            <option value={HostType.FIREWALL}>Firewall</option>
            <option value={HostType.ROUTER}>Router</option>
            <option value={HostType.SERVER}>Server</option>
          </select>
        </div>

        {/* State Filter */}
        <div>
          <select
            value={filters.state}
            onChange={(e) => onFilterChange({ state: e.target.value as ContainerState | 'all' })}
            className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          >
            <option value="all">All States</option>
            <option value={ContainerState.RUNNING}>Running</option>
            <option value={ContainerState.STOPPED}>Stopped</option>
            <option value={ContainerState.PAUSED}>Paused</option>
            <option value={ContainerState.EXITED}>Exited</option>
          </select>
        </div>

        {/* Agent Filter */}
        <div>
          <select
            value={String(filters.hasAgents)}
            onChange={(e) => onFilterChange({ hasAgents: e.target.value === 'true' ? true : e.target.value === 'false' ? false : 'all' })}
            className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          >
            <option value="all">All Containers</option>
            <option value="true">With Agents</option>
            <option value="false">Without Agents</option>
          </select>
        </div>

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isLoading}
          className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 disabled:opacity-50 flex items-center space-x-2"
        >
          <span>{isLoading ? 'Refreshing...' : 'Refresh'}</span>
          {!isLoading && <span>🔄</span>}
        </button>

        {/* Container Count */}
        <div className="text-sm text-gray-500">
          {containerCount} container{containerCount !== 1 ? 's' : ''}
        </div>
      </div>
    </div>
  );
};

// =============================================================================
// Main Page Component
// =============================================================================

export const HostDiscoveryPage: React.FC = () => {
  // State
  const [containers, setContainers] = useState<ContainerWithStatus[]>([]);
  const [filteredContainers, setFilteredContainers] = useState<ContainerWithStatus[]>([]);
  const [agentTemplates, setAgentTemplates] = useState<AgentTemplate[]>([]);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const [filters, setFilters] = useState<HostDiscoveryFilters>({
    topologyId: '',
    networkId: '',
    hostType: 'all',
    state: 'all',
    hasAgents: 'all',
    searchQuery: '',
  });

  const [assignmentDialog, setAssignmentDialog] = useState<AssignmentDialogState>({
    isOpen: false,
    selectedContainer: null,
    selectedAgentType: null,
    isAssigning: false,
    error: null,
    jobId: null,
  });

  // Fetch containers
  const fetchContainers = useCallback(async () => {
    try {
      setIsRefreshing(true);
      const response = await discoverContainers({
        topologyId: filters.topologyId || undefined,
        networkId: filters.networkId || undefined,
        state: filters.state === 'all' ? undefined : filters.state as ContainerState,
        hostType: filters.hostType === 'all' ? undefined : filters.hostType,
        hasAgents: filters.hasAgents === 'all' ? undefined : filters.hasAgents as boolean,
        includeStopped: true,
      });

      const containersWithStatus = response.containers.map(container => ({
        ...container,
        opencodeHealth: container.opencode_ready ? 'healthy' as const : 'unknown' as const,
        activeSessions: 0, // Would be populated from session data
      }));

      setContainers(containersWithStatus);

      // Apply client-side search filter
      let filtered = containersWithStatus;
      if (filters.searchQuery) {
        const query = filters.searchQuery.toLowerCase();
        filtered = filtered.filter(c =>
          c.container_name.toLowerCase().includes(query) ||
          c.host_name.toLowerCase().includes(query) ||
          c.container_id.toLowerCase().includes(query) ||
          c.host_id.toLowerCase().includes(query)
        );
      }

      setFilteredContainers(filtered);
    } catch (error) {
      console.error('Failed to fetch containers:', error);
    } finally {
      setIsRefreshing(false);
    }
  }, [filters]);

  // Fetch agent templates
  const fetchAgentTemplates = useCallback(async () => {
    try {
      const response = await getAgentTemplates();
      setAgentTemplates(Object.values(response.agents));
    } catch (error) {
      console.error('Failed to fetch agent templates:', error);
    }
  }, []);

  // Fetch health status
  const fetchHealth = useCallback(async () => {
    try {
      const response = await getHealth();
      setHealth(response);
    } catch (error) {
      console.error('Failed to fetch health:', error);
    }
  }, []);

  // Initial data fetch
  useEffect(() => {
    const loadData = async () => {
      setIsLoading(true);
      await Promise.all([
        fetchContainers(),
        fetchAgentTemplates(),
        fetchHealth(),
      ]);
      setIsLoading(false);
    };
    loadData();
  }, []);

  // Refetch when filters change (debounced would be better in production)
  useEffect(() => {
    if (!isLoading) {
      fetchContainers();
    }
  }, [filters.topologyId, filters.networkId, filters.hostType, filters.state, filters.hasAgents]);

  // Apply search filter immediately
  useEffect(() => {
    let filtered = containers;
    if (filters.searchQuery) {
      const query = filters.searchQuery.toLowerCase();
      filtered = filtered.filter(c =>
        c.container_name.toLowerCase().includes(query) ||
        c.host_name.toLowerCase().includes(query) ||
        c.container_id.toLowerCase().includes(query) ||
        c.host_id.toLowerCase().includes(query)
      );
    }
    setFilteredContainers(filtered);
  }, [filters.searchQuery, containers]);

  // Handle filter change
  const handleFilterChange = useCallback((newFilters: Partial<HostDiscoveryFilters>) => {
    setFilters(prev => ({ ...prev, ...newFilters }));
  }, []);

  // Handle assign button click
  const handleAssignClick = useCallback((container: ContainerInfo) => {
    setAssignmentDialog({
      isOpen: true,
      selectedContainer: container,
      selectedAgentType: null,
      isAssigning: false,
      error: null,
      jobId: null,
    });
  }, []);

  // Handle agent type selection in dialog
  const handleAgentTypeSelect = useCallback((agentType: AgentType) => {
    setAssignmentDialog(prev => ({
      ...prev,
      selectedAgentType: agentType,
      error: null,
    }));
  }, []);

  // Handle dialog close
  const handleDialogClose = useCallback(() => {
    setAssignmentDialog({
      isOpen: false,
      selectedContainer: null,
      selectedAgentType: null,
      isAssigning: false,
      error: null,
      jobId: null,
    });
  }, []);

  // Handle agent assignment confirmation
  const handleAssignConfirm = useCallback(async () => {
    if (!assignmentDialog.selectedContainer || !assignmentDialog.selectedAgentType) {
      return;
    }

    setAssignmentDialog(prev => ({
      ...prev,
      isAssigning: true,
      error: null,
    }));

    try {
      const assignment: AgentAssignment = {
        topology_id: assignmentDialog.selectedContainer!.topology_id,
        network_id: assignmentDialog.selectedContainer!.network_id,
        host_id: assignmentDialog.selectedContainer!.host_id,
        agent_type: assignmentDialog.selectedAgentType!,
      };

      const response = await assignAgent(assignment);

      setAssignmentDialog(prev => ({
        ...prev,
        jobId: response.job_id || null,
      }));

      // If job ID provided, poll for status
      if (response.job_id) {
        const pollInterval = setInterval(async () => {
          try {
            const jobStatus = await getJobStatus(response.job_id!);
            if (jobStatus.status === 'completed') {
              clearInterval(pollInterval);
              await fetchContainers(); // Refresh containers
              handleDialogClose();
            } else if (jobStatus.status === 'failed') {
              clearInterval(pollInterval);
              setAssignmentDialog(prev => ({
                ...prev,
                error: jobStatus.error || 'Assignment failed',
                isAssigning: false,
                jobId: null,
              }));
            }
          } catch (error) {
            clearInterval(pollInterval);
            setAssignmentDialog(prev => ({
              ...prev,
              error: getErrorMessage(error),
              isAssigning: false,
              jobId: null,
            }));
          }
        }, 1000);
      } else {
        // No job ID, assume immediate completion
        await fetchContainers();
        handleDialogClose();
      }
    } catch (error) {
      setAssignmentDialog(prev => ({
        ...prev,
        error: getErrorMessage(error),
        isAssigning: false,
        jobId: null,
      }));
    }
  }, [assignmentDialog.selectedContainer, assignmentDialog.selectedAgentType, fetchContainers, handleDialogClose]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading Host Discovery...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-100 p-6">
      {/* Header */}
      <header className="mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Host Discovery</h1>
            <p className="text-gray-600 mt-1">
              Discover containers and assign AI agents
            </p>
          </div>
          {health && (
            <div className="flex items-center space-x-4">
              <div className="text-sm">
                <span className="text-gray-500">System Health: </span>
                <span className={`font-medium ${
                  health.status === 'healthy' ? 'text-green-600' :
                  health.status === 'degraded' ? 'text-yellow-600' : 'text-red-600'
                }`}>
                  {health.status}
                </span>
              </div>
            </div>
          )}
        </div>
      </header>

      {/* Filters */}
      <FiltersPanel
        filters={filters}
        onFilterChange={handleFilterChange}
        onRefresh={fetchContainers}
        isLoading={isRefreshing}
        containerCount={filteredContainers.length}
      />

      {/* Container List */}
      <div className="bg-white rounded-lg shadow-sm p-4">
        <div className="mb-4">
          <h2 className="text-xl font-semibold text-gray-900">Discovered Containers</h2>
        </div>

        {/* Table Header */}
        <div className="hidden md:grid grid-cols-12 gap-4 px-4 py-2 bg-gray-50 rounded-t-lg border-b border-gray-200 text-sm font-medium text-gray-500">
          <div className="col-span-1"></div>
          <div className="col-span-2">Container</div>
          <div className="col-span-2">Host</div>
          <div className="col-span-2">Topology/Network</div>
          <div className="col-span-1">IP Address</div>
          <div className="col-span-1">State</div>
          <div className="col-span-1">OpenCode</div>
          <div className="col-span-1">Agents</div>
          <div className="col-span-1">Actions</div>
        </div>

        {/* Container Rows */}
        <div className="mt-2">
          {filteredContainers.length > 0 ? (
            filteredContainers.map((container) => (
              <ContainerRow
                key={container.container_id}
                container={container}
                onAssignClick={handleAssignClick}
              />
            ))
          ) : (
            <div className="text-center py-12 text-gray-500">
              <p className="text-lg">No containers found</p>
              <p className="text-sm mt-2">Try adjusting your filters or refresh the discovery</p>
            </div>
          )}
        </div>
      </div>

      {/* Assignment Dialog */}
      {assignmentDialog.isOpen && (
        <AssignmentDialog
          state={assignmentDialog}
          agentTemplates={agentTemplates}
          onClose={handleDialogClose}
          onAgentTypeSelect={handleAgentTypeSelect}
          onConfirm={handleAssignConfirm}
        />
      )}
    </div>
  );
};

export default HostDiscoveryPage;
