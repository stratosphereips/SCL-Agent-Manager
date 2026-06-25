import { useState, useEffect, useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  Server, Network, Users, Activity, Plus, RefreshCw, Trash2,
  CheckCircle, XCircle, AlertCircle, Clock, Zap
} from 'lucide-react';
import api from '@/api';
import type { Topology, Host, AgentAssignment, AgentTemplate } from '@/types';

interface DashboardStats {
  topologies: number;
  activeHosts: number;
  assignedAgents: number;
  runningSessions: number;
}

export function DashboardPage() {
  const [selectedTopology, setSelectedTopology] = useState<Topology | null>(null);
  const [topologies, setTopologies] = useState<Topology[]>([]);
  const [agentTemplates, setAgentTemplates] = useState<Record<string, AgentTemplate>>({});
  const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set());
  const [selectedAgents, setSelectedAgents] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [assignmentStatus, setAssignmentStatus] = useState<string | null>(null);

  // Fetch topologies and agent templates on mount
  useEffect(() => {
    Promise.all([
      api.getTopologies(),
      api.getAgentTemplates()
    ])
      .then(([toposData, templatesData]) => {
        setTopologies(toposData.topologies || []);
        setAgentTemplates(templatesData.agents || {});
        setLoading(false);
      })
      .catch(err => {
        setError(err.message || 'Failed to load data');
        setLoading(false);
      });
  }, []);

  // Calculate stats
  const stats = useMemo<DashboardStats>(() => {
    const activeHosts = selectedTopology
      ? selectedTopology.networks?.reduce((sum, net) =>
          sum + (net.hosts?.length || 0), 0) || 0
      : 0;

    const assignedAgents = selectedTopology
      ? selectedTopology.networks?.reduce((sum, net) =>
          sum + (net.hosts?.reduce((hSum, host) =>
            hSum + (host.agents?.length || 0), 0) || 0), 0) || 0
      : 0;

    return {
      topologies: topologies.length,
      activeHosts,
      assignedAgents,
      runningSessions: 0 // TODO: Fetch from session API
    };
  }, [selectedTopology, topologies]);

  // Get all hosts from selected topology
  const allHosts = useMemo(() => {
    if (!selectedTopology) return [];

    const hosts: Array<{ host: Host; networkId: string; networkName: string }> = [];
    selectedTopology.networks?.forEach(net => {
      net.hosts?.forEach(host => {
        hosts.push({ host, networkId: net.id, networkName: net.name });
      });
    });
    return hosts;
  }, [selectedTopology]);

  // Get agents for selected hosts
  const selectedHostsData = useMemo(() => {
    return allHosts.filter(({ host }) => selectedHosts.has(host.id));
  }, [allHosts, selectedHosts]);

  // Toggle host selection
  const toggleHost = (hostId: string) => {
    const newSelection = new Set(selectedHosts);
    if (newSelection.has(hostId)) {
      newSelection.delete(hostId);
    } else {
      newSelection.add(hostId);
    }
    setSelectedHosts(newSelection);
  };

  // Select all hosts
  const selectAllHosts = () => {
    const allIds = new Set(allHosts.map(({ host }) => host.id));
    setSelectedHosts(allIds);
  };

  // Clear host selection
  const clearHostSelection = () => {
    setSelectedHosts(new Set());
  };

  // Toggle agent selection
  const toggleAgent = (agentType: string) => {
    const newSelection = new Set(selectedAgents);
    if (newSelection.has(agentType)) {
      newSelection.delete(agentType);
    } else {
      newSelection.add(agentType);
    }
    setSelectedAgents(newSelection);
  };

  // Assign agents to selected hosts
  const assignAgents = async () => {
    if (selectedHosts.size === 0 || selectedAgents.size === 0) {
      setAssignmentStatus('Please select hosts and agents');
      return;
    }

    setAssignmentStatus('Assigning agents...');
    try {
      const promises = Array.from(selectedHosts).flatMap(hostId => {
        const hostData = selectedHostsData.find(({ host }) => host.id === hostId);
        if (!hostData) return [];

        return Array.from(selectedAgents).map(agentType =>
          api.assignAgent({
            topology_id: selectedTopology!.id,
            network_id: hostData.networkId,
            host_id: hostId,
            agent_type: agentType as any
          })
        );
      });

      await Promise.all(promises);
      setAssignmentStatus('Agents assigned successfully!');

      // Reload topology to get updated state
      const updated = await api.getTopology(selectedTopology.id);
      setSelectedTopology(updated);

      // Clear selections
      setSelectedHosts(new Set());
      setSelectedAgents(new Set());
    } catch (err: any) {
      setAssignmentStatus(`Error: ${err.message}`);
    }
  };

  // Remove agent from host
  const removeAgent = async (hostId: string, agentType: string, networkId: string) => {
    try {
      await api.removeAgent(selectedTopology!.id, hostId, agentType as any, networkId);
      const updated = await api.getTopology(selectedTopology!.id);
      setSelectedTopology(updated);
    } catch (err: any) {
      setError(err.message);
    }
  };

  // Start topology
  const startTopology = async () => {
    if (!selectedTopology) return;
    setAssignmentStatus('Starting topology...');
    try {
      await api.startTopology(selectedTopology.id);
      setAssignmentStatus('Topology started successfully!');
    } catch (err: any) {
      setAssignmentStatus(`Error: ${err.message}`);
    }
  };

  // Stop topology
  const stopTopology = async () => {
    if (!selectedTopology) return;
    setAssignmentStatus('Stopping topology...');
    try {
      await api.stopTopology(selectedTopology.id);
      setAssignmentStatus('Topology stopped successfully!');
    } catch (err: any) {
      setAssignmentStatus(`Error: ${err.message}`);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <RefreshCw className="animate-spin mx-auto mb-4" size={32} />
          <p className="text-sm text-gray-500 dark:text-gray-400">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center text-red-500">
          <AlertCircle className="mx-auto mb-4" size={32} />
          <p>{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col gap-6 overflow-auto p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Agent Management Dashboard
          </h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Select a topology to manage agents and view execution
          </p>
        </div>
        {selectedTopology && (
          <div className="flex gap-2">
            <button
              onClick={startTopology}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
            >
              <Zap size={16} />
              Start
            </button>
            <button
              onClick={stopTopology}
              className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
            >
              <Clock size={16} />
              Stop
            </button>
            <Link
              to="/agents"
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              <Activity size={16} />
              Agent Execution
            </Link>
          </div>
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <div className="p-4 bg-trident-surface rounded-lg border border-trident-border">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 dark:bg-blue-900 rounded-lg">
              <Network className="text-blue-600 dark:text-blue-400" size={20} />
            </div>
            <div>
              <p className="text-2xl font-bold">{stats.topologies}</p>
              <p className="text-xs text-gray-500 dark:text-gray-400">Topologies</p>
            </div>
          </div>
        </div>
        <div className="p-4 bg-trident-surface rounded-lg border border-trident-border">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-100 dark:bg-green-900 rounded-lg">
              <Server className="text-green-600 dark:text-green-400" size={20} />
            </div>
            <div>
              <p className="text-2xl font-bold">{stats.activeHosts}</p>
              <p className="text-xs text-gray-500 dark:text-gray-400">Active Hosts</p>
            </div>
          </div>
        </div>
        <div className="p-4 bg-trident-surface rounded-lg border border-trident-border">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-100 dark:bg-purple-900 rounded-lg">
              <Users className="text-purple-600 dark:text-purple-400" size={20} />
            </div>
            <div>
              <p className="text-2xl font-bold">{stats.assignedAgents}</p>
              <p className="text-xs text-gray-500 dark:text-gray-400">Assigned Agents</p>
            </div>
          </div>
        </div>
        <div className="p-4 bg-trident-surface rounded-lg border border-trident-border">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-orange-100 dark:bg-orange-900 rounded-lg">
              <Activity className="text-orange-600 dark:text-orange-400" size={20} />
            </div>
            <div>
              <p className="text-2xl font-bold">{stats.runningSessions}</p>
              <p className="text-xs text-gray-500 dark:text-gray-400">Running Sessions</p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6 flex-1 min-h-0">
        {/* Left Panel: Topology Selection */}
        <div className="flex flex-col gap-4 overflow-auto">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Select Topology</h2>
          <div className="flex flex-col gap-2">
            {topologies.map(topo => (
              <button
                key={topo.id}
                onClick={() => setSelectedTopology(topo)}
                className={`p-4 rounded-lg border-2 text-left transition-all ${
                  selectedTopology?.id === topo.id
                    ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                    : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="font-semibold text-gray-900 dark:text-white truncate" title={topo.name}>
                      {topo.name}
                    </h3>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      {topo.networks?.length || 0} networks · {topo.version}
                    </p>
                  </div>
                  {selectedTopology?.id === topo.id && (
                    <CheckCircle className="text-blue-500 dark:text-blue-400" size={20} />
                  )}
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Right Panel: Host Selection & Agent Assignment */}
        {selectedTopology ? (
          <div className="flex flex-col gap-4 overflow-auto">
            {/* Agent Selection */}
            <div>
              <h2 className="text-lg font-semibold mb-3 text-gray-900 dark:text-white">Select Agents</h2>
              <div className="grid grid-cols-2 gap-2">
                {Object.entries(agentTemplates).map(([key, template]) => (
                  <button
                    key={key}
                    onClick={() => toggleAgent(key)}
                    className={`p-3 rounded-lg border text-left transition-all ${
                      selectedAgents.has(key)
                        ? 'border-purple-500 bg-purple-50 dark:bg-purple-900/20'
                        : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-500'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-medium text-sm text-gray-900 dark:text-white truncate" title={template.name}>{template.name}</p>
                        <p className="text-xs text-gray-500 dark:text-gray-400 line-clamp-2" title={template.description}>{template.description}</p>
                      </div>
                      {selectedAgents.has(key) && (
                        <CheckCircle className="text-purple-500 dark:text-purple-400" size={16} />
                      )}
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Host Selection */}
            <div className="flex-1 flex flex-col min-h-0">
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Select Hosts</h2>
                <div className="flex gap-2">
                  <button
                    onClick={selectAllHosts}
                    className="text-xs px-3 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-200 dark:hover:bg-gray-600"
                  >
                    Select All
                  </button>
                  <button
                    onClick={clearHostSelection}
                    className="text-xs px-3 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-200 dark:hover:bg-gray-600"
                  >
                    Clear
                  </button>
                </div>
              </div>

              <div className="flex-1 overflow-auto">
                <div className="space-y-2">
                  {allHosts.map(({ host, networkName }) => (
                    <div
                      key={host.id}
                      className={`p-3 rounded-lg border cursor-pointer transition-all ${
                        selectedHosts.has(host.id)
                        ? 'border-green-500 bg-green-50 dark:bg-green-900/20'
                        : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-500'
                      }`}
                      onClick={() => toggleHost(host.id)}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            {selectedHosts.has(host.id) && (
                              <CheckCircle className="text-green-500 dark:text-green-400" size={16} />
                            )}
                            <p className="font-medium text-sm text-gray-900 dark:text-white truncate" title={host.name}>{host.name}</p>
                            <span className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-700 rounded">
                              {host.type}
                            </span>
                          </div>
                          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1 truncate" title={`${networkName} · ${host.image}`}>
                            {networkName} · {host.image}
                          </p>
                          {host.agents && host.agents.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-2">
                              {host.agents.map(agent => (
                                <span
                                  key={agent}
                                  className="text-xs px-2 py-0.5 bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300 rounded flex items-center gap-1"
                                >
                                  {agent}
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      removeAgent(host.id, agent, networkName);
                                    }}
                                    className="hover:text-red-500 dark:hover:text-red-400"
                                  >
                                    <XCircle size={12} />
                                  </button>
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Action Bar */}
            <div className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
              <div className="text-sm text-gray-500 dark:text-gray-400">
                {selectedHosts.size} hosts · {selectedAgents.size} agents selected
              </div>
              <button
                onClick={assignAgents}
                disabled={selectedHosts.size === 0 || selectedAgents.size === 0}
                className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-300 dark:disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors"
              >
                <Plus size={16} />
                Assign Agents
              </button>
            </div>

            {assignmentStatus && (
              <div className={`text-sm p-3 rounded-lg ${
                assignmentStatus.includes('Error')
                  ? 'bg-red-100 text-red-700 dark:bg-red-900/20 dark:text-red-400'
                  : 'bg-green-100 text-green-700 dark:bg-green-900/20 dark:text-green-400'
              }`}>
                {assignmentStatus}
              </div>
            )}
          </div>
        ) : (
          <div className="flex items-center justify-center">
            <p className="text-gray-500 dark:text-gray-400">Select a topology to manage agents</p>
          </div>
        )}
      </div>
    </div>
  );
}
