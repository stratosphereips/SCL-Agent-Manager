# Agent Manager Frontend

React + TypeScript + Vite frontend for the Agent Manager plugin.

## Pages

- **`/agents`** — Lists agents from currently-running topologies and lets users set goals and view session messages.
- **`/containers`** — Host discovery page: browse topology containers, view configured agents, and assign/remove agents.
- **`/topology`** — Lists available topologies and provides start/stop controls.

## Tech Stack

- React 18
- TypeScript
- Vite
- Tailwind CSS
- Lucide React icons

## Development

```bash
npm ci
npm run dev
```

The dev server runs on `http://localhost:5173` by default.

## Build

```bash
npm run build
```

The production build is output to `dist/` and served by the Python backend.

## Key Behaviors

- The **Agents** page polls `/api/agents/assignments` and `/api/containers/discover?state=running` every 10 seconds.
- It renders only assignments whose `topology_id` has a running container, preventing stale agents from stopped topologies from appearing.
- Assignment IDs are deterministic (`{topology_id}-{network_id}-{host_id}-{agent_type}`), so React does not remount agent cards while the user is typing a goal.
- `SessionStream` polls session messages every 3 seconds.

## Project Structure

```
src/
├── api.ts              # API client wrappers
├── api-trident.ts      # Trident-compatible endpoints
├── types.ts            # Shared TypeScript interfaces
├── components/
│   └── SessionStream.tsx
└── pages/
    ├── AgentsPage.tsx
    ├── HostDiscoveryPage.tsx
    ├── TopologyPage.tsx
    └── DashboardPage.tsx
```
