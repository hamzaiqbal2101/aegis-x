import { useState } from 'react';
import Overview from './pages/Overview';
import Policies from './pages/Policies';
import Events from './pages/Events';
import Zones from './pages/Zones';
import { API_BASE_URL, hasBuildTimeToken, setApiToken } from './lib/api';

type Page = 'overview' | 'policies' | 'events' | 'zones';

const NAV: { id: Page; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'policies', label: 'Policies' },
  { id: 'events', label: 'Events' },
  { id: 'zones', label: 'Zones' },
];

export default function App() {
  const [page, setPage] = useState<Page>('overview');
  // Token held in React state only — never localStorage, never persisted.
  const [tokenInput, setTokenInput] = useState('');
  const [tokenSaved, setTokenSaved] = useState(hasBuildTimeToken());

  function saveToken() {
    setApiToken(tokenInput || undefined);
    setTokenSaved(Boolean(tokenInput.trim()));
  }

  return (
    <div className="min-h-screen bg-white text-zinc-900">
      <header className="border-b border-zinc-200">
        <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-3 px-4 py-4">
          <h1 className="text-xl font-bold">AEGIS X Dashboard</h1>
          <nav className="flex gap-1" aria-label="Dashboard pages">
            {NAV.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => setPage(item.id)}
                aria-current={page === item.id ? 'page' : undefined}
                className={`rounded px-3 py-1.5 text-sm ${
                  page === item.id
                    ? 'bg-zinc-900 text-white'
                    : 'text-zinc-700 hover:bg-zinc-100'
                }`}
              >
                {item.label}
              </button>
            ))}
          </nav>
        </div>
      </header>

      <div className="mx-auto max-w-5xl px-4 py-4">
        <div className="rounded-lg border border-zinc-200 p-4">
          <p className="text-sm text-zinc-600">
            API: <code className="bg-zinc-100 px-1 py-0.5 rounded">{API_BASE_URL}</code>
            {' '}· GET /status needs no auth; all other endpoints send{' '}
            <code className="bg-zinc-100 px-1 py-0.5 rounded">Authorization: Bearer &lt;token&gt;</code>
          </p>
          {hasBuildTimeToken() ? (
            <p className="mt-2 text-sm text-zinc-600">
              A build-time token (VITE_API_TOKEN) is configured; no token
              input is needed.
            </p>
          ) : (
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <label htmlFor="api-token" className="text-sm">
                API token (kept in memory for this session only):
              </label>
              <input
                id="api-token"
                type="password"
                autoComplete="off"
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
                placeholder="Bearer token"
                className="rounded border border-zinc-300 px-2 py-1 text-sm"
              />
              <button
                type="button"
                onClick={saveToken}
                className="rounded border border-zinc-300 px-3 py-1 text-sm"
              >
                Save for this session
              </button>
              {tokenSaved && (
                <span className="text-sm text-emerald-700">
                  Token held in memory only.
                </span>
              )}
            </div>
          )}
        </div>
      </div>

      <main className="mx-auto max-w-5xl px-4 pb-10">
        {page === 'overview' && <Overview />}
        {page === 'policies' && <Policies />}
        {page === 'events' && <Events />}
        {page === 'zones' && <Zones />}
      </main>

      <footer className="mx-auto max-w-5xl px-4 pb-6 text-xs text-zinc-500">
        AEGIS X dashboard (M7). This dashboard shows only data fetched from
        the live Management API plus the manually maintained engine statuses
        in src/config/engines.ts. It contains no mock data, no sample
        traffic, and no invented threat counts.
      </footer>
    </div>
  );
}
