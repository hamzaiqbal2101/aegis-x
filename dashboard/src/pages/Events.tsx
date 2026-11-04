import { useEffect, useState } from 'react';
import { fetchAudit, isOffline, type AuditEntry } from '../lib/api';
import OfflineBanner from '../components/OfflineBanner';

export default function Events() {
  const [state, setState] = useState<
    | { kind: 'loading' }
    | { kind: 'offline'; message: string }
    | { kind: 'error'; message: string }
    | { kind: 'ready'; entries: AuditEntry[] }
  >({ kind: 'loading' });

  useEffect(() => {
    let cancelled = false;
    fetchAudit()
      .then((entries) => {
        if (!cancelled) setState({ kind: 'ready', entries });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        if (isOffline(err)) {
          setState({
            kind: 'offline',
            message: err instanceof Error ? err.message : 'API offline',
          });
        } else {
          setState({
            kind: 'error',
            message: err instanceof Error ? err.message : 'Unknown error',
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold">Events</h2>
      <p className="text-sm text-zinc-600">
        Audit entries returned by GET /audit. Nothing here is invented: if
        the API returns nothing, this page says so.
      </p>

      {state.kind === 'loading' && <p className="text-sm">Loading events…</p>}
      {state.kind === 'offline' && <OfflineBanner detail={state.message} />}
      {state.kind === 'error' && (
        <p role="alert" className="text-sm text-red-800">
          Failed to load events: {state.message}
        </p>
      )}
      {state.kind === 'ready' && (
        <>
          {state.entries.length === 0 ? (
            <p className="text-sm text-zinc-600">No events recorded.</p>
          ) : (
            <div className="overflow-auto rounded-lg border border-zinc-200">
              <table className="w-full text-left text-sm">
                <thead className="bg-zinc-100">
                  <tr>
                    <th className="px-3 py-2">Timestamp</th>
                    <th className="px-3 py-2">Actor</th>
                    <th className="px-3 py-2">Action</th>
                    <th className="px-3 py-2">Policy ID</th>
                    <th className="px-3 py-2">Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {state.entries.map((entry, i) => (
                    <tr key={i} className="border-t border-zinc-200">
                      <td className="px-3 py-2">{entry.timestamp ?? '—'}</td>
                      <td className="px-3 py-2">{entry.actor ?? '—'}</td>
                      <td className="px-3 py-2">{entry.action ?? '—'}</td>
                      <td className="px-3 py-2">{entry.policy_id ?? '—'}</td>
                      <td className="px-3 py-2">{entry.detail ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
