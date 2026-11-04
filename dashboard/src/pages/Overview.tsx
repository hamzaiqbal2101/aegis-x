import { useEffect, useState } from 'react';
import {
  API_BASE_URL,
  fetchStatus,
  fetchTelemetry,
  isOffline,
  type TelemetryResult,
} from '../lib/api';
import { ENGINES, type EngineStatus } from '../config/engines';
import OfflineBanner from '../components/OfflineBanner';

const STATUS_STYLES: Record<EngineStatus, string> = {
  active: 'bg-emerald-100 text-emerald-800',
  degraded: 'bg-amber-100 text-amber-800',
  unsupported: 'bg-zinc-200 text-zinc-700',
  unverified: 'bg-orange-100 text-orange-800',
  unknown: 'bg-zinc-100 text-zinc-600',
};

const STATUS_LABELS: Record<EngineStatus, string> = {
  active: 'active',
  degraded: 'degraded',
  unsupported: 'unsupported',
  unverified: 'unverified',
  unknown: 'unknown',
};

export default function Overview() {
  const [apiState, setApiState] = useState<
    | { kind: 'loading' }
    | { kind: 'online'; data: unknown }
    | { kind: 'offline'; message: string }
    | { kind: 'error'; message: string }
  >({ kind: 'loading' });

  const [telemetryState, setTelemetryState] = useState<
    | { kind: 'loading' }
    | { kind: 'available'; data: TelemetryResult & { available: true } }
    | { kind: 'unavailable'; reason: string }
    | { kind: 'offline'; message: string }
    | { kind: 'error'; message: string }
  >({ kind: 'loading' });

  useEffect(() => {
    let cancelled = false;
    fetchStatus()
      .then((data) => {
        if (!cancelled) setApiState({ kind: 'online', data });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        if (isOffline(err)) {
          setApiState({
            kind: 'offline',
            message: err instanceof Error ? err.message : 'API offline',
          });
        } else {
          setApiState({
            kind: 'error',
            message: err instanceof Error ? err.message : 'Unknown error',
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetchTelemetry()
      .then((data) => {
        if (cancelled) return;
        if (data.available) {
          setTelemetryState({ kind: 'available', data });
        } else {
          setTelemetryState({ kind: 'unavailable', reason: data.reason });
        }
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        if (isOffline(err)) {
          setTelemetryState({
            kind: 'offline',
            message: err instanceof Error ? err.message : 'API offline',
          });
        } else {
          setTelemetryState({
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
      <h2 className="text-xl font-semibold">Overview</h2>

      {/* Management API health is LIVE, never hardcoded. */}
      <section
        aria-label="Management API health"
        className="rounded-lg border border-zinc-200 p-4"
      >
        <h3 className="font-semibold">Management API</h3>
        <p className="mt-1 text-sm text-zinc-600">
          Base URL: <code className="bg-zinc-100 px-1 py-0.5 rounded">{API_BASE_URL}</code>
        </p>
        {apiState.kind === 'loading' && (
          <p className="mt-2 text-sm">Checking GET /status…</p>
        )}
        {apiState.kind === 'online' && (
          <div className="mt-2">
            <span className="inline-block rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-semibold text-emerald-800">
              online
            </span>
            <pre className="mt-2 overflow-auto rounded bg-zinc-100 p-3 text-xs">
              {JSON.stringify(apiState.data, null, 2)}
            </pre>
          </div>
        )}
        {apiState.kind === 'offline' && (
          <div className="mt-2">
            <span className="inline-block rounded-full bg-red-100 px-2 py-0.5 text-xs font-semibold text-red-800">
              offline
            </span>
            <div className="mt-2">
              <OfflineBanner detail={apiState.message} />
            </div>
          </div>
        )}
        {apiState.kind === 'error' && (
          <div className="mt-2">
            <span className="inline-block rounded-full bg-red-100 px-2 py-0.5 text-xs font-semibold text-red-800">
              error
            </span>
            <p className="mt-2 text-sm text-red-800">{apiState.message}</p>
          </div>
        )}
      </section>

      {/* Packet counters are LIVE from GET /telemetry/counters (a
        read-only `nft -j list ruleset` parse on the API host). When the
        API cannot read counters it says so explicitly; no numbers are
        ever substituted. NOTE: live rendering against a running API
        stays untested here (no browser click-through available) — this
        wiring is code-complete only. */}
      <section
        aria-label="Packet counters"
        className="rounded-lg border border-zinc-200 p-4"
      >
        <h3 className="font-semibold">Packet counters</h3>
        {telemetryState.kind === 'loading' && (
          <p className="mt-2 text-sm">Checking GET /telemetry/counters…</p>
        )}
        {telemetryState.kind === 'available' &&
          telemetryState.data.counters.length > 0 && (
            <table className="mt-3 w-full text-left text-sm">
              <thead>
                <tr className="text-zinc-600">
                  <th className="py-1 pr-3">Table</th>
                  <th className="py-1 pr-3">Chain</th>
                  <th className="py-1 pr-3">Handle</th>
                  <th className="py-1 pr-3">Name</th>
                  <th className="py-1 pr-3">Packets</th>
                  <th className="py-1">Bytes</th>
                </tr>
              </thead>
              <tbody>
                {telemetryState.data.counters.map((row, i) => (
                  <tr key={i} className="border-t border-zinc-100">
                    <td className="py-1 pr-3">{row.table ?? '—'}</td>
                    <td className="py-1 pr-3">{row.chain ?? '—'}</td>
                    <td className="py-1 pr-3">{row.handle ?? '—'}</td>
                    <td className="py-1 pr-3">{row.name ?? '—'}</td>
                    <td className="py-1 pr-3">{row.packets}</td>
                    <td className="py-1">{row.bytes}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        {telemetryState.kind === 'available' &&
          telemetryState.data.counters.length === 0 && (
            <p className="mt-2 text-sm text-zinc-600">
              Telemetry is available but the ruleset reported no counters.
            </p>
          )}
        {telemetryState.kind === 'unavailable' && (
          <p className="mt-2 text-sm text-amber-800">
            telemetry unavailable: {telemetryState.reason}
          </p>
        )}
        {telemetryState.kind === 'offline' && (
          <div className="mt-2">
            <OfflineBanner detail={telemetryState.message} />
          </div>
        )}
        {telemetryState.kind === 'error' && (
          <p className="mt-2 text-sm text-red-800">{telemetryState.message}</p>
        )}
      </section>

      <section aria-label="Engine health">
        <h3 className="font-semibold">Engines</h3>
        <p className="mt-1 text-sm text-zinc-600">
          Statuses are manually maintained in{' '}
          <code className="bg-zinc-100 px-1 py-0.5 rounded">src/config/engines.ts</code>{' '}
          and claim only what this repo has proven. The packet counters
          above are the only live traffic numbers on this page, fetched
          from the API; no other traffic or threat numbers are shown.
        </p>
        <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {ENGINES.map((engine) => (
            <article
              key={engine.id}
              className="rounded-lg border border-zinc-200 p-4"
            >
              <div className="flex items-center justify-between gap-2">
                <h4 className="font-medium">{engine.name}</h4>
                <span
                  className={`rounded-full px-2 py-0.5 text-xs font-semibold ${STATUS_STYLES[engine.status]}`}
                >
                  {STATUS_LABELS[engine.status]}
                </span>
              </div>
              <p className="mt-2 text-sm text-zinc-600">{engine.note}</p>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}
