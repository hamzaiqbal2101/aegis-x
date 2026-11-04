import { useEffect, useState } from 'react';
import { fetchPolicies, isOffline, type Policy } from '../lib/api';
import OfflineBanner from '../components/OfflineBanner';

export interface Zone {
  name: string;
  members: string[];
}

/**
 * Derive zones ONLY from real policy data fetched from the API.
 * A policy may carry zones as an array of {name|id, members|addresses}
 * objects, or as a name -> members map. Anything else yields no zones —
 * never a guessed default set.
 */
export function deriveZones(policies: Policy[]): Zone[] {
  const zones = new Map<string, Set<string>>();
  for (const policy of policies) {
    const raw = (policy.raw ?? {}) as Record<string, unknown>;
    const candidates: unknown[] = [];
    if (Array.isArray(raw.zones)) candidates.push(...raw.zones);
    if (raw.zones && typeof raw.zones === 'object' && !Array.isArray(raw.zones)) {
      for (const [name, members] of Object.entries(
        raw.zones as Record<string, unknown>,
      )) {
        candidates.push({ name, members });
      }
    }
    for (const candidate of candidates) {
      const obj = (candidate ?? {}) as Record<string, unknown>;
      const name =
        typeof obj.name === 'string'
          ? obj.name
          : typeof obj.id === 'string'
            ? obj.id
            : typeof candidate === 'string'
              ? candidate
              : null;
      if (!name) continue;
      const membersRaw =
        obj.members ?? obj.addresses ?? obj.hosts ?? obj.cidrs ?? [];
      const members: string[] = Array.isArray(membersRaw)
        ? membersRaw.filter((m): m is string => typeof m === 'string')
        : typeof membersRaw === 'string'
          ? [membersRaw]
          : [];
      const set = zones.get(name) ?? new Set<string>();
      for (const m of members) set.add(m);
      zones.set(name, set);
    }
  }
  return [...zones.entries()].map(([name, members]) => ({
    name,
    members: [...members],
  }));
}

export default function Zones() {
  const [state, setState] = useState<
    | { kind: 'loading' }
    | { kind: 'offline'; message: string }
    | { kind: 'error'; message: string }
    | { kind: 'ready'; zones: Zone[]; policyCount: number }
  >({ kind: 'loading' });

  useEffect(() => {
    let cancelled = false;
    fetchPolicies()
      .then((policies) => {
        if (!cancelled) {
          setState({
            kind: 'ready',
            zones: deriveZones(policies),
            policyCount: policies.length,
          });
        }
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
      <h2 className="text-xl font-semibold">Zones</h2>
      <p className="text-sm text-zinc-600">
        Zones are derived only from policy data fetched from the API. No
        zones are assumed.
      </p>

      {state.kind === 'loading' && <p className="text-sm">Loading zones…</p>}
      {state.kind === 'offline' && <OfflineBanner detail={state.message} />}
      {state.kind === 'error' && (
        <p role="alert" className="text-sm text-red-800">
          Failed to load zones: {state.message}
        </p>
      )}
      {state.kind === 'ready' && (
        <>
          {state.policyCount === 0 ? (
            <p className="text-sm text-zinc-600">
              No policies exist, so no zones can be derived.
            </p>
          ) : state.zones.length === 0 ? (
            <p className="text-sm text-zinc-600">
              No zones found in the fetched policy data.
            </p>
          ) : (
            <>
              <ul className="space-y-3">
                {state.zones.map((zone) => (
                  <li
                    key={zone.name}
                    className="rounded-lg border border-zinc-200 p-4"
                  >
                    <h3 className="font-medium">{zone.name}</h3>
                    {zone.members.length === 0 ? (
                      <p className="mt-1 text-sm text-zinc-600">
                        No members listed in policy data.
                      </p>
                    ) : (
                      <ul className="mt-1 list-disc pl-5 text-sm text-zinc-600">
                        {zone.members.map((member) => (
                          <li key={member}>{member}</li>
                        ))}
                      </ul>
                    )}
                  </li>
                ))}
              </ul>

              <section>
                <h3 className="font-semibold">Zone-to-zone matrix</h3>
                <div className="mt-2 overflow-auto rounded-lg border border-zinc-200">
                  <table className="w-full text-left text-sm">
                    <thead className="bg-zinc-100">
                      <tr>
                        <th className="px-3 py-2">From \ To</th>
                        {state.zones.map((zone) => (
                          <th key={zone.name} className="px-3 py-2">
                            {zone.name}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {state.zones.map((from) => (
                        <tr key={from.name} className="border-t border-zinc-200">
                          <td className="px-3 py-2 font-medium">{from.name}</td>
                          {state.zones.map((to) => (
                            <td key={to.name} className="px-3 py-2 text-zinc-600">
                              unknown — matrix computation is not yet exposed
                              by the API
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p className="mt-2 text-sm text-zinc-600">
                  Flows cannot be computed in this dashboard: the policy
                  matcher lives Rust-side and the API does not yet expose a
                  matrix endpoint, so no allowed/denied flow is claimed.
                </p>
              </section>
            </>
          )}
        </>
      )}
    </div>
  );
}
