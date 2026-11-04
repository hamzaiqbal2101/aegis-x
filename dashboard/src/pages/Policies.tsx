import { useEffect, useState } from 'react';
import {
  fetchPolicies,
  fetchPolicy,
  isOffline,
  validatePolicy,
  type Policy,
} from '../lib/api';
import OfflineBanner from '../components/OfflineBanner';

export default function Policies() {
  const [state, setState] = useState<
    | { kind: 'loading' }
    | { kind: 'offline'; message: string }
    | { kind: 'error'; message: string }
    | { kind: 'ready'; policies: Policy[] }
  >({ kind: 'loading' });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<unknown | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [validation, setValidation] = useState<unknown | null>(null);
  const [validating, setValidating] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetchPolicies()
      .then((policies) => {
        if (!cancelled) setState({ kind: 'ready', policies });
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

  async function openPolicy(id: string) {
    setSelectedId(id);
    setDetail(null);
    setDetailError(null);
    setValidation(null);
    try {
      setDetail(await fetchPolicy(id));
    } catch (err) {
      setDetailError(
        err instanceof Error ? err.message : 'Failed to load policy',
      );
    }
  }

  async function onValidate(id: string) {
    setValidating(true);
    setValidation(null);
    try {
      setValidation(await validatePolicy(id));
    } catch (err) {
      setValidation({
        error: err instanceof Error ? err.message : 'Validation failed',
      });
    } finally {
      setValidating(false);
    }
  }

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold">Policies</h2>

      {state.kind === 'loading' && <p className="text-sm">Loading policies…</p>}
      {state.kind === 'offline' && (
        <OfflineBanner detail={state.message} />
      )}
      {state.kind === 'error' && (
        <p role="alert" className="text-sm text-red-800">
          Failed to load policies: {state.message}
        </p>
      )}
      {state.kind === 'ready' && (
        <>
          {state.policies.length === 0 ? (
            <p className="text-sm text-zinc-600">No policies returned by the API.</p>
          ) : (
            <ul className="divide-y divide-zinc-200 rounded-lg border border-zinc-200">
              {state.policies.map((policy) => (
                <li key={policy.id} className="p-3">
                  <button
                    type="button"
                    onClick={() => openPolicy(policy.id)}
                    className="text-left font-medium text-blue-700 underline"
                  >
                    {policy.name ?? policy.id}
                  </button>
                  <p className="text-sm text-zinc-600">id: {policy.id}</p>
                  {policy.hash && (
                    <p className="break-all text-sm text-zinc-600">
                      hash: {policy.hash}
                    </p>
                  )}
                  <button
                    type="button"
                    onClick={() => onValidate(policy.id)}
                    disabled={validating}
                    className="mt-2 rounded border border-zinc-300 px-3 py-1 text-sm disabled:opacity-50"
                  >
                    {validating ? 'Validating…' : 'Validate'}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </>
      )}

      {selectedId && (
        <section className="rounded-lg border border-zinc-200 p-4">
          <h3 className="font-semibold">Policy: {selectedId}</h3>
          {detailError && (
            <p role="alert" className="mt-2 text-sm text-red-800">
              {detailError}
            </p>
          )}
          {detail !== null && (
            <pre className="mt-2 overflow-auto rounded bg-zinc-100 p-3 text-xs">
              {JSON.stringify(detail, null, 2)}
            </pre>
          )}
          {validation !== null && (
            <div className="mt-3">
              <h4 className="font-medium">Validation result</h4>
              <pre className="mt-1 overflow-auto rounded bg-zinc-100 p-3 text-xs">
                {JSON.stringify(validation, null, 2)}
              </pre>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
