/**
 * Typed client for the AEGIS X Management API (M2).
 *
 * Contract (see api/README.md when the API lands):
 *   GET  /status                    (no auth)
 *   GET  /policies                  (auth)
 *   GET  /policies/{id}             (auth)
 *   POST /policies/{id}/validate    (auth)
 *   GET  /audit                     (auth)
 * Auth: `Authorization: Bearer <token>`.
 *
 * Base URL: import.meta.env.VITE_API_URL, default http://127.0.0.1:8000.
 * Token: import.meta.env.VITE_API_TOKEN at build time, otherwise set at
 * runtime via setApiToken() from the in-app token field. The token is held
 * ONLY in module memory for the session — it is never written to
 * localStorage, sessionStorage, or any cookie.
 *
 * Offline semantics: any fetch failure (network error, DNS, connection
 * refused, timeout) is surfaced as an ApiOfflineError. Callers must render
 * an explicit "API offline" state and MUST NOT substitute mock data.
 */

export const API_BASE_URL: string =
  import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000';

const BUILD_TIME_TOKEN: string | undefined =
  import.meta.env.VITE_API_TOKEN || undefined;

// In-memory only. Never persisted.
let runtimeToken: string | undefined = undefined;

export function setApiToken(token: string | undefined): void {
  runtimeToken = token?.trim() ? token.trim() : undefined;
}

export function getApiToken(): string | undefined {
  return runtimeToken ?? BUILD_TIME_TOKEN;
}

export function hasBuildTimeToken(): boolean {
  return Boolean(BUILD_TIME_TOKEN);
}

export class ApiOfflineError extends Error {
  constructor(message = 'API offline') {
    super(message);
    this.name = 'ApiOfflineError';
  }
}

export class ApiHttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiHttpError';
    this.status = status;
  }
}

const TIMEOUT_MS = 10_000;

async function request<T>(
  path: string,
  options: { auth: boolean; method?: string },
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (options.auth) {
      const token = getApiToken();
      if (token) headers['Authorization'] = `Bearer ${token}`;
    }
    const res = await fetch(`${API_BASE_URL}${path}`, {
      method: options.method ?? 'GET',
      headers,
      signal: controller.signal,
    });
    if (!res.ok) {
      let detail = res.statusText;
      try {
        const body = await res.text();
        if (body) detail = body.slice(0, 500);
      } catch {
        /* keep statusText */
      }
      throw new ApiHttpError(res.status, `API returned ${res.status}: ${detail}`);
    }
    // Some endpoints may return an empty body.
    const text = await res.text();
    if (!text) return undefined as T;
    return JSON.parse(text) as T;
  } catch (err) {
    if (err instanceof ApiHttpError) throw err;
    // fetch TypeError (network refused / DNS / CORS) and AbortError
    // (timeout) both mean the API could not be reached: offline.
    throw new ApiOfflineError(
      err instanceof Error && err.name === 'AbortError'
        ? `API request to ${path} timed out after ${TIMEOUT_MS}ms`
        : `Could not reach the API at ${API_BASE_URL}${path}`,
    );
  } finally {
    clearTimeout(timer);
  }
}

/** GET /status — no auth. Raw JSON, shape defined by the API. */
export function fetchStatus(): Promise<unknown> {
  return request<unknown>('/status', { auth: false });
}

/** A policy as returned by the API. Only id/name/hash are relied on;
 *  everything else is carried through as `raw` for the detail view. */
export interface Policy {
  id: string;
  name?: string;
  hash?: string;
  raw: unknown;
}

function normalizePolicies(data: unknown): Policy[] {
  const list: unknown[] = Array.isArray(data)
    ? data
    : Array.isArray((data as { policies?: unknown })?.policies)
      ? ((data as { policies: unknown[] }).policies as unknown[])
      : [];
  return list.map((item, i) => {
    const obj = (item ?? {}) as Record<string, unknown>;
    const id =
      typeof obj.id === 'string'
        ? obj.id
        : typeof obj.id === 'number'
          ? String(obj.id)
          : typeof obj.policy_id === 'string'
            ? obj.policy_id
            : typeof obj.policy_id === 'number'
              ? String(obj.policy_id)
              : `policy-${i}`;
    return {
      id,
      name: typeof obj.name === 'string' ? obj.name : undefined,
      hash:
        typeof obj.hash === 'string'
          ? obj.hash
          : typeof obj.sha256 === 'string'
            ? obj.sha256
            : undefined,
      raw: item,
    };
  });
}

/** GET /policies — auth. */
export async function fetchPolicies(): Promise<Policy[]> {
  const data = await request<unknown>('/policies', { auth: true });
  return normalizePolicies(data);
}

/** GET /policies/{id} — auth. Returns the raw policy document. */
export function fetchPolicy(id: string): Promise<unknown> {
  return request<unknown>(`/policies/${encodeURIComponent(id)}`, { auth: true });
}

/** POST /policies/{id}/validate — auth. Returns the raw validation result. */
export function validatePolicy(id: string): Promise<unknown> {
  return request<unknown>(`/policies/${encodeURIComponent(id)}/validate`, {
    auth: true,
    method: 'POST',
  });
}

/** One audit entry. Only fields the API actually returns are shown;
 *  missing fields render as "—", never invented. */
export interface AuditEntry {
  timestamp?: string;
  actor?: string;
  action?: string;
  policy_id?: string;
  detail?: string;
  raw: unknown;
}

function normalizeAudit(data: unknown): AuditEntry[] {
  const list: unknown[] = Array.isArray(data)
    ? data
    : Array.isArray((data as { entries?: unknown })?.entries)
      ? ((data as { entries: unknown[] }).entries as unknown[])
      : Array.isArray((data as { events?: unknown })?.events)
        ? ((data as { events: unknown[] }).events as unknown[])
        : Array.isArray((data as { audit?: unknown })?.audit)
          ? ((data as { audit: unknown[] }).audit as unknown[])
          : [];
  return list.map((item) => {
    const obj = (item ?? {}) as Record<string, unknown>;
    const str = (v: unknown): string | undefined =>
      typeof v === 'string' ? v : undefined;
    return {
      timestamp: str(obj.timestamp) ?? str(obj.time) ?? str(obj.created_at),
      actor: str(obj.actor) ?? str(obj.user),
      action: str(obj.action),
      policy_id:
        str(obj.policy_id) ??
        str(obj.policyId) ??
        (typeof obj.policy_id === 'number'
          ? String(obj.policy_id)
          : undefined),
      detail:
        str(obj.detail) ??
        str(obj.message) ??
        (obj.detail !== undefined
          ? JSON.stringify(obj.detail)
          : undefined),
      raw: item,
    };
  });
}

/** GET /audit — auth. */
export async function fetchAudit(): Promise<AuditEntry[]> {
  const data = await request<unknown>('/audit', { auth: true });
  return normalizeAudit(data);
}

/**
 * One nft counter row, exactly as reported by the API's read-only
 * `nft -j list ruleset` parse. No value here is invented: when the API
 * cannot read counters it returns { available: false, reason } instead.
 */
export interface TelemetryCounter {
  table?: string | null;
  chain?: string | null;
  handle?: number | null;
  name?: string | null;
  packets: number;
  bytes: number;
}

export type TelemetryResult =
  | { available: true; counters: TelemetryCounter[] }
  | { available: false; reason: string };

/** GET /telemetry/counters — auth. */
export async function fetchTelemetry(): Promise<TelemetryResult> {
  const data = await request<unknown>('/telemetry/counters', { auth: true });
  const obj = (data ?? {}) as Record<string, unknown>;
  if (obj.available === false) {
    return {
      available: false,
      reason:
        typeof obj.reason === 'string' && obj.reason
          ? obj.reason
          : 'unknown reason',
    };
  }
  if (obj.available === true && Array.isArray(obj.counters)) {
    const counters: TelemetryCounter[] = [];
    for (const item of obj.counters as unknown[]) {
      const row = (item ?? {}) as Record<string, unknown>;
      // Drop malformed rows rather than inventing numbers for them.
      if (typeof row.packets !== 'number' || typeof row.bytes !== 'number') {
        continue;
      }
      counters.push({
        table: typeof row.table === 'string' ? row.table : null,
        chain: typeof row.chain === 'string' ? row.chain : null,
        handle: typeof row.handle === 'number' ? row.handle : null,
        name: typeof row.name === 'string' ? row.name : null,
        packets: row.packets,
        bytes: row.bytes,
      });
    }
    return { available: true, counters };
  }
  throw new Error('Unexpected telemetry response from the API');
}

export function isOffline(err: unknown): boolean {
  return err instanceof ApiOfflineError;
}
