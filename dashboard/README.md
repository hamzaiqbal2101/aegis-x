# AEGIS X Dashboard (M7)

Vite + React + TypeScript + Tailwind CSS v4 dashboard for the AEGIS X
Management API (M2). It shows only data fetched from the live API, plus
the manually maintained engine statuses in `src/config/engines.ts`. There
are no mock charts, no sample traffic graphs, and no fake threat counts
anywhere in this app.

## Pages

- **Overview** — engine health cards from `src/config/engines.ts`, plus
  live Management API health from `GET /status` (online/offline is
  determined by the fetch, never hardcoded).
- **Policies** — `GET /policies` list (name + id + hash when present),
  click a policy for its raw JSON (`GET /policies/{id}`), and a Validate
  button (`POST /policies/{id}/validate`).
- **Events** — real audit entries from `GET /audit` (timestamp, actor,
  action, policy_id, detail). Empty state: "No events recorded."
- **Zones** — zones derived only from fetched policy data, plus a
  zone-to-zone matrix whose cells honestly read "unknown — matrix
  computation is not yet exposed by the API" (the matcher is Rust-side).

If the API cannot be reached, pages show an explicit "API offline —
start the API (see api/README.md)" banner and no rows. Fetch failures
are never papered over with sample data.

## Install

```sh
npm install
```

## Run (development)

```sh
npm run dev
```

## Build

```sh
npm run build
```

## Environment variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `VITE_API_URL` | `http://127.0.0.1:8000` | Base URL of the Management API |
| `VITE_API_TOKEN` | (unset) | Bearer token baked in at build time, if set |

If `VITE_API_TOKEN` is not set, the dashboard header shows a token
field. A token entered there is stored **only in memory** for the
session — never in localStorage, sessionStorage, or a cookie. Refreshing
the page clears it.

## Honest-status note

Engine statuses in `src/config/engines.ts` are manually maintained, not
measured by this dashboard. The coordinator updates that file as
milestones land. In particular, the IDS / rate limiting / DNS /
threat-intel / behavioral / segmentation engines are currently marked as
in development (built in parallel by another agent) and must not be
marked active until their code is in the repo and tested.
