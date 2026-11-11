# Centinela — Brute Force Detection and Empirical Capture

Centinela is an Express/TypeScript authentication-event detector with a React dashboard, rule-based protection, anomaly-scoring components, and an auditable event-capture path backed by Supabase.

## Empirical event collection

The empirical capture path is deliberately separate from the historical traffic generators and CICIDS flow demos.

- `POST /registrar_intento` receives authentication outcomes from a trusted application backend. It requires a server-to-server bearer token and a configured Supabase event store.
- `POST /demo/login` records HTTP authentication requests handled by the Centinela demo login. Persistent storage must be configured.
- Captured records are written to `public.centinela_auth_events` before the HTTP response is sent.
- Identifiers are HMAC-pseudonymized before storage. Raw passwords are never stored.
- Captured events are initially labeled `unknown`. A failed password is not automatically considered an attack.
- Simulated UI events are rejected by the empirical event repository and are not exported by the captured-dataset endpoint.
- The detector starts untrained. It can be trained only from benign events that have been captured and explicitly labeled.

The empirical endpoints are:

| Endpoint | Purpose |
| --- | --- |
| `POST /api/experimentos` | Create an experiment and make it the active capture context. |
| `POST /api/experimentos/:experimentId/finalizar` | Finish the active experiment. |
| `POST /api/eventos/:eventId/etiqueta` | Add an independently justified ground-truth label and its audit history. |
| `POST /api/experimentos/entrenar_con_eventos_capturados` | Train from labeled benign event windows in the active experiment (minimum 50). |
| `GET /api/dataset/capturado` | Export captured, non-simulated events as JSON; add `?formato=csv` for CSV. |
| `GET /api/experimentos/metricas_capturadas` | Calculate classification metrics only over captured events with known labels. |
| `GET /health` | Inspect whether the persistent event store is configured. |

All dataset, labeling, experiment, and evaluation endpoints require admin authentication. Use the dashboard login cookie or a server-side `Authorization: Bearer $DASHBOARD_PASSWORD` header.

## Supabase setup

1. Create a Supabase project.
2. Open the SQL Editor and execute the schema in [`supabase/schema.sql`](supabase/schema.sql). It creates the experiment, event, and label-history tables, enables RLS, and grants the server role only the privileges required by the backend.
3. In the Supabase project settings, copy the Project URL and create a server-side Secret API key. The legacy service-role key is accepted for compatibility, but a Secret API key is preferred.
4. Configure the following environment variables on the Centinela server (never in React or any `VITE_*` variable):

| Variable | Description |
| --- | --- |
| `SUPABASE_URL` | Supabase Project URL. |
| `SUPABASE_SECRET_KEY` | Supabase server-side Secret API key. |
| `CENTINELA_HASH_SECRET` | Long random secret used to HMAC-pseudonymize IPs and user identifiers. |
| `CENTINELA_INGEST_TOKEN` | Separate long random token used only by the trusted authentication backend calling `/registrar_intento`. |
| `DASHBOARD_PASSWORD` | Strong admin password. There is no built-in default password. |
| `SECRET_KEY` | Secret used to sign the admin session cookie. |
| `TRUST_PROXY_HOPS` | Number of trusted reverse-proxy hops. Set to `1` only when the deployment has one trusted proxy in front of Express. |
| `CENTINELA_VERSION` | Code release/version recorded with every event. |
| `CENTINELA_CONFIG_VERSION` | Detector configuration version recorded with every event. |

`CENTINELA_EXPERIMENT_ID` is optional. Prefer creating experiments through the API; the active experiment is restored from Supabase after a server restart.

For a Render deployment, set the secret variables in the Render dashboard. `render.yaml` declares them as unsynced secrets and configures one trusted proxy hop for Render.

## Integration from an authentication backend

Call Centinela from the server that actually handles authentication—not from browser JavaScript. The trusted backend must report the end user's IP (after validating it according to its own proxy chain) because Centinela otherwise sees the backend's network address.

Example request:

```bash
curl -X POST "$CENTINELA_URL/registrar_intento" \
  -H "Authorization: Bearer $CENTINELA_INGEST_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "usuario": "pseudonymous-account-001",
    "exitoso": false,
    "ip": "198.51.100.25"
  }'
```

The IP shown above is a documentation-only example address. The actual integration must send the source IP verified by the trusted authentication backend. Do not accept an IP supplied directly by an untrusted browser.

## Recommended experimental procedure

1. Create a new experiment with a defined protocol, scenario, and versioned detector configuration.
2. Capture normal authentication activity from the application under study. Include successful logins and genuine user mistakes.
3. Conduct authorized, controlled attack campaigns against the same testbed. Each request must pass through the actual authentication endpoint and then be observed by Centinela.
4. Preserve the independent campaign manifest: time range, source hosts, target accounts, attack type, request count, and ground-truth rationale. Do not derive labels from Centinela's own alert decisions.
5. Label events using the audited labeling endpoint. Use `benign` only when there is evidence of legitimate activity; use `attack` only when the event is linked to a documented attack campaign. Leave ambiguous activity as `unknown`.
6. Train only with benign events from the training period. Keep attack campaigns and later time periods out of training.
7. Evaluate on a separate, untouched test period or campaign. Report the number of captured, labeled, and excluded unknown events, the class balance, confusion matrices, precision, recall, F1, false-positive rate, and measured latency.
8. Export the captured dataset and archive the experiment metadata, source commit, configuration, and labeling manifest.

Controlled attacks in a testbed are real HTTP authentication requests observed by the application, but they are still experimental activity—not spontaneous attacks from an external production population. Describe the source and environment accurately in a paper. If real user accounts or personal data are involved, obtain the required authorization, minimize collection, pseudonymize identifiers, and define retention.

## Historical components

The historical simulator and CICIDS demonstration routes are not the source of the new empirical dataset. Legacy synthetic/CICIDS model-training routes are disabled in this branch to prevent accidental contamination of the detector baseline. The existing benchmark/demo views should not be cited as empirical results.

## Development

The Docker build uses Node.js 22 to support the current pinned Supabase JavaScript SDK.

```bash
npm install
npm run dev
npm run build
```
