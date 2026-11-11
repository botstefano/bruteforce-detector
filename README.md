# Centinela — Brute Force Detection and Empirical Capture

Centinela is an Express/TypeScript authentication-event detector with a React dashboard, rule-based protection, anomaly-scoring components, and an auditable event-capture path backed by Supabase.

## Empirical event collection

The empirical capture path is separate from the historical traffic generators and CICIDS flow demonstrations.

- `POST /registrar_intento` receives authentication outcomes from a trusted application backend. It requires a server-to-server bearer token and a configured Supabase event store.
- `POST /demo/login` records HTTP authentication requests handled by the Centinela demo login. Persistent storage must be configured.
- Captured records are written to `public.centinela_auth_events` before the HTTP response is sent.
- IP and user identifiers are HMAC-pseudonymized before storage. Raw passwords are never accepted by the capture endpoint or stored.
- The exact five-dimensional feature vector used for each detector decision, its schema version, and measured inference latencies are stored with the event. No feature values are backfilled with random estimates.
- Captured events are initially labeled `unknown`. A failed password is not automatically considered an attack.
- The empirical event repository rejects simulator events. Exports read only events captured through the empirical path.
- The detector starts untrained. It can be trained only from at least 50 benign events captured and explicitly labeled in the active experiment's training period.

## Access control and live event stream

Socket.IO is not a public event feed. Every connection must present the signed, expiring `admin_session` HttpOnly cookie issued after successful dashboard login. The cookie is checked by server middleware, and the socket is disconnected when its session expires. The dashboard no longer trusts a localStorage flag and does not connect before `GET /api/session` succeeds.

Socket.IO accepts same-origin requests by default. If a separately hosted dashboard must connect from another origin, set `ALLOWED_ORIGINS` to a comma-separated list of exact origins (scheme and host, without a wildcard). Keep the dashboard and API on the same origin when possible. CORS origin checks do not replace the required session authentication.

The server-to-server capture token is independent of the dashboard password. Never place `CENTINELA_INGEST_TOKEN`, `SUPABASE_SECRET_KEY`, or `SECRET_KEY` in frontend code.

## Empirical endpoints

| Endpoint | Purpose |
| --- | --- |
| `POST /api/experimentos` | Create an experiment and configure temporal dataset boundaries. |
| `POST /api/experimentos/:experimentId/finalizar` | Finish the active experiment. |
| `POST /api/experimentos/:experimentId/abortar` | Mark an incomplete experiment as aborted, with a required reason. |
| `POST /api/eventos/:eventId/etiqueta` | Add an independently justified ground-truth label and audit history. |
| `POST /api/experimentos/entrenar_con_eventos_capturados` | Train from labeled benign windows in the training split (minimum 50). |
| `GET /api/dataset/capturado` | Export captured, non-simulator events as JSON; add `?formato=csv` for CSV. |
| `GET /api/experimentos/metricas_capturadas` | Calculate classification metrics exclusively on labeled test-split events. |
| `GET /api/experimentos/estado` | Return the active experiment's immutable temporal boundaries and capture state to the authenticated dashboard. |
| `GET /api/session` | Validate the admin session for the dashboard and Socket.IO. |
| `GET /health` | Probe the Supabase table with the server key and report `supabase_ok`, store configuration, ingest-token presence, active experiment, `capture_ready` for the built-in capture path, and `backend_integration_ready` for `/registrar_intento`. `db_ok` reflects the Supabase read probe; `local_store_ok` describes the in-memory dashboard cache. |

Dataset, labeling, experiment, evaluation, and administrative event endpoints require admin authentication. Use the dashboard's HttpOnly session cookie or a trusted server-side `Authorization: Bearer $DASHBOARD_PASSWORD` header.

## Dashboard workflow

After signing into the admin dashboard, open **Captura Empírica** to inspect the live Supabase health probe, create an experiment with preregistered train/validation cutoffs, review captured events, record independently justified labels, freeze the benign-only baseline, finalize or abort the run, and export its CSV. Only the 50 most recent events are shown in the panel; the authenticated export contains the complete selected experiment. The panel does not create simulated traffic or infer ground truth from detector alerts.

## Supabase setup

1. Create a Supabase project.
2. Open the SQL Editor and execute [`supabase/schema.sql`](supabase/schema.sql). It creates the experiment, event, and label-history tables, enables RLS, and grants the backend role only the necessary privileges.
3. In the Supabase project settings, copy the Project URL and create a server-side Secret API key. The legacy service-role key is accepted for compatibility, but a Secret API key is preferred.
4. Configure the following environment variables on the Centinela server (never in React or any `VITE_*` variable):

| Variable | Description |
| --- | --- |
| `SUPABASE_URL` | Supabase Project URL. |
| `SUPABASE_SECRET_KEY` | Supabase server-side Secret API key. |
| `CENTINELA_HASH_SECRET` | Long random secret used to HMAC-pseudonymize IPs and user identifiers. Keep it stable across restarts. |
| `CENTINELA_INGEST_TOKEN` | Separate long random token used only by the trusted authentication backend calling `/registrar_intento`. |
| `DASHBOARD_PASSWORD` | Strong admin password. There is no built-in default password. |
| `SECRET_KEY` | Long random secret used to sign expiring admin session cookies. |
| `TRUST_PROXY_HOPS` | Number of trusted reverse-proxy hops. Set it to the actual count in front of Express; do not guess. |
| `ALLOWED_ORIGINS` | Optional comma-separated allowlist for a separately hosted dashboard. Same-origin is the default; never use `*`. |
| `CENTINELA_DEMO_CREDENTIALS_JSON` | Optional JSON object with demo account credentials. No demo passwords are committed to the repository. |
| `CENTINELA_VERSION` | Code release/version recorded with every event. |
| `CENTINELA_CONFIG_VERSION` | Detector configuration version recorded with every event. |

For Render, set the secret variables in the Render dashboard. `render.yaml` declares them as unsynced secrets and configures one trusted proxy hop for the current single-proxy deployment. Recheck this value if the deployment topology changes.

## Experiment setup and temporal split

Create an experiment before collecting events. The API requires two future ISO-8601 UTC cutoffs, fixed before collection begins:

```http
POST /api/experimentos
Content-Type: application/json

{
  "protocol_name": "centinela-auth-capture-v1",
  "scenario": "controlled-authentication-testbed",
  "train_end_at": "2026-12-01T00:00:00Z",
  "validation_end_at": "2026-12-03T00:00:00Z",
  "description": "Pre-registered capture protocol"
}
```

Each event is assigned by its server-observed timestamp:
- Before `train_end_at`: `train`.
- From `train_end_at` until `validation_end_at`: `validation`.
- At or after `validation_end_at`: `test`.

Training may be started only after `train_end_at` and before `validation_end_at`. It reconstructs a clean baseline using only events labeled `benign` in the training split, with a minimum of 50 windows. This avoids contaminating the benign baseline when a live feature window originally included an attack that was labeled only later. The feature vector seen online for every event is still stored unchanged for audit and evaluation. The trained baseline is frozen in the experiment metadata; another fit requires a new experiment. On restart, the same benign-only baseline is reconstructed deterministically using the recorded Isolation Forest seed. Final classification metrics use only labeled events in the test split. Validation events remain separate. An event with uncertain provenance remains `unknown` and is excluded from classification metrics. Do not move cutoffs after inspecting model results.

## Integration from an authentication backend

Call Centinela from the server that actually handles authentication—not from browser JavaScript. The trusted backend must report the end user's IP after validating its own proxy chain; otherwise Centinela sees the authentication backend's network address.

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

1. Freeze and record the code version, detector configuration, and temporal cutoffs before collection.
2. Capture normal authentication activity from the application under study, including successful logins and genuine user mistakes.
3. Conduct authorized, controlled attack campaigns against the same testbed. Each request must pass through the actual authentication endpoint and then be observed by Centinela.
4. Preserve an independent campaign manifest: time range, source hosts, target accounts, attack type, request count, and ground-truth rationale. Do not derive labels from Centinela's own alert decisions.
5. Label events using the audited labeling endpoint. Use `benign` only when there is evidence of legitimate activity; use `attack` only when the event is linked to a documented attack campaign. Leave ambiguous activity as `unknown`.
6. Train only with benign events from the training split. Use validation data only for predeclared model selection or threshold tuning; freeze the configuration before test.
7. Evaluate once on the separate test period. Report captured, labeled, and excluded event counts, class balance, confusion matrices, precision, recall, F1, false-positive rate, and measured inference latency.
8. Export the captured dataset and archive experiment metadata, source commit, configuration, and labeling manifest.

Controlled attacks in a testbed are real HTTP authentication requests observed by the application, but they are still experimental activity—not spontaneous attacks from an external production population. Describe the source and environment accurately in a paper. If real user accounts or personal data are involved, obtain the required authorization, minimize collection, pseudonymize identifiers, and define retention.

## Historical components

The historical traffic simulator and CICIDS demonstration routes are not the source of the new empirical dataset. Legacy generated/CICIDS model-training routes are disabled in this branch to prevent accidental contamination of the detector baseline. Historical dashboards and reports should not be cited as empirical results.

## Development

The Docker build uses Node.js 22 for the pinned Supabase JavaScript SDK.

```bash
npm install
npm run dev
npm run build
```



After an experiment is finalized, pass its exact `experiment_id` when exporting or requesting metrics; the API refuses to combine multiple experiments implicitly:

```http
GET /api/dataset/capturado?experiment_id=EXPERIMENT_UUID&formato=csv
GET /api/experimentos/metricas_capturadas?experiment_id=EXPERIMENT_UUID
```

## Offline empirical evaluation from Supabase exports

The Node application records the five-dimensional feature vector actually seen by its live detector. For a standards-based comparison, use the separate Python evaluator:

```bash
python -m pip install -r requirements-empirical.txt
python empirical_auth_evaluation.py \
  --input centinela_eventos_capturados.csv \
  --output-dir empirical_results \
  --seed 42 \
  --bootstrap 1000
```

The CSV must be exported from the authenticated endpoint:

```http
GET /api/dataset/capturado?formato=csv
```

The evaluator refuses rows marked as simulated, unassigned temporal splits, and feature schemas other than `centinela-auth-features-v2`. It requires at least 50 labeled-benign training events plus labeled benign and attack observations in both validation and test.

Training vectors are reconstructed from confirmed benign training events only, to avoid contaminating the normal baseline with earlier malicious events that may have been recognized and labeled later. Validation and test use the exact feature vectors stored when the live Node detector processed each event.

The evaluator fits actual scikit-learn Isolation Forest, One-Class SVM (RBF), and Local Outlier Factor (novelty mode). It calibrates each threshold on validation and reports final metrics only on the untouched test split. It also reports the decisions and measured inference latencies emitted by the running Node service separately from offline scikit-learn model results. Results include input/script hashes, environment versions, prediction CSV, and a manifest. Cluster bootstrap uses `campaign_id` when supplied by the trusted authentication backend and falls back to the pseudonymized source IP.

The legacy TypeScript components with labels `one_class_svm` and `lof` are approximate distance-based implementations, not canonical One-Class SVM and LOF. Do not cite their Node outputs as standard implementations of those algorithms. Use the separate scikit-learn results for canonical algorithm comparisons, and describe Node outputs as the behavior of the deployed application.

For valid research claims, describe controlled attack campaigns as experimental testbed traffic, not as unsolicited attacks from public production networks. Keep the campaign manifest, authorization, time boundaries, labels, exclusions, software commit, and configuration with the exported artifacts.


If a Supabase write fails after the detector has processed a request, Centinela pauses further capture to avoid generating feature windows with a missing event. Check server logs and `/health`. If the gap cannot be reconciled, abort the incomplete experiment with a written reason, then create a new experiment after repairing storage. Do not report the incomplete run as a completed evaluation.
