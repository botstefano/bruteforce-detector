-- Centinela: almacenamiento persistente y trazable de eventos de autenticación.
-- La aplicación debe conectarse desde el backend con SUPABASE_SERVICE_ROLE_KEY.
-- Nunca exponer esa clave en el navegador ni en variables VITE_*.

create extension if not exists pgcrypto;

create table if not exists public.centinela_experiments (
  id uuid primary key default gen_random_uuid(),
  protocol_name text not null,
  scenario text,
  description text,
  status text not null default 'planned'
    check (status in ('planned', 'running', 'completed', 'aborted')),
  started_at timestamptz,
  finished_at timestamptz,
  code_version text,
  detector_config jsonb not null default '{}'::jsonb,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  check (finished_at is null or started_at is null or finished_at >= started_at)
);

create table if not exists public.centinela_auth_events (
  id bigint generated always as identity primary key,
  event_id uuid not null default gen_random_uuid() unique,
  occurred_at timestamptz not null,
  received_at timestamptz not null default now(),
  source_ip_hash text,
  user_key_hash text,
  auth_success boolean not null,
  origin text not null,
  is_simulated boolean not null default false,

  -- Las etiquetas no se deducen del resultado de autenticación.
  -- Todo evento empieza como unknown hasta disponer de evidencia independiente.
  ground_truth_label text not null default 'unknown'
    check (ground_truth_label in ('unknown', 'benign', 'attack')),
  ground_truth_method text,
  ground_truth_updated_at timestamptz,
  ground_truth_notes text,

  experiment_id uuid references public.centinela_experiments(id) on delete set null,
  scenario text,
  request_id uuid,

  alerta_reglas boolean not null default false,
  razon_reglas text,
  alerta_ml boolean not null default false,
  alerta_iforest boolean not null default false,
  alerta_ocsvm boolean not null default false,
  alerta_lof boolean not null default false,
  score_ml double precision,
  latency_rules_ms double precision,
  latency_ml_ms double precision,
  latency_total_ms double precision,

  detector_version text,
  config_version text,
  metadata jsonb not null default '{}'::jsonb,

  check (score_ml is null or (score_ml >= 0 and score_ml <= 1)),
  check (latency_rules_ms is null or latency_rules_ms >= 0),
  check (latency_ml_ms is null or latency_ml_ms >= 0),
  check (latency_total_ms is null or latency_total_ms >= 0)
);

create table if not exists public.centinela_event_label_history (
  id bigint generated always as identity primary key,
  event_id uuid not null references public.centinela_auth_events(event_id) on delete cascade,
  previous_label text not null
    check (previous_label in ('unknown', 'benign', 'attack')),
  new_label text not null
    check (new_label in ('unknown', 'benign', 'attack')),
  labeling_method text not null,
  rationale text not null,
  labeled_at timestamptz not null default now(),
  labeled_by text,
  provenance jsonb not null default '{}'::jsonb
);

create index if not exists idx_centinela_events_occurred_at
  on public.centinela_auth_events (occurred_at desc);
create index if not exists idx_centinela_events_experiment
  on public.centinela_auth_events (experiment_id, occurred_at);
create index if not exists idx_centinela_events_truth
  on public.centinela_auth_events (ground_truth_label, occurred_at);
create index if not exists idx_centinela_events_simulated
  on public.centinela_auth_events (is_simulated, occurred_at);
create index if not exists idx_centinela_events_source_ip_hash
  on public.centinela_auth_events (source_ip_hash, occurred_at);
create index if not exists idx_centinela_label_history_event
  on public.centinela_event_label_history (event_id, labeled_at desc);

-- El navegador no consulta ni modifica estas tablas directamente.
-- El backend usa la service-role key, guardada exclusivamente en el servidor.
alter table public.centinela_experiments enable row level security;
alter table public.centinela_auth_events enable row level security;
alter table public.centinela_event_label_history enable row level security;

revoke all on table public.centinela_experiments from anon, authenticated;
revoke all on table public.centinela_auth_events from anon, authenticated;
revoke all on table public.centinela_event_label_history from anon, authenticated;

grant all on table public.centinela_experiments to service_role;
grant all on table public.centinela_auth_events to service_role;
grant all on table public.centinela_event_label_history to service_role;

grant usage, select on sequence public.centinela_auth_events_id_seq to service_role;
grant usage, select on sequence public.centinela_event_label_history_id_seq to service_role;
