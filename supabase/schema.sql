-- Esquema de referencia Centinela para Supabase.
-- Aplicar en un proyecto de desarrollo tras revisar el SQL.
-- El backend Node usa SUPABASE_SECRET_KEY (o la clave heredada service-role); nunca incluirla en el cliente.

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
  ground_truth_label text not null default 'unknown'
    check (ground_truth_label in ('unknown', 'benign', 'attack')),
  ground_truth_method text,
  ground_truth_updated_at timestamptz,
  ground_truth_notes text,
  experiment_id uuid references public.centinela_experiments(id) on delete set null,
  scenario text,
  dataset_split text not null default 'unassigned'
    check (dataset_split in ('unassigned', 'train', 'validation', 'test')),
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
  previous_label text not null check (previous_label in ('unknown', 'benign', 'attack')),
  new_label text not null check (new_label in ('unknown', 'benign', 'attack')),
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
create index if not exists idx_centinela_events_split
  on public.centinela_auth_events (experiment_id, dataset_split, occurred_at);
create index if not exists idx_centinela_events_simulated
  on public.centinela_auth_events (is_simulated, occurred_at);
create index if not exists idx_centinela_events_source_ip_hash
  on public.centinela_auth_events (source_ip_hash, occurred_at);
create index if not exists idx_centinela_label_history_event
  on public.centinela_event_label_history (event_id, labeled_at desc);

alter table public.centinela_experiments enable row level security;
alter table public.centinela_auth_events enable row level security;
alter table public.centinela_event_label_history enable row level security;

revoke all on table public.centinela_experiments from anon, authenticated;
revoke all on table public.centinela_auth_events from anon, authenticated;
revoke all on table public.centinela_event_label_history from anon, authenticated;

grant select, insert, update on table public.centinela_experiments to service_role;
grant select, insert, update on table public.centinela_auth_events to service_role;
grant select, insert on table public.centinela_event_label_history to service_role;

grant usage, select on sequence public.centinela_auth_events_id_seq to service_role;
grant usage, select on sequence public.centinela_event_label_history_id_seq to service_role;

-- Etiquetado transaccional: actualiza el evento y registra su historial juntos.
create or replace function public.label_centinela_event(
  p_event_id uuid,
  p_label text,
  p_method text,
  p_rationale text,
  p_labeled_by text default null
)
returns jsonb
language plpgsql
security invoker
set search_path = public
as $function$
declare
  v_previous_label text;
  v_now timestamptz := now();
begin
  if p_label not in ('benign', 'attack') then
    raise exception 'Etiqueta no permitida';
  end if;
  if nullif(trim(p_method), '') is null or nullif(trim(p_rationale), '') is null then
    raise exception 'El método y la justificación son obligatorios';
  end if;

  select ground_truth_label into v_previous_label
  from public.centinela_auth_events
  where event_id = p_event_id and is_simulated = false
  for update;

  if not found then
    raise exception 'Evento capturado no encontrado';
  end if;

  update public.centinela_auth_events
  set ground_truth_label = p_label,
      ground_truth_method = trim(p_method),
      ground_truth_notes = trim(p_rationale),
      ground_truth_updated_at = v_now
  where event_id = p_event_id and is_simulated = false;

  insert into public.centinela_event_label_history (
    event_id, previous_label, new_label, labeling_method, rationale, labeled_by
  ) values (
    p_event_id, v_previous_label, p_label, trim(p_method), trim(p_rationale), nullif(trim(p_labeled_by), '')
  );

  return jsonb_build_object(
    'event_id', p_event_id,
    'previous_label', v_previous_label,
    'label', p_label,
    'labeled_at', v_now
  );
end;
$function$;

revoke all on function public.label_centinela_event(uuid, text, text, text, text) from public, anon, authenticated;
grant execute on function public.label_centinela_event(uuid, text, text, text, text) to service_role;
