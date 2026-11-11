-- Centinela empirical capture: UTC feature schema and campaign linkage.
alter table public.centinela_auth_events
  alter column feature_schema_version set default 'centinela-auth-features-v2';

alter table public.centinela_auth_events
  add column if not exists campaign_id text;

create index if not exists idx_centinela_events_campaign
  on public.centinela_auth_events (experiment_id, campaign_id, occurred_at);
