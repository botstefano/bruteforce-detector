-- Make one captured HTTP attempt idempotent across portal/runner retries.
-- Existing historical rows leave request_id NULL and remain untouched.
create unique index if not exists idx_centinela_auth_events_request_id_unique
  on public.centinela_auth_events (request_id)
  where request_id is not null;

comment on column public.centinela_auth_events.request_id is
  'Deterministic idempotency key for an automated lab job attempt; null for non-agent events.';
