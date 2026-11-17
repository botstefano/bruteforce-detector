-- Centinela auth features v3.
-- The online detector no longer uses absolute UTC hour. Historical v2 rows remain
-- valid with five dimensions; new v3 rows contain four dimensions.
do $$
declare
  constraint_row record;
begin
  for constraint_row in
    select conname
    from pg_constraint
    where conrelid = 'public.centinela_auth_events'::regclass
      and contype = 'c'
      and pg_get_constraintdef(oid) ilike '%cardinality(features)%'
  loop
    execute format(
      'alter table public.centinela_auth_events drop constraint %I',
      constraint_row.conname
    );
  end loop;
end;
$$;

alter table public.centinela_auth_events
  add constraint centinela_auth_events_features_v2_v3_check
  check (cardinality(features) in (4, 5));

alter table public.centinela_auth_events
  alter column feature_schema_version set default 'centinela-auth-features-v3';

comment on column public.centinela_auth_events.feature_schema_version is
  'v2: five features including absolute UTC hour; v3: four behavioral features without hour-of-day.';
