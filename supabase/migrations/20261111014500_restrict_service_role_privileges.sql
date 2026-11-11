-- Apply least-privilege ACLs explicitly; Supabase may grant service_role broad defaults.
revoke all on table public.centinela_experiments from service_role;
revoke all on table public.centinela_auth_events from service_role;
revoke all on table public.centinela_event_label_history from service_role;

grant select, insert, update on table public.centinela_experiments to service_role;
grant select, insert, update on table public.centinela_auth_events to service_role;
grant select, insert on table public.centinela_event_label_history to service_role;
