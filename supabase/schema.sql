-- Angel Supermarket store audit: database schema, roles and security rules.
-- Run once in the Supabase SQL editor. Safe to run again (it skips what already exists).
-- People, emails and the store manager PIN are added separately (see seed section in the
-- setup file shared privately), so no personal details are stored in this repository.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------- tables
create table if not exists public.members (
  email text primary key check (email = lower(email)),
  role text not null check (role in ('super','hr')),
  name text,
  added_at timestamptz not null default now()
);

-- The visit being worked on ("draft") and the week ahead ("next").
-- Public part: what the store manager and the public link can see.
create table if not exists public.drafts (
  slot text primary key check (slot in ('draft','next')),
  data jsonb not null default '{}'::jsonb,
  updated_at bigint not null default 0,
  updated_by text
);
-- Private part: sales, profit, purchases, KPI figures and the Operations tab.
create table if not exists public.drafts_private (
  slot text primary key check (slot in ('draft','next')),
  data jsonb not null default '{}'::jsonb,
  updated_at bigint not null default 0,
  updated_by text
);

-- Approved weeks.
create table if not exists public.weeks (
  id text primary key,                 -- visit date, YYYY-MM-DD
  saved_at bigint not null default 0,
  approved boolean not null default false,
  approved_at bigint,
  approved_by text,
  sum jsonb,                           -- summary without sales figures
  data jsonb                           -- visit without sales figures
);
create table if not exists public.weeks_private (
  id text primary key references public.weeks(id) on delete cascade,
  sum jsonb,
  data jsonb
);

create table if not exists public.config (
  id int primary key default 1 check (id = 1),
  data jsonb not null default '{}'::jsonb,
  updated_at bigint not null default 0
);
create table if not exists public.config_private (
  id int primary key default 1 check (id = 1),
  data jsonb not null default '{}'::jsonb,
  updated_at bigint not null default 0
);

-- Store manager PIN (only ever read by the functions below).
create table if not exists public.sm_settings (
  id int primary key default 1 check (id = 1),
  pin_hash text,
  fail_count int not null default 0,
  locked_until timestamptz
);
create table if not exists public.sm_sessions (
  uid uuid primary key,
  expires_at timestamptz not null
);

create table if not exists public.audit_log (
  id bigserial primary key,
  at timestamptz not null default now(),
  actor text not null,
  role text,
  action text not null,
  details jsonb,
  visit text
);
create index if not exists audit_log_at on public.audit_log (at desc);

-- ---------------------------------------------------------------- who is this?
create or replace function public.my_email() returns text
language sql stable as $$ select lower(coalesce(auth.jwt() ->> 'email', '')) $$;

create or replace function public.my_role() returns text
language sql stable security definer set search_path = public as $$
  select coalesce(
    (select m.role from members m where m.email = my_email() and my_email() <> ''),
    case when exists (select 1 from sm_sessions s where s.uid = auth.uid() and s.expires_at > now())
         then 'sm' else 'viewer' end)
$$;

create or replace function public.is_super() returns boolean
language sql stable as $$ select public.my_role() = 'super' $$;
create or replace function public.is_member() returns boolean
language sql stable as $$ select public.my_role() in ('super','hr') $$;
create or replace function public.can_edit() returns boolean
language sql stable as $$ select public.my_role() in ('super','hr','sm') $$;

-- Name recorded in the change history. The store manager is always recorded as sravan@kugans.com.
create or replace function public.actor_name() returns text
language sql stable as $$
  select case public.my_role() when 'sm' then 'sravan@kugans.com'
                               when 'viewer' then null
                               else public.my_email() end
$$;

-- Stamp every draft save with who made it.
create or replace function public.stamp_actor() returns trigger
language plpgsql as $$ begin new.updated_by := public.actor_name(); return new; end $$;
drop trigger if exists drafts_stamp on public.drafts;
create trigger drafts_stamp before insert or update on public.drafts for each row execute function public.stamp_actor();
drop trigger if exists drafts_private_stamp on public.drafts_private;
create trigger drafts_private_stamp before insert or update on public.drafts_private for each row execute function public.stamp_actor();

-- Only the super admin's approval can mark a week approved; record who did it.
create or replace function public.stamp_week() returns trigger
language plpgsql as $$ begin
  if new.approved then new.approved_by := public.actor_name(); end if; return new; end $$;
drop trigger if exists weeks_stamp on public.weeks;
create trigger weeks_stamp before insert or update on public.weeks for each row execute function public.stamp_week();

-- ---------------------------------------------------------------- functions the page calls
create or replace function public.whoami() returns json
language sql stable security definer set search_path = public as $$
  select json_build_object('role', my_role(), 'email', my_email(), 'actor', actor_name(),
    'name', (select name from members where email = my_email()))
$$;

create or replace function public.log_event(p_action text, p_details jsonb default null, p_visit text default null)
returns void language plpgsql security definer set search_path = public as $$
declare a text := actor_name();
begin
  if a is null then raise exception 'not allowed'; end if;
  insert into audit_log(actor, role, action, details, visit) values (a, my_role(), left(p_action, 500), p_details, p_visit);
end $$;

create or replace function public.sm_unlock(p_pin text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare s sm_settings;
begin
  if auth.uid() is null then return json_build_object('ok', false, 'error', 'no_session'); end if;
  select * into s from sm_settings where id = 1 for update;
  if s.pin_hash is null then return json_build_object('ok', false, 'error', 'no_pin'); end if;
  if s.locked_until is not null and s.locked_until > now() then
    return json_build_object('ok', false, 'error', 'locked', 'until', s.locked_until);
  end if;
  if s.pin_hash = crypt(coalesce(p_pin, ''), s.pin_hash) then
    update sm_settings set fail_count = 0, locked_until = null where id = 1;
    insert into sm_sessions(uid, expires_at) values (auth.uid(), now() + interval '12 hours')
      on conflict (uid) do update set expires_at = excluded.expires_at;
    insert into audit_log(actor, role, action) values ('sravan@kugans.com', 'sm', 'Opened store manager mode');
    return json_build_object('ok', true);
  end if;
  update sm_settings
     set fail_count = case when fail_count + 1 >= 5 then 0 else fail_count + 1 end,
         locked_until = case when fail_count + 1 >= 5 then now() + interval '15 minutes' else null end
   where id = 1;
  insert into audit_log(actor, role, action) values ('unknown', 'viewer', 'Wrong store manager PIN entered');
  return json_build_object('ok', false, 'error', 'wrong_pin');
end $$;

create or replace function public.sm_lock() returns void
language sql security definer set search_path = public as $$ delete from sm_sessions where uid = auth.uid() $$;

create or replace function public.set_sm_pin(p_pin text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not is_super() then raise exception 'only a super admin can change the PIN'; end if;
  if p_pin !~ '^[0-9]{3,8}$' then raise exception 'the PIN must be 3 to 8 digits'; end if;
  insert into sm_settings(id, pin_hash) values (1, crypt(p_pin, gen_salt('bf')))
    on conflict (id) do update set pin_hash = excluded.pin_hash, fail_count = 0, locked_until = null;
  delete from sm_sessions;
  insert into audit_log(actor, role, action) values (actor_name(), 'super', 'Changed the store manager PIN');
end $$;

-- ---------------------------------------------------------------- security rules
alter table public.members        enable row level security;
alter table public.drafts         enable row level security;
alter table public.drafts_private enable row level security;
alter table public.weeks          enable row level security;
alter table public.weeks_private  enable row level security;
alter table public.config         enable row level security;
alter table public.config_private enable row level security;
alter table public.sm_settings    enable row level security;
alter table public.sm_sessions    enable row level security;
alter table public.audit_log      enable row level security;

do $$ declare r record; begin
  for r in select policyname, tablename from pg_policies where schemaname = 'public' and tablename in
    ('members','drafts','drafts_private','weeks','weeks_private','config','config_private','audit_log')
  loop execute format('drop policy %I on public.%I', r.policyname, r.tablename); end loop;
end $$;

create policy members_read  on public.members for select using (public.is_member());
create policy members_write on public.members for all using (public.is_super()) with check (public.is_super());

create policy drafts_read   on public.drafts for select using (true);
create policy drafts_insert on public.drafts for insert with check (public.can_edit());
create policy drafts_update on public.drafts for update using (public.can_edit()) with check (public.can_edit());

create policy drafts_private_all on public.drafts_private for all using (public.is_member()) with check (public.is_member());

create policy weeks_read  on public.weeks for select using (true);
create policy weeks_write on public.weeks for all using (public.is_super()) with check (public.is_super());
create policy weeks_private_read  on public.weeks_private for select using (public.is_member());
create policy weeks_private_write on public.weeks_private for all using (public.is_super()) with check (public.is_super());

create policy config_read  on public.config for select using (true);
create policy config_write on public.config for all using (public.is_super()) with check (public.is_super());
create policy config_private_read  on public.config_private for select using (public.is_member());
create policy config_private_write on public.config_private for all using (public.is_super()) with check (public.is_super());

create policy audit_log_read on public.audit_log for select using (public.is_member());
-- sm_settings and sm_sessions have no policies: only the functions above can touch them.

-- ---------------------------------------------------------------- API access
grant usage on schema public to anon, authenticated;
grant select on public.drafts, public.weeks, public.config to anon, authenticated;
grant insert, update on public.drafts to authenticated;
grant select, insert, update, delete on public.drafts_private, public.weeks, public.weeks_private,
  public.config, public.config_private, public.members to authenticated;
grant select on public.audit_log to authenticated;
revoke all on public.sm_settings, public.sm_sessions from anon, authenticated;
grant execute on function public.whoami(), public.log_event(text, jsonb, text), public.sm_unlock(text),
  public.sm_lock(), public.set_sm_pin(text) to anon, authenticated;

-- ---------------------------------------------------------------- photos
insert into storage.buckets (id, name, public) values ('photos', 'photos', true)
  on conflict (id) do update set public = true;
drop policy if exists "audit photos upload" on storage.objects;
create policy "audit photos upload" on storage.objects for insert to authenticated
  with check (bucket_id = 'photos' and public.can_edit());
drop policy if exists "audit photos delete" on storage.objects;
create policy "audit photos delete" on storage.objects for delete to authenticated
  using (bucket_id = 'photos' and public.is_member());
