-- Park Test · Supabase schema, passphrase edition
-- Paste the whole file into the Supabase SQL Editor and run it once.
--
-- BEFORE YOU RUN: change the passphrase on the marked line below.

-- Supabase keeps pgcrypto in the extensions schema, so put it on the path.
create extension if not exists pgcrypto with schema extensions;
set search_path = public, extensions;

-- ---------------------------------------------------------------- tables

create table if not exists parktest_auth (
  id           int primary key default 1,
  pass_hash    text not null,
  fail_count   int not null default 0,
  locked_until timestamptz,
  constraint parktest_auth_single_row check (id = 1)
);

create table if not exists parktest_config (
  id         int primary key default 1,
  payload    jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  constraint parktest_config_single_row check (id = 1)
);

create table if not exists parktest_sessions (
  id         text primary key,
  date       date not null,
  payload    jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

create index if not exists parktest_sessions_date_idx on parktest_sessions (date desc);

create table if not exists parktest_photos (
  session_id text primary key references parktest_sessions (id) on delete cascade,
  image      text not null,
  created_at timestamptz not null default now()
);

insert into parktest_config (id, payload) values (1, '{}'::jsonb) on conflict (id) do nothing;

-- >>> CHANGE THIS PASSPHRASE <<<
insert into parktest_auth (id, pass_hash)
  values (1, crypt('change-this-passphrase', gen_salt('bf', 10)))
  on conflict (id) do nothing;

-- ---------------------------------------------------------------- lock down

alter table parktest_auth     enable row level security;
alter table parktest_photos   enable row level security;
alter table parktest_config   enable row level security;
alter table parktest_sessions enable row level security;

-- No policies are created and no grants are given, so the anon role cannot read
-- or write these tables through the REST API at all. Everything goes through the
-- security definer functions below, each of which checks the passphrase.
-- Supabase grants anon and authenticated broad table access by default.
-- Take it all back: nothing reaches these tables except via the functions.
revoke all on parktest_auth, parktest_config, parktest_sessions, parktest_photos
  from public, anon, authenticated;
grant usage on schema public to anon;

-- ---------------------------------------------------------------- auth

create or replace function pt_auth(p_pass text)
returns text language plpgsql security definer set search_path = public, extensions as $$
declare
  a parktest_auth%rowtype;
  n int;
begin
  select * into a from parktest_auth where id = 1 for update;
  if a.locked_until is not null and a.locked_until > now() then
    return 'locked';
  end if;
  if a.pass_hash = crypt(p_pass, a.pass_hash) then
    update parktest_auth set fail_count = 0, locked_until = null where id = 1;
    return 'ok';
  end if;
  n := a.fail_count + 1;
  update parktest_auth
     set fail_count   = case when n >= 10 then 0 else n end,
         locked_until = case when n >= 10 then now() + interval '15 minutes' else locked_until end
   where id = 1;
  return case when n >= 10 then 'locked' else 'unauthorized' end;
end $$;

revoke execute on function pt_auth(text) from public;

-- ---------------------------------------------------------------- api

create or replace function pt_load(p_pass text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare st text;
begin
  st := pt_auth(p_pass);
  if st <> 'ok' then return jsonb_build_object('ok', false, 'error', st); end if;
  return jsonb_build_object(
    'ok', true,
    'config', coalesce((select payload from parktest_config where id = 1), '{}'::jsonb),
    'sessions', coalesce((
      select jsonb_agg(jsonb_build_object('id', id, 'date', date) || payload order by date desc)
      from parktest_sessions), '[]'::jsonb)
  );
end $$;

create or replace function pt_save_config(p_pass text, p_payload jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare st text;
begin
  st := pt_auth(p_pass);
  if st <> 'ok' then return jsonb_build_object('ok', false, 'error', st); end if;
  insert into parktest_config (id, payload) values (1, p_payload)
    on conflict (id) do update set payload = excluded.payload, updated_at = now();
  return jsonb_build_object('ok', true);
end $$;

create or replace function pt_save_session(p_pass text, p_id text, p_date date, p_payload jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare st text;
begin
  st := pt_auth(p_pass);
  if st <> 'ok' then return jsonb_build_object('ok', false, 'error', st); end if;
  insert into parktest_sessions (id, date, payload) values (p_id, p_date, p_payload)
    on conflict (id) do update set date = excluded.date, payload = excluded.payload, updated_at = now();
  return jsonb_build_object('ok', true);
end $$;

create or replace function pt_clear_sessions(p_pass text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare st text;
begin
  st := pt_auth(p_pass);
  if st <> 'ok' then return jsonb_build_object('ok', false, 'error', st); end if;
  delete from parktest_sessions;
  return jsonb_build_object('ok', true);
end $$;

create or replace function pt_save_photo(p_pass text, p_session_id text, p_image text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare st text;
begin
  st := pt_auth(p_pass);
  if st <> 'ok' then return jsonb_build_object('ok', false, 'error', st); end if;
  if length(p_image) > 4000000 then
    return jsonb_build_object('ok', false, 'error', 'too large');
  end if;
  insert into parktest_photos (session_id, image) values (p_session_id, p_image)
    on conflict (session_id) do update set image = excluded.image, created_at = now();
  return jsonb_build_object('ok', true);
end $$;

create or replace function pt_get_photo(p_pass text, p_session_id text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare st text;
begin
  st := pt_auth(p_pass);
  if st <> 'ok' then return jsonb_build_object('ok', false, 'error', st); end if;
  return jsonb_build_object(
    'ok', true,
    'image', (select image from parktest_photos where session_id = p_session_id)
  );
end $$;

create or replace function pt_set_pass(p_pass text, p_new text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare st text;
begin
  st := pt_auth(p_pass);
  if st <> 'ok' then return jsonb_build_object('ok', false, 'error', st); end if;
  if length(p_new) < 12 then
    return jsonb_build_object('ok', false, 'error', 'too short');
  end if;
  update parktest_auth set pass_hash = crypt(p_new, gen_salt('bf', 10)), fail_count = 0, locked_until = null
   where id = 1;
  return jsonb_build_object('ok', true);
end $$;

-- Free Supabase projects pause after seven days of inactivity. This does nothing
-- except give the weekly keep-alive something harmless to call.
create or replace function pt_ping()
returns jsonb language sql security definer set search_path = public as $$
  select jsonb_build_object('ok', true);
$$;

grant execute on function
  pt_load(text),
  pt_save_config(text, jsonb),
  pt_save_session(text, text, date, jsonb),
  pt_clear_sessions(text),
  pt_save_photo(text, text, text),
  pt_get_photo(text, text),
  pt_set_pass(text, text),
  pt_ping()
to anon;
