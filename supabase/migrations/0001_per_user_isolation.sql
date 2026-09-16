-- Bible Study — per-user isolation, the first thing that ships.
--
-- Rule (Brooks, 2026-09-16): "it's imperative no journals overlap or any journeys or anything of
-- the sort." Every table that holds a person's data:
--   1. carries user_id, filled by a trigger from the signed-in identity (the client cannot choose it)
--   2. has row level security ON and FORCED
--   3. has exactly one policy: you can see/insert/change/delete a row only if user_id is you
--   4. grants nothing to anon (signed-out visitors), everything row-scoped to authenticated
-- There is no sharing of any kind in this schema. If group sharing is ever wanted, it gets its own
-- table and its own policies; nothing here loosens.
--
-- tests/isolation.test.mjs runs this exact file and proves A cannot read/change/delete B.

-- gen_random_uuid() is built into Postgres 13+ (Supabase runs 15+); no extension needed.

-- ── helpers ───────────────────────────────────────────────────────────────────────────────
create or replace function public.set_owner()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then
    raise exception 'not signed in' using errcode = '42501';
  end if;
  new.user_id := auth.uid();            -- always the caller, never what the client sent
  return new;
end $$;

create or replace function public.touch_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end $$;

-- ── tables ────────────────────────────────────────────────────────────────────────────────
create table public.profiles (
  user_id      uuid primary key,
  display_name text not null default '',
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

create table public.settings (
  user_id    uuid primary key,
  data       jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

create table public.plans (                      -- a study plan and its sessions, logs, prep
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null,
  title      text not null default 'Untitled study',
  data       jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.journal (                    -- the journey: dated entries, optional verse
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null,
  entry_date date not null default current_date,
  verse_ref  text not null default '',
  body       text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.umbrellas (                  -- highlight topics with a permanent colour
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null,
  label      text not null,
  color      text not null default '#e8c547',
  created_at timestamptz not null default now()
);

create table public.highlights (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null,
  ref         text not null,                     -- "John 3:16"
  umbrella_id uuid references public.umbrellas(id) on delete set null,
  note        text not null default '',
  created_at  timestamptz not null default now()
);

create table public.questions (                  -- saved questions + their scripture-first study
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null,
  text       text not null,
  study      jsonb,
  status     text not null default 'open',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.chats (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null,
  plan_id    uuid references public.plans(id) on delete cascade,
  messages   jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.ai_usage (                   -- per-person monthly counter the AI proxy enforces
  user_id uuid not null,
  month   text not null,                         -- 'YYYY-MM'
  calls   int  not null default 0,
  primary key (user_id, month)
);

-- ── one policy per table: your rows only, signed-in only ──────────────────────────────────
do $$
declare t text;
begin
  foreach t in array array['profiles','settings','plans','journal','umbrellas','highlights','questions','chats','ai_usage']
  loop
    execute format('alter table public.%I enable row level security', t);
    execute format('alter table public.%I force row level security', t);
    execute format('revoke all on public.%I from anon', t);
    execute format('grant select, insert, update, delete on public.%I to authenticated', t);
    execute format($p$create policy "own rows only" on public.%I
                      for all to authenticated
                      using (user_id = auth.uid())
                      with check (user_id = auth.uid())$p$, t);
    if t <> 'ai_usage' then   -- ai_usage rows are written by the AI proxy (service role) with an explicit user_id
      execute format('create trigger set_owner before insert on public.%I for each row execute function public.set_owner()', t);
    end if;
  end loop;
  foreach t in array array['profiles','settings','plans','journal','questions','chats']
  loop
    execute format('create trigger touch before update on public.%I for each row execute function public.touch_updated_at()', t);
  end loop;
end $$;

-- ai_usage is written by the AI proxy (service role) and only READ by its owner
revoke insert, update, delete on public.ai_usage from authenticated;

-- a highlight may only point at the caller's own umbrella (the FK alone would allow B's id)
create or replace function public.check_umbrella_owner()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.umbrella_id is not null and not exists (
      select 1 from public.umbrellas u where u.id = new.umbrella_id and u.user_id = auth.uid()) then
    raise exception 'umbrella is not yours' using errcode = '42501';
  end if;
  return new;
end $$;
create trigger umbrella_owner before insert or update on public.highlights
  for each row execute function public.check_umbrella_owner();

-- same for a chat's plan
create or replace function public.check_plan_owner()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.plan_id is not null and not exists (
      select 1 from public.plans p where p.id = new.plan_id and p.user_id = auth.uid()) then
    raise exception 'plan is not yours' using errcode = '42501';
  end if;
  return new;
end $$;
create trigger plan_owner before insert or update on public.chats
  for each row execute function public.check_plan_owner();
