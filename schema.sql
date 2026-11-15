-- Реестр заявок: схема для Supabase.
-- Выполнить целиком в Supabase: SQL Editor -> New query -> Run.

-- 1. Профили пользователей (роль задаётся только администратором в панели Supabase)
create table if not exists public.profiles (
  id        uuid primary key references auth.users(id) on delete cascade,
  login     text not null unique,
  full_name text not null,
  role      text not null check (role in ('manager', 'executor'))
);

-- 2. Праздники и официальные переносы (нерабочие дни, кроме суббот и воскресений)
create table if not exists public.holidays (
  day  date primary key,
  note text
);

-- 3. Заявки
create table if not exists public.requests (
  id               uuid primary key default gen_random_uuid(),
  owner_id         uuid not null default auth.uid() references public.profiles(id),
  incoming_no      text not null unique,
  received_date    date not null default current_date,
  recommended_date date,   -- считается триггером: +5 рабочих дней
  deadline_date    date,   -- считается триггером: +15 рабочих дней
  req_type         text not null check (req_type in ('pool', 'project')),
  supplier         text not null,
  summary          text not null,
  goods            text,
  status           text not null default 'new'
                   check (status in ('new', 'work', 'info', 'appr', 'done', 'rej')),
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now()
);
create index if not exists requests_owner_idx    on public.requests(owner_id);
create index if not exists requests_received_idx on public.requests(received_date desc);

-- 4. Расчёт рабочих дней (день поступления не считается)
create or replace function public.add_workdays(start_date date, n int)
returns date
language plpgsql stable security definer set search_path = public as $$
declare
  d   date := start_date;
  cnt int  := 0;
begin
  while cnt < n loop
    d := d + 1;
    if extract(isodow from d) < 6
       and not exists (select 1 from public.holidays h where h.day = d) then
      cnt := cnt + 1;
    end if;
  end loop;
  return d;
end $$;

create or replace function public.requests_set_dates()
returns trigger
language plpgsql security definer set search_path = public as $$
begin
  -- сроки всегда пересчитываются, вручную их изменить нельзя
  new.recommended_date := public.add_workdays(new.received_date, 5);
  new.deadline_date    := public.add_workdays(new.received_date, 15);
  new.updated_at       := now();
  return new;
end $$;

drop trigger if exists requests_set_dates on public.requests;
create trigger requests_set_dates
  before insert or update on public.requests
  for each row execute function public.requests_set_dates();

-- 5. Проверка роли
create or replace function public.is_manager()
returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'manager');
$$;

-- 6. Права доступа (Row Level Security)
alter table public.profiles enable row level security;
alter table public.holidays enable row level security;
alter table public.requests enable row level security;

-- profiles: свой профиль; руководитель видит все. Изменять через сайт нельзя.
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_manager());

-- holidays: читать могут все вошедшие, изменять только через SQL Editor
drop policy if exists holidays_select on public.holidays;
create policy holidays_select on public.holidays for select to authenticated using (true);

-- requests: исполнитель видит и меняет только свои; руководитель видит все, но не меняет
drop policy if exists requests_select on public.requests;
create policy requests_select on public.requests for select to authenticated
  using (owner_id = auth.uid() or public.is_manager());

drop policy if exists requests_insert on public.requests;
create policy requests_insert on public.requests for insert to authenticated
  with check (
    owner_id = auth.uid()
    and exists (select 1 from public.profiles p where p.id = auth.uid())
  );

drop policy if exists requests_update on public.requests;
create policy requests_update on public.requests for update to authenticated
  using (owner_id = auth.uid())
  with check (owner_id = auth.uid());

drop policy if exists requests_delete on public.requests;
create policy requests_delete on public.requests for delete to authenticated
  using (owner_id = auth.uid());

-- 7. Праздники. ВАЖНО: сверить с официальным календарём РК и постановлением
-- Правительства о переносе выходных. Даты, выпадающие на субботу или воскресенье,
-- добавлять не нужно (они и так нерабочие), но нужно добавить день переноса.
-- Религиозный праздник (Курбан айт) каждый год в новые даты: добавить вручную.
insert into public.holidays (day, note) values
  ('2026-12-16', 'День Независимости'),
  ('2026-12-17', 'День Независимости'),
  ('2027-01-01', 'Новый год'),
  ('2027-01-02', 'Новый год')
on conflict do nothing;
-- Добавьте переносы и остальные праздники, например:
-- insert into public.holidays (day, note) values ('2027-03-22', 'Наурыз') on conflict do nothing;
