-- =====================================================================
-- Реестр входящих заявок: миграция до версии 2
-- (саморегистрация @ot.kz, роли pending/executor/manager/admin,
--  администрирование, праздники РК 2026–2027).
--
-- Как выполнить: Supabase → SQL Editor → New query → вставить ВЕСЬ файл → Run.
-- Файл можно запускать повторно: он ничего не удаляет из заявок и профилей.
-- Ключ service_role и пароль базы для него НЕ нужны.
-- =====================================================================


-- ---------------------------------------------------------------------
-- 0. НАСТРОЙКА: разрешённый домен почты для регистрации.
--    Чтобы сменить домен, поменяйте 'ot.kz' здесь и выполните файл снова.
-- ---------------------------------------------------------------------
create or replace function public.allowed_email_domain()
returns text
language sql immutable as $$
  select 'ot.kz'::text
$$;


-- ---------------------------------------------------------------------
-- 1. Таблицы (создаются, только если их ещё нет)
-- ---------------------------------------------------------------------
create table if not exists public.profiles (
  id        uuid primary key references auth.users(id) on delete cascade,
  login     text not null unique,
  full_name text not null,
  role      text not null default 'pending'
);

create table if not exists public.holidays (
  day  date primary key,
  note text
);

create table if not exists public.requests (
  id               uuid primary key default gen_random_uuid(),
  owner_id         uuid not null default auth.uid() references public.profiles(id),
  incoming_no      text not null unique,
  received_date    date not null default current_date,
  recommended_date date,
  deadline_date    date,
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


-- ---------------------------------------------------------------------
-- 2. Роли: расширяем проверку profiles.role (данные не теряются)
-- ---------------------------------------------------------------------
do $$
declare c record;
begin
  -- убираем старые ограничения на поле role (например, только manager/executor)
  for c in
    select con.conname
    from pg_constraint con
    where con.conrelid = 'public.profiles'::regclass
      and con.contype = 'c'
      and pg_get_constraintdef(con.oid) ilike '%role%'
  loop
    execute format('alter table public.profiles drop constraint %I', c.conname);
  end loop;
end $$;

alter table public.profiles
  add constraint profiles_role_check
  check (role in ('pending', 'executor', 'manager', 'admin'));

alter table public.profiles alter column role set default 'pending';


-- ---------------------------------------------------------------------
-- 3. Вспомогательные функции ролей
-- ---------------------------------------------------------------------
create or replace function public.my_role()
returns text
language sql stable security definer set search_path = public as $$
  select role from public.profiles where id = auth.uid()
$$;

create or replace function public.is_admin()
returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() = 'admin', false)
$$;

-- true для руководителя и администратора
create or replace function public.is_manager()
returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('manager', 'admin'), false)
$$;

-- одобренный пользователь (может работать с заявками)
create or replace function public.is_approved()
returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('executor', 'manager', 'admin'), false)
$$;


-- ---------------------------------------------------------------------
-- 4. Регистрация: только домен @ot.kz, новый профиль с ролью pending
-- ---------------------------------------------------------------------
create or replace function public.auth_check_email_domain()
returns trigger
language plpgsql security definer set search_path = public as $$
declare
  dom text := lower(public.allowed_email_domain());
begin
  if new.email is null
     or split_part(lower(new.email), '@', 2) <> dom then
    raise exception 'Регистрация разрешена только для адресов @%', dom
      using errcode = 'check_violation';
  end if;
  return new;
end $$;

drop trigger if exists auth_check_email_domain on auth.users;
create trigger auth_check_email_domain
  before insert on auth.users
  for each row execute function public.auth_check_email_domain();

create or replace function public.auth_create_profile()
returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, login, full_name, role)
  values (
    new.id,
    lower(new.email),
    coalesce(nullif(trim(new.raw_user_meta_data->>'full_name'), ''), lower(new.email)),
    'pending'
  )
  on conflict do nothing;
  return new;
end $$;

drop trigger if exists auth_create_profile on auth.users;
create trigger auth_create_profile
  after insert on auth.users
  for each row execute function public.auth_create_profile();


-- ---------------------------------------------------------------------
-- 5. Администратор: a.yussupov@ot.kz
--    (профиль создаётся, если его нет; если есть, роль меняется на admin)
-- ---------------------------------------------------------------------
insert into public.profiles (id, login, full_name, role)
select u.id,
       lower(u.email),
       coalesce(nullif(trim(u.raw_user_meta_data->>'full_name'), ''), lower(u.email)),
       'admin'
from auth.users u
where lower(u.email) = 'a.yussupov@ot.kz'
on conflict (id) do update set role = 'admin';


-- ---------------------------------------------------------------------
-- 6. Функции администрирования (вызываются с сайта, проверяют is_admin())
-- ---------------------------------------------------------------------
drop function if exists public.admin_list_users();
create function public.admin_list_users()
returns table (id uuid, email text, full_name text, role text, created_at timestamptz)
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_admin() then
    raise exception 'Доступ только для администратора' using errcode = '42501';
  end if;
  return query
    select u.id,
           u.email::text,
           coalesce(p.full_name, u.email::text),
           coalesce(p.role, 'pending'),   -- без профиля = ожидает подтверждения
           u.created_at
    from auth.users u
    left join public.profiles p on p.id = u.id
    order by (coalesce(p.role, 'pending') = 'pending') desc, u.created_at desc;
end $$;

create or replace function public.admin_set_role(target uuid, new_role text)
returns void
language plpgsql volatile security definer set search_path = public as $$
declare
  cur_role text;
  admins   int;
  u_email  text;
  u_name   text;
begin
  if not public.is_admin() then
    raise exception 'Доступ только для администратора' using errcode = '42501';
  end if;
  if new_role is null or new_role not in ('pending', 'executor', 'manager', 'admin') then
    raise exception 'Недопустимая роль: %', coalesce(new_role, 'пусто') using errcode = '22023';
  end if;

  -- блокируем строки администраторов, чтобы два одновременных запроса
  -- не сняли роль у двух последних администраторов
  perform 1 from public.profiles where role = 'admin' for update;

  select role into cur_role from public.profiles where id = target;
  if cur_role = 'admin' and new_role <> 'admin' then
    select count(*) into admins from public.profiles where role = 'admin';
    if admins <= 1 then
      raise exception 'Нельзя снять роль администратора у последнего администратора'
        using errcode = '23514';
    end if;
  end if;

  if cur_role is null then
    -- у пользователя ещё нет профиля: создаём
    select lower(u.email),
           coalesce(nullif(trim(u.raw_user_meta_data->>'full_name'), ''), lower(u.email))
      into u_email, u_name
    from auth.users u where u.id = target;
    if u_email is null then
      raise exception 'Пользователь не найден' using errcode = 'P0002';
    end if;
    insert into public.profiles (id, login, full_name, role)
    values (target, u_email, u_name, new_role);
  else
    update public.profiles set role = new_role where id = target;
  end if;
end $$;

create or replace function public.admin_set_name(target uuid, new_name text)
returns void
language plpgsql volatile security definer set search_path = public as $$
declare
  n text := trim(coalesce(new_name, ''));
begin
  if not public.is_admin() then
    raise exception 'Доступ только для администратора' using errcode = '42501';
  end if;
  if n = '' then
    raise exception 'ФИО не может быть пустым' using errcode = '22023';
  end if;
  if length(n) > 200 then
    raise exception 'ФИО слишком длинное (не более 200 символов)' using errcode = '22023';
  end if;
  update public.profiles set full_name = n where id = target;
  if not found then
    raise exception 'Профиль не найден. Сначала назначьте пользователю роль.' using errcode = 'P0002';
  end if;
end $$;

-- вызывать admin-функции могут только вошедшие (внутри всё равно проверка is_admin)
revoke all on function public.admin_list_users()              from public, anon;
revoke all on function public.admin_set_role(uuid, text)      from public, anon;
revoke all on function public.admin_set_name(uuid, text)      from public, anon;
grant execute on function public.admin_list_users()           to authenticated;
grant execute on function public.admin_set_role(uuid, text)   to authenticated;
grant execute on function public.admin_set_name(uuid, text)   to authenticated;


-- ---------------------------------------------------------------------
-- 7. Расчёт сроков (день поступления не считается; сб, вс и holidays пропускаются)
-- ---------------------------------------------------------------------
create or replace function public.add_workdays(start_date date, n int)
returns date
language plpgsql stable security definer set search_path = public as $$
declare
  d   date := start_date;
  cnt int  := 0;
begin
  if start_date is null or n is null then
    return null;
  end if;
  while cnt < n loop
    d := d + 1;
    if extract(isodow from d) < 6
       and not exists (select 1 from public.holidays h where h.day = d) then
      cnt := cnt + 1;
    end if;
  end loop;
  return d;
end $$;

-- Триггер: сроки всегда считает база; автора и дату создания подменить нельзя.
create or replace function public.requests_set_dates()
returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    if auth.uid() is not null then
      new.owner_id := auth.uid();      -- автор = тот, кто создаёт
    end if;
    new.created_at := now();
  else
    new.owner_id   := old.owner_id;    -- передача заявки другому не предусмотрена
    new.created_at := old.created_at;
  end if;
  new.recommended_date := public.add_workdays(new.received_date, 5);
  new.deadline_date    := public.add_workdays(new.received_date, 15);
  new.updated_at       := now();
  return new;
end $$;

drop trigger if exists requests_set_dates on public.requests;
create trigger requests_set_dates
  before insert or update on public.requests
  for each row execute function public.requests_set_dates();


-- ---------------------------------------------------------------------
-- 8. Права доступа (Row Level Security)
-- ---------------------------------------------------------------------
alter table public.profiles enable row level security;
alter table public.holidays enable row level security;
alter table public.requests enable row level security;

-- profiles: читать свой; руководитель и администратор читают все.
-- Изменения только через триггер регистрации и admin-функции.
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_manager());
drop policy if exists profiles_insert on public.profiles;
drop policy if exists profiles_update on public.profiles;
drop policy if exists profiles_delete on public.profiles;
revoke insert, update, delete on public.profiles from anon, authenticated;

-- holidays: читать всем вошедшим, менять только через SQL Editor
drop policy if exists holidays_select on public.holidays;
create policy holidays_select on public.holidays for select to authenticated using (true);
revoke insert, update, delete on public.holidays from anon, authenticated;

-- requests
drop policy if exists requests_select on public.requests;
create policy requests_select on public.requests for select to authenticated
  using ((owner_id = auth.uid() and public.is_approved()) or public.is_manager());

drop policy if exists requests_insert on public.requests;
create policy requests_insert on public.requests for insert to authenticated
  with check (owner_id = auth.uid() and public.is_approved());

drop policy if exists requests_update on public.requests;
create policy requests_update on public.requests for update to authenticated
  using      (owner_id = auth.uid() and public.is_approved())
  with check (owner_id = auth.uid() and public.is_approved());

drop policy if exists requests_delete on public.requests;
create policy requests_delete on public.requests for delete to authenticated
  using (owner_id = auth.uid() and public.is_approved());

revoke all on public.requests from anon;


-- ---------------------------------------------------------------------
-- 9. Праздники и переносы выходных РК (только будние нерабочие дни)
--
-- Источники:
--  * Закон РК от 13.12.2001 № 267 «О праздниках в Республике Казахстан»
--    (ред. Закона от 11.06.2026 № 306-VIII, действует с 01.07.2026):
--    https://adilet.zan.kz/rus/docs/Z010000267_
--    ст. 3: 1–2 янв, 8 мар, 15 мар (День Конституции, с 01.07.2026; 30 августа
--    больше не праздник), 21–23 мар, 1 мая, 7 мая, 9 мая, 6 июл, 16 дек;
--    ст. 2: 25 окт. ст. 5: при совпадении с выходным выходным становится
--    следующий рабочий день.
--  * Трудовой кодекс РК, ст. 85: 7 января и первый день Курбан айта —
--    выходные дни без переноса.
--  * 2026: gov.kz «Праздничные и выходные дни в РК в 2026 году»
--    https://www.gov.kz/article/33969?lang=ru (обновлено 22.04.2026)
--  * Курбан айт: календарь ДУМК (2026 — 27 мая; 2027 — 16 мая, воскресенье,
--    поэтому будний выходной не добавляется; дата может сдвинуться на день).
--  * 2027: постановление Правительства о переносах на 2027 год на 15.11.2026
--    не найдено; переносы ниже — по ст. 5 Закона. ПРОВЕРЬТЕ после его выхода.
--
-- Субботы и воскресенья не вносятся. Рабочие субботы расчёт не учитывает.
-- ---------------------------------------------------------------------

-- Исправление первой версии: 17 декабря с 2022 года не праздник.
delete from public.holidays where day = date '2026-12-17';

insert into public.holidays (day, note) values
  -- 2026
  ('2026-01-01', 'Новый год'),
  ('2026-01-02', 'Новый год'),
  ('2026-01-07', 'Православное Рождество'),
  ('2026-03-09', 'Перенос с 8 марта (вс)'),
  ('2026-03-23', 'Наурыз мейрамы'),
  ('2026-03-24', 'Перенос с 21 марта (сб), Наурыз'),
  ('2026-03-25', 'Перенос с 22 марта (вс), Наурыз'),
  ('2026-05-01', 'Праздник единства народа Казахстана'),
  ('2026-05-07', 'День защитника Отечества'),
  ('2026-05-11', 'Перенос с 9 мая (сб), День Победы'),
  ('2026-05-27', 'Курбан айт (первый день)'),
  ('2026-07-06', 'День Столицы'),
  ('2026-10-26', 'Перенос с 25 октября (вс), День Республики'),
  ('2026-12-16', 'День Независимости'),
  -- 2027
  ('2027-01-01', 'Новый год'),
  ('2027-01-04', 'Перенос со 2 января (сб), Новый год'),
  ('2027-01-07', 'Православное Рождество'),
  ('2027-03-08', 'Международный женский день'),
  ('2027-03-15', 'День Конституции'),
  ('2027-03-22', 'Наурыз мейрамы'),
  ('2027-03-23', 'Наурыз мейрамы'),
  ('2027-03-24', 'Перенос с 21 марта (вс), Наурыз'),
  ('2027-05-03', 'Перенос с 1 мая (сб), Праздник единства'),
  ('2027-05-07', 'День защитника Отечества'),
  ('2027-05-10', 'Перенос с 9 мая (вс), День Победы'),
  ('2027-07-06', 'День Столицы'),
  ('2027-10-25', 'День Республики'),
  ('2027-12-16', 'День Независимости')
on conflict (day) do update set note = excluded.note;


-- ---------------------------------------------------------------------
-- 10. Пересчитать сроки уже созданных заявок по новому списку праздников
--     (данные заявок не меняются, только сроки)
-- ---------------------------------------------------------------------
update public.requests set received_date = received_date;


-- ---------------------------------------------------------------------
-- 11. Проверка (результат появится внизу SQL Editor)
-- ---------------------------------------------------------------------
select 'Готово' as "Миграция",
       (select count(*) from public.profiles where role = 'admin')   as "Администраторов",
       (select count(*) from public.profiles where role = 'pending') as "Ожидают",
       (select count(*) from public.holidays)                        as "Праздников в таблице",
       public.add_workdays(date '2026-11-16', 5)  as "Пн 16.11.2026 + 5 = 23.11.2026",
       public.add_workdays(date '2026-12-14', 5)  as "Пн 14.12.2026 + 5 (через 16.12) = 22.12.2026";
