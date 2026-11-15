-- =====================================================================
-- Реестр входящих заявок: миграция v4 — работа без почты
--  * администратор задаёт сотруднику временный пароль прямо на сайте;
--  * при первом входе с временным паролем сайт требует сменить пароль;
--  * функция-«заглушка», чтобы Supabase вообще не отправлял письма
--    (подключается вручную: Authentication → Hooks, см. README).
--
-- Выполнять ПОСЛЕ migration.sql и migration_v3.sql:
-- SQL Editor → New query → вставить весь файл → Run. Можно запускать повторно.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- 1. Флаг «нужно сменить пароль»
alter table public.profiles
  add column if not exists must_change_password boolean not null default false;


-- 2. Администратор задаёт временный пароль
create or replace function public.admin_set_password(target uuid, new_password text)
returns void
language plpgsql volatile security definer set search_path = public as $$
begin
  if not public.is_admin() then
    raise exception 'Доступ только для администратора' using errcode = '42501';
  end if;
  if new_password is null or length(new_password) < 8 then
    raise exception 'Пароль должен быть не короче 8 символов' using errcode = '22023';
  end if;
  if length(new_password) > 72 then
    raise exception 'Пароль слишком длинный (не более 72 символов)' using errcode = '22023';
  end if;

  update auth.users
     set encrypted_password = extensions.crypt(new_password, extensions.gen_salt('bf')),
         email_confirmed_at = coalesce(email_confirmed_at, now()),
         updated_at         = now()
   where id = target;
  if not found then
    raise exception 'Пользователь не найден' using errcode = 'P0002';
  end if;

  -- при входе с временным паролем сайт попросит задать свой
  update public.profiles
     set must_change_password = (target <> auth.uid())
   where id = target;

  -- завершить открытые сеансы сотрудника на других устройствах (если доступно)
  begin
    delete from auth.sessions where user_id = target and target <> auth.uid();
  exception when others then
    null;
  end;
end $$;

revoke all on function public.admin_set_password(uuid, text) from public, anon;
grant execute on function public.admin_set_password(uuid, text) to authenticated;


-- 3. Пользователь сменил пароль — снимаем флаг (только себе)
create or replace function public.clear_must_change_password()
returns void
language sql volatile security definer set search_path = public as $$
  update public.profiles set must_change_password = false where id = auth.uid();
$$;

revoke all on function public.clear_must_change_password() from public, anon;
grant execute on function public.clear_must_change_password() to authenticated;


-- 4. «Заглушка» для писем Supabase: ничего не отправляет.
--    Подключается в панели: Authentication → Hooks → Send Email hook →
--    Postgres → схема public → функция send_email_noop.
create or replace function public.send_email_noop(event jsonb)
returns jsonb
language sql stable as $$
  select '{}'::jsonb
$$;

grant execute on function public.send_email_noop(jsonb) to supabase_auth_admin;
revoke all on function public.send_email_noop(jsonb) from public, anon, authenticated;


-- 5. Проверка
select 'Готово (v4)' as "Миграция",
       (select count(*) from public.profiles where must_change_password) as "Ждут смены пароля";
