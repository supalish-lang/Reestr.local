-- =====================================================================
-- Реестр входящих заявок: миграция v3
-- Руководитель и администратор:
--   * создают заявки на любого подтверждённого исполнителя (в т.ч. импортом);
--   * переназначают заявки и правят их поля;
--   * статус меняет только исполнитель заявки;
--   * удалить чужую заявку может только администратор.
-- Добавлено поле created_by (кто зарегистрировал заявку).
--
-- Выполнять ПОСЛЕ migration.sql: SQL Editor → New query → вставить весь файл → Run.
-- Можно запускать повторно, данные не удаляются.
-- =====================================================================

-- 1. Кто зарегистрировал заявку
alter table public.requests
  add column if not exists created_by uuid references public.profiles(id) on delete set null;

-- для старых заявок считаем, что их зарегистрировал сам исполнитель
update public.requests set created_by = owner_id where created_by is null;


-- 2. Триггер: сроки, автор, исполнитель, статус
create or replace function public.requests_set_dates()
returns trigger
language plpgsql security definer set search_path = public as $$
declare
  uid uuid    := auth.uid();
  mgr boolean := public.is_manager();
begin
  if tg_op = 'INSERT' then
    new.created_at := now();
    if uid is not null then
      new.created_by := uid;
      -- исполнитель создаёт заявки только на себя;
      -- руководитель/админ — на выбранного исполнителя (по умолчанию на себя)
      if new.owner_id is null or not mgr then
        new.owner_id := uid;
      end if;
    end if;
  else
    new.created_at := old.created_at;
    if uid is not null then
      new.created_by := old.created_by;   -- с сайта автора не подменить
      -- переназначать могут только руководитель и администратор
      if not mgr then
        new.owner_id := old.owner_id;
      end if;
      -- статус меняет только исполнитель заявки
      if new.status is distinct from old.status and uid <> old.owner_id then
        raise exception 'Статус меняет только исполнитель заявки'
          using errcode = '42501';
      end if;
    end if;
  end if;

  -- исполнитель должен быть подтверждённым пользователем
  if tg_op = 'INSERT' or new.owner_id is distinct from old.owner_id then
    if not exists (select 1 from public.profiles p
                   where p.id = new.owner_id
                     and p.role in ('executor', 'manager', 'admin')) then
      raise exception 'Исполнитель не найден или ещё не подтверждён администратором'
        using errcode = '23503';
    end if;
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


-- 3. Права доступа к заявкам
drop policy if exists requests_select on public.requests;
create policy requests_select on public.requests for select to authenticated
  using ((owner_id = auth.uid() and public.is_approved()) or public.is_manager());

drop policy if exists requests_insert on public.requests;
create policy requests_insert on public.requests for insert to authenticated
  with check (public.is_approved() and (owner_id = auth.uid() or public.is_manager()));

drop policy if exists requests_update on public.requests;
create policy requests_update on public.requests for update to authenticated
  using      ((owner_id = auth.uid() and public.is_approved()) or public.is_manager())
  with check ((owner_id = auth.uid() and public.is_approved()) or public.is_manager());

drop policy if exists requests_delete on public.requests;
create policy requests_delete on public.requests for delete to authenticated
  using ((owner_id = auth.uid() and public.is_approved()) or public.is_admin());


-- 4. Проверка
select 'Готово (v3)' as "Миграция",
       (select count(*) from public.requests)                         as "Заявок",
       (select count(*) from public.requests where created_by is null) as "Без автора (должно быть 0)";
