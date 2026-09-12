-- Family Expense Tracker - Supabase setup
-- Run this whole script once in Supabase > SQL Editor.

create extension if not exists pgcrypto;

create table if not exists public.households (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.household_members (
  household_id uuid not null references public.households(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in ('owner','member')),
  joined_at timestamptz not null default now(),
  primary key (household_id, user_id)
);

create table if not exists public.invitations (
  id uuid primary key default gen_random_uuid(),
  household_id uuid not null references public.households(id) on delete cascade,
  email text not null,
  token text not null unique,
  role text not null default 'member' check (role in ('owner','member')),
  status text not null default 'pending' check (status in ('pending','accepted','revoked')),
  invited_by uuid not null references auth.users(id) on delete cascade,
  expires_at timestamptz not null default (now() + interval '14 days'),
  created_at timestamptz not null default now()
);

create table if not exists public.expenses (
  id uuid primary key default gen_random_uuid(),
  household_id uuid not null references public.households(id) on delete cascade,
  month text not null check (month ~ '^\\d{4}-\\d{2}$'),
  name text not null,
  category text not null default 'Miscellaneous',
  planned numeric(12,2) not null default 0 check (planned >= 0),
  actual numeric(12,2) not null default 0 check (actual >= 0),
  due_date date,
  completed boolean not null default false,
  recurring boolean not null default false,
  notes text,
  created_by uuid not null references auth.users(id),
  updated_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists expenses_household_month_idx on public.expenses(household_id, month);
create index if not exists invitations_email_idx on public.invitations(lower(email));

create table if not exists public.activity_log (
  id bigint generated always as identity primary key,
  household_id uuid not null references public.households(id) on delete cascade,
  expense_id uuid,
  action text not null,
  expense_name text,
  user_id uuid references auth.users(id),
  created_at timestamptz not null default now()
);

-- Helper functions avoid recursive RLS lookups.
create or replace function public.is_household_member(p_household uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.household_members hm
    where hm.household_id = p_household and hm.user_id = auth.uid()
  );
$$;

create or replace function public.is_household_owner(p_household uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.household_members hm
    where hm.household_id = p_household and hm.user_id = auth.uid() and hm.role='owner'
  );
$$;

create or replace function public.create_household(p_name text)
returns uuid language plpgsql security definer set search_path = public as $$
declare h uuid;
begin
  if auth.uid() is null then raise exception 'Not authenticated'; end if;
  insert into public.households(name, created_by) values (trim(p_name), auth.uid()) returning id into h;
  insert into public.household_members(household_id, user_id, role) values (h, auth.uid(), 'owner');
  return h;
end;
$$;

grant execute on function public.create_household(text) to authenticated;

create or replace function public.accept_invitation(p_token text)
returns uuid language plpgsql security definer set search_path = public as $$
declare inv public.invitations%rowtype;
declare user_email text;
begin
  if auth.uid() is null then raise exception 'Not authenticated'; end if;
  user_email := lower(coalesce(auth.jwt() ->> 'email',''));
  select * into inv from public.invitations
  where token = p_token and status='pending' and expires_at > now()
  limit 1;
  if inv.id is null then raise exception 'Invite is invalid, expired, or already used'; end if;
  if lower(inv.email) <> user_email then raise exception 'Please sign in using the invited email address'; end if;
  insert into public.household_members(household_id, user_id, role)
  values (inv.household_id, auth.uid(), inv.role)
  on conflict (household_id, user_id) do nothing;
  update public.invitations set status='accepted' where id=inv.id;
  return inv.household_id;
end;
$$;

grant execute on function public.accept_invitation(text) to authenticated;

create or replace function public.log_expense_activity()
returns trigger language plpgsql security definer set search_path=public as $$
begin
  if tg_op = 'INSERT' then
    insert into public.activity_log(household_id, expense_id, action, expense_name, user_id)
    values (new.household_id, new.id, 'added', new.name, auth.uid());
    return new;
  elsif tg_op = 'UPDATE' then
    insert into public.activity_log(household_id, expense_id, action, expense_name, user_id)
    values (new.household_id, new.id, case when new.completed is distinct from old.completed then (case when new.completed then 'completed' else 'reopened' end) else 'updated' end, new.name, auth.uid());
    return new;
  elsif tg_op = 'DELETE' then
    insert into public.activity_log(household_id, expense_id, action, expense_name, user_id)
    values (old.household_id, old.id, 'deleted', old.name, auth.uid());
    return old;
  end if;
end;
$$;

drop trigger if exists trg_expense_activity on public.expenses;
create trigger trg_expense_activity after insert or update or delete on public.expenses
for each row execute function public.log_expense_activity();

alter table public.households enable row level security;
alter table public.household_members enable row level security;
alter table public.invitations enable row level security;
alter table public.expenses enable row level security;
alter table public.activity_log enable row level security;

-- households
create policy "members read households" on public.households for select to authenticated
using (public.is_household_member(id));

-- membership
create policy "members read household members" on public.household_members for select to authenticated
using (public.is_household_member(household_id));
create policy "owners remove members" on public.household_members for delete to authenticated
using (public.is_household_owner(household_id) and user_id <> auth.uid());

-- invitations
create policy "owners read invitations" on public.invitations for select to authenticated
using (public.is_household_owner(household_id) or lower(email)=lower(coalesce(auth.jwt()->>'email','')));
create policy "owners create invitations" on public.invitations for insert to authenticated
with check (public.is_household_owner(household_id) and invited_by=auth.uid());
create policy "owners update invitations" on public.invitations for update to authenticated
using (public.is_household_owner(household_id));
create policy "owners delete invitations" on public.invitations for delete to authenticated
using (public.is_household_owner(household_id));

-- expenses
create policy "members read expenses" on public.expenses for select to authenticated
using (public.is_household_member(household_id));
create policy "members add expenses" on public.expenses for insert to authenticated
with check (public.is_household_member(household_id) and created_by=auth.uid() and updated_by=auth.uid());
create policy "members update expenses" on public.expenses for update to authenticated
using (public.is_household_member(household_id))
with check (public.is_household_member(household_id) and updated_by=auth.uid());
create policy "members delete expenses" on public.expenses for delete to authenticated
using (public.is_household_member(household_id));

-- activity
create policy "members read activity" on public.activity_log for select to authenticated
using (public.is_household_member(household_id));

-- Grants
grant usage on schema public to authenticated;
grant select on public.households, public.household_members, public.invitations, public.expenses, public.activity_log to authenticated;
grant insert, update, delete on public.invitations, public.expenses to authenticated;
grant delete on public.household_members to authenticated;
