-- Santa Lucia: autenticação Supabase + armazenamento privado por usuário.
-- Execute este arquivo no SQL Editor do seu projeto Supabase.
create table if not exists public.user_app_state (
  user_id uuid primary key references auth.users(id) on delete cascade,
  state jsonb not null default '{"characters":[],"campaigns":[],"rolls":[]}'::jsonb,
  updated_at timestamptz not null default now()
);
alter table public.user_app_state enable row level security;
drop policy if exists "Users can read their own Santa Lucia state" on public.user_app_state;
create policy "Users can read their own Santa Lucia state" on public.user_app_state for select to authenticated using (auth.uid() = user_id);
drop policy if exists "Users can insert their own Santa Lucia state" on public.user_app_state;
create policy "Users can insert their own Santa Lucia state" on public.user_app_state for insert to authenticated with check (auth.uid() = user_id);
drop policy if exists "Users can update their own Santa Lucia state" on public.user_app_state;
create policy "Users can update their own Santa Lucia state" on public.user_app_state for update to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
grant select, insert, update on public.user_app_state to authenticated;

-- Campanhas compartilhadas, membros e perfis públicos (usados ao entrar na conta).
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text
);
create table if not exists public.campaigns (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  place text,
  year text,
  creator_id uuid not null references auth.users(id) on delete cascade default auth.uid(),
  join_code text not null unique,
  created_at timestamptz not null default now()
);
create table if not exists public.campaign_members (
  campaign_id uuid not null references public.campaigns(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'player',
  primary key (campaign_id, user_id)
);
alter table public.profiles enable row level security;
alter table public.campaigns enable row level security;
alter table public.campaign_members enable row level security;

create or replace function public.is_campaign_member(cid uuid) returns boolean
language sql security definer set search_path = public stable as $$
  select exists (select 1 from public.campaign_members where campaign_id = cid and user_id = auth.uid());
$$;

drop policy if exists "Profiles readable by authenticated" on public.profiles;
create policy "Profiles readable by authenticated" on public.profiles for select to authenticated using (true);
drop policy if exists "Users manage own profile" on public.profiles;
create policy "Users manage own profile" on public.profiles for all to authenticated using (auth.uid() = id) with check (auth.uid() = id);

drop policy if exists "Members read campaigns" on public.campaigns;
create policy "Members read campaigns" on public.campaigns for select to authenticated using (creator_id = auth.uid() or public.is_campaign_member(id));
drop policy if exists "Users create campaigns" on public.campaigns;
create policy "Users create campaigns" on public.campaigns for insert to authenticated with check (creator_id = auth.uid());
drop policy if exists "Creator updates campaign" on public.campaigns;
create policy "Creator updates campaign" on public.campaigns for update to authenticated using (creator_id = auth.uid()) with check (creator_id = auth.uid());
drop policy if exists "Creator deletes campaign" on public.campaigns;
create policy "Creator deletes campaign" on public.campaigns for delete to authenticated using (creator_id = auth.uid());

drop policy if exists "Members read memberships" on public.campaign_members;
create policy "Members read memberships" on public.campaign_members for select to authenticated using (public.is_campaign_member(campaign_id));
drop policy if exists "Users leave campaigns" on public.campaign_members;
create policy "Users leave campaigns" on public.campaign_members for delete to authenticated using (user_id = auth.uid());

grant select, insert, update on public.profiles to authenticated;
grant select, insert, update, delete on public.campaigns to authenticated;
grant select, delete on public.campaign_members to authenticated;

-- O criador vira mestre automaticamente.
create or replace function public.add_campaign_creator() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.campaign_members (campaign_id, user_id, role) values (new.id, new.creator_id, 'master')
  on conflict do nothing;
  return new;
end $$;
drop trigger if exists campaigns_add_creator on public.campaigns;
create trigger campaigns_add_creator after insert on public.campaigns for each row execute function public.add_campaign_creator();

-- Entrar em uma campanha pelo código.
create or replace function public.join_campaign(code text) returns uuid
language plpgsql security definer set search_path = public as $$
declare cid uuid;
begin
  if auth.uid() is null then raise exception 'Não autenticado'; end if;
  select id into cid from public.campaigns where upper(join_code) = upper(trim(code));
  if cid is null then raise exception 'Código inválido'; end if;
  insert into public.campaign_members (campaign_id, user_id, role) values (cid, auth.uid(), 'player')
  on conflict do nothing;
  return cid;
end $$;
grant execute on function public.join_campaign(text) to authenticated;

-- Cria/atualiza o perfil público a partir do nome informado no cadastro.
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, display_name)
  values (new.id, coalesce(new.raw_user_meta_data->>'display_name', new.raw_user_meta_data->>'full_name', 'Jogador'))
  on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();
insert into public.profiles (id, display_name)
select id, coalesce(raw_user_meta_data->>'display_name', raw_user_meta_data->>'full_name', 'Jogador') from auth.users
on conflict (id) do nothing;

-- Contas criadas já entram confirmadas (sem verificação por e-mail).
create or replace function public.auto_confirm_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.email_confirmed_at is null then new.email_confirmed_at := now(); end if;
  return new;
end $$;
drop trigger if exists auto_confirm_user on auth.users;
create trigger auto_confirm_user before insert on auth.users for each row execute function public.auto_confirm_user();
-- Confirma as contas que ficaram pendentes.
update auth.users set email_confirmed_at = now() where email_confirmed_at is null;
