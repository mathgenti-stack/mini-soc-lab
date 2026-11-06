-- Applied to the Supabase project (ref vnmcjtdxfbjnxiuezzda) on 2026-11-06. Kept here as the record of the schema.
-- One row per signed-in person: the lab's saved files and the course page's state.
create table public.progress (
  user_id uuid primary key default auth.uid() references auth.users (id) on delete cascade,
  lab jsonb not null default '{}'::jsonb,     -- {"terminal_linux.json": "<file text>", ...} (files under /mnt/soclab)
  course jsonb not null default '{}'::jsonb,  -- the course page's saved state (checklists, quiz, notes)
  updated_at timestamptz not null default now(),
  constraint lab_is_object check (jsonb_typeof(lab) = 'object'),
  constraint course_is_object check (jsonb_typeof(course) = 'object'),
  constraint size_limit check (pg_column_size(lab) + pg_column_size(course) < 1000000)
);

comment on table public.progress is 'Mini SOC Lab: study progress per user (only the owner can read or change it).';

alter table public.progress enable row level security;

create policy "read own progress" on public.progress
  for select to authenticated using ((select auth.uid()) = user_id);
create policy "add own progress" on public.progress
  for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "change own progress" on public.progress
  for update to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "delete own progress" on public.progress
  for delete to authenticated using ((select auth.uid()) = user_id);

revoke all on public.progress from anon;
grant select, insert, update, delete on public.progress to authenticated;

create function public.touch_updated_at() returns trigger
language plpgsql set search_path = '' as $$
begin
  new.updated_at := now();
  return new;
end $$;

create trigger progress_touch before update on public.progress
  for each row execute function public.touch_updated_at();

-- "Apagar minha conta": removes the auth user; the progress row goes with it (on delete cascade).
create function public.delete_my_account() returns void
language plpgsql security definer set search_path = '' as $$
begin
  if auth.uid() is null then
    raise exception 'not signed in';
  end if;
  delete from auth.users where id = auth.uid();
end $$;

revoke execute on function public.delete_my_account() from public, anon;
grant execute on function public.delete_my_account() to authenticated;
revoke execute on function public.touch_updated_at() from public, anon, authenticated;
