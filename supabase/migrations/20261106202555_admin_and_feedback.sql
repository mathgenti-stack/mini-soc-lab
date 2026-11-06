-- Applied to the Supabase project (ref vnmcjtdxfbjnxiuezzda) on 2026-11-06. Kept here as the record of the schema.
-- Admin view (follow the testers) and the feedback button.

-- Who is admin: a private list of e-mails (no policies, so the API cannot read or change it).
create table public.admins (
  email text primary key
);
alter table public.admins enable row level security;
revoke all on public.admins from anon, authenticated;
insert into public.admins (email) values ('mathgenti@gmail.com');

-- True for a signed-in admin with a confirmed e-mail.
create function public.is_admin() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from auth.users u join public.admins a on lower(a.email) = lower(u.email)
    where u.id = auth.uid() and u.email_confirmed_at is not null
  );
$$;
revoke execute on function public.is_admin() from public, anon;
grant execute on function public.is_admin() to authenticated;

-- Everyone's account and progress, for the admin page only.
create function public.admin_overview()
returns table (user_id uuid, email text, name text, created_at timestamptz, last_sign_in_at timestamptz,
               updated_at timestamptz, course jsonb, lab jsonb)
language plpgsql stable security definer set search_path = '' as $$
begin
  if not public.is_admin() then
    raise exception 'admins only' using errcode = '42501';
  end if;
  return query
    select u.id, u.email::text, (u.raw_user_meta_data ->> 'name')::text, u.created_at, u.last_sign_in_at,
           p.updated_at, coalesce(p.course, '{}'::jsonb), coalesce(p.lab, '{}'::jsonb)
    from auth.users u left join public.progress p on p.user_id = u.id
    order by greatest(u.last_sign_in_at, p.updated_at) desc nulls last;
end $$;
revoke execute on function public.admin_overview() from public, anon;
grant execute on function public.admin_overview() to authenticated;

-- Feedback: anyone can send (signed in or not); only the admin reads it.
create table public.feedback (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  user_id uuid default auth.uid() references auth.users (id) on delete cascade,
  page text not null,            -- 'curso' or 'lab'
  context text not null default '',  -- where the person was (topic and tab, or the challenge)
  message text not null,
  resolved boolean not null default false,
  constraint page_ok check (page in ('curso', 'lab')),
  constraint message_size check (char_length(btrim(message)) between 1 and 2000),
  constraint context_size check (char_length(context) <= 300)
);
alter table public.feedback enable row level security;

create policy "anyone sends feedback" on public.feedback
  for insert to anon, authenticated
  with check (resolved = false and (user_id is null or user_id = (select auth.uid())));
create policy "admin reads feedback" on public.feedback
  for select to authenticated using ((select public.is_admin()));
create policy "admin marks feedback" on public.feedback
  for update to authenticated using ((select public.is_admin())) with check ((select public.is_admin()));
create policy "admin deletes feedback" on public.feedback
  for delete to authenticated using ((select public.is_admin()));

revoke all on public.feedback from anon, authenticated;
grant insert (page, context, message, user_id) on public.feedback to anon, authenticated;
grant select, delete on public.feedback to authenticated;
grant update (resolved) on public.feedback to authenticated;

create index feedback_user_id on public.feedback (user_id);
