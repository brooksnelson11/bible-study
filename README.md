# Bible Study

A personal Bible study site: read the whole Bible, keep a journal, highlight verses under your own
topics, plan and lead studies. Every person's journal, plans and highlights are theirs alone.

## The isolation rule comes first

No journal, plan, highlight, question or chat is ever visible to another account. This is enforced
in the database, not in page code:

- every table carries `user_id`, set by a trigger from the signed-in identity. The client cannot choose it.
- row level security is on and forced on every table, with one policy: `user_id = auth.uid()`.
- signed-out visitors get nothing. Cross-references (a highlight's topic, a chat's plan) must also be yours.

`supabase/migrations/0001_per_user_isolation.sql` is the whole rule set.
`tests/isolation.test.mjs` runs that exact file in a local Postgres and proves, table by table, that
user A cannot read, change, delete, or plant rows in user B's account (74 checks). It runs on every
push and the site does not deploy if it fails. `tests/isolation.live.mjs` runs the same proof against
the real project through the public API before a deploy is allowed.

```
npm ci
node tests/isolation.test.mjs
```

## Status

- [x] Phase 1: per-user rules + the proof (this)
- [ ] Phase 2: static reader + Proverbs + journal + highlights (GitHub Pages)
- [ ] Phase 3: sign-in (email link) + sync through Supabase
- [ ] Phase 4: AI plan outline, session prep, chat behind a per-person monthly cap

## How I built it

I set the rule that comes first here: nobody can ever see another person's journal, plans or highlights, and no feature ships before that's proven. The code and the 74 checks were written with Claude Code, an AI coding assistant, working from my direction.
