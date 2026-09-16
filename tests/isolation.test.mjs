// Proves the per-user rules in supabase/migrations/0001_per_user_isolation.sql actually hold.
// Runs the EXACT migration file inside an in-process Postgres (PGlite), with Supabase's auth.uid()
// and the anon/authenticated roles emulated, then acts as user A, user B, a signed-out visitor,
// and a half-signed-in session, and checks every table. Any leak fails the run (exit 1).
//
//   node tests/isolation.test.mjs
//
// The deploy workflow runs this on every push; tests/isolation.live.mjs runs the same assertions
// against the real Supabase project through its public API before a deploy is allowed.
import { PGlite } from '@electric-sql/pglite';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

const MIGRATION = new URL('../supabase/migrations/0001_per_user_isolation.sql', import.meta.url);
const db = new PGlite();
let fails = 0;
const ok = (label, cond, extra = '') => { console.log((cond ? 'ok   ' : 'FAIL ') + label + (cond ? '' : '  ' + extra)); if (!cond) fails++; };
const A = randomUUID(), B = randomUUID();

// ── emulate the Supabase auth surface the policies depend on ────────────────────────────────
await db.exec(`
  create schema auth;
  create function auth.uid() returns uuid language sql stable as
    $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
  create role anon nologin;
  create role authenticated nologin;
  grant usage on schema public to anon, authenticated;
  grant usage on schema auth to anon, authenticated;
  grant execute on function auth.uid() to anon, authenticated;
`);
await db.exec(readFileSync(MIGRATION, 'utf8'));

// ── session switching ───────────────────────────────────────────────────────────────────────
const as = async (uid) => { await db.exec(`reset role; select set_config('request.jwt.claim.sub', '${uid ?? ''}', false); set role authenticated;`); };
const asAnon = async () => { await db.exec(`reset role; select set_config('request.jwt.claim.sub', '', false); set role anon;`); };
const admin = async () => { await db.exec('reset role;'); };
const q = (sql, params = []) => db.query(sql, params);
const fails_with = async (sql, params = []) => { try { await q(sql, params); return null; } catch (e) { return String(e.message || e); } };

// One sample row per table. `insert` is the client-shaped insert (no user_id — the trigger sets it).
const TABLES = {
  profiles:   { insert: "insert into profiles(display_name) values ('A')", key: 'user_id' },
  settings:   { insert: "insert into settings(data) values ('{\"theme\":\"dawn\"}')", key: 'user_id' },
  plans:      { insert: "insert into plans(title) values ('Romans in 6 weeks')", key: 'id' },
  journal:    { insert: "insert into journal(body, verse_ref) values ('felt this today', 'Ps 23')", key: 'id' },
  umbrellas:  { insert: "insert into umbrellas(label, color) values ('Identity', '#abc')", key: 'id' },
  highlights: { insert: "insert into highlights(ref, note) values ('John 3:16', 'core')", key: 'id' },
  questions:  { insert: "insert into questions(text) values ('why did Jesus weep?')", key: 'id' },
  chats:      { insert: "insert into chats(messages) values ('[{\"role\":\"user\",\"text\":\"hi\"}]')", key: 'id' },
};

// ── 0. structural guard: every public table has RLS on + forced + a policy ──────────────────
await admin();
const rls = (await q(`select c.relname, c.relrowsecurity, c.relforcerowsecurity,
                        (select count(*) from pg_policy p where p.polrelid = c.oid) as policies
                      from pg_class c join pg_namespace n on n.oid = c.relnamespace
                      where n.nspname = 'public' and c.relkind = 'r' order by 1`)).rows;
for (const r of rls) ok(`table ${r.relname}: RLS on, forced, ${r.policies} policy`, r.relrowsecurity && r.relforcerowsecurity && Number(r.policies) >= 1);
ok('every table in the schema was checked (' + rls.length + ')', rls.length === Object.keys(TABLES).length + 1 /* ai_usage */);

// ── 1. A writes, A reads ────────────────────────────────────────────────────────────────────
const aIds = {};
for (const [t, spec] of Object.entries(TABLES)) {
  await as(A);
  const err = await fails_with(spec.insert);
  ok(`${t}: A can insert`, !err, err || '');
  const rows = (await q(`select * from ${t}`)).rows;
  ok(`${t}: A sees exactly her row, stamped with her id`, rows.length === 1 && rows[0].user_id === A);
  aIds[t] = rows[0]?.[spec.key];
}

// ── 2. B sees, changes, deletes nothing of A's ──────────────────────────────────────────────
for (const [t, spec] of Object.entries(TABLES)) {
  await as(B);
  ok(`${t}: B sees 0 rows`, (await q(`select * from ${t}`)).rows.length === 0);
  ok(`${t}: B sees 0 rows even by A's exact id`, (await q(`select * from ${t} where ${spec.key} = $1`, [aIds[t]])).rows.length === 0);
  const upd = await q(`update ${t} set ${t === 'profiles' ? 'display_name' : t === 'settings' ? 'data' : t === 'plans' ? 'title' : t === 'journal' ? 'body' : t === 'umbrellas' ? 'label' : t === 'highlights' ? 'note' : t === 'questions' ? 'text' : 'messages'} = ${t === 'settings' ? "'{}'" : t === 'chats' ? "'[]'" : "'hacked'"} where ${spec.key} = $1`, [aIds[t]]);
  ok(`${t}: B's update of A's row touches 0 rows`, upd.affectedRows === 0);
  const del = await q(`delete from ${t} where ${spec.key} = $1`, [aIds[t]]);
  ok(`${t}: B's delete of A's row touches 0 rows`, del.affectedRows === 0);
}

// ── 3. B cannot write a row INTO A's account, even by naming A's id ─────────────────────────
await as(B);
await q(`insert into journal(user_id, body) values ($1, 'planted')`, [A]);
await as(A);
const aJournal = (await q('select body from journal')).rows;
ok('journal: a row B inserted "as A" landed in B\'s account, not A\'s', aJournal.length === 1 && aJournal[0].body === 'felt this today');
await as(B);
ok('journal: …and B owns it', (await q('select body from journal')).rows.map(r => r.body).join() === 'planted');
const handoff = await fails_with(`update journal set user_id = $1 where body = 'planted'`, [A]);
ok('journal: B cannot hand her row to A by changing user_id (update rejected)', /row-level security/i.test(handoff || ''));
await as(A);
ok('journal: …and A still has exactly her one entry', (await q('select count(*)::int as n from journal')).rows[0].n === 1);

// ── 4. cross-references cannot point at another person's things ─────────────────────────────
await as(B);
ok('highlights: B cannot attach A\'s umbrella', /not yours|violates|permission/i.test(await fails_with(`insert into highlights(ref, umbrella_id) values ('Ps 1:1', $1)`, [aIds.umbrellas]) || ''));
ok('chats: B cannot attach a chat to A\'s plan', /not yours|violates|permission/i.test(await fails_with(`insert into chats(plan_id) values ($1)`, [aIds.plans]) || ''));

// ── 5. signed-out and half-signed-in sessions get nothing ───────────────────────────────────
await asAnon();
ok('anon: cannot read journal', /permission denied/i.test(await fails_with('select * from journal') || ''));
ok('anon: cannot insert journal', /permission denied/i.test(await fails_with("insert into journal(body) values ('x')") || ''));
await as(null);
ok('authenticated role with no identity: insert refused by the owner trigger', /not signed in|violates row-level/i.test(await fails_with("insert into journal(body) values ('x')") || ''));
ok('authenticated role with no identity: reads 0 rows', (await q('select * from journal')).rows.length === 0);

// ── 6. ai_usage: proxy-written, owner-read ──────────────────────────────────────────────────
await admin();
await q(`insert into ai_usage(user_id, month, calls) values ($1, '2026-09', 3), ($2, '2026-09', 9)`, [A, B]);
await as(A);
ok('ai_usage: A reads only her own counter', JSON.stringify((await q('select calls from ai_usage')).rows) === '[{"calls":3}]');
ok('ai_usage: A cannot bump her own counter', /permission denied/i.test(await fails_with("update ai_usage set calls = 0") || ''));
ok('ai_usage: A cannot insert a counter', /permission denied/i.test(await fails_with("insert into ai_usage(user_id, month) values ($1, '2026-10')", [A]) || ''));

// ── 7. what A can still do to her own things (the rules must not break normal use) ──────────
await as(A);
ok('plans: A can update her own', (await q(`update plans set title = 'Romans, 8 weeks' where id = $1`, [aIds.plans])).affectedRows === 1);
ok('highlights: A can file under her own umbrella', !(await fails_with(`update highlights set umbrella_id = $1 where id = $2`, [aIds.umbrellas, aIds.highlights])));
ok('plans: A can delete her own', (await q(`delete from plans where id = $1`, [aIds.plans])).affectedRows === 1);

console.log(fails ? `\n${fails} FAILED — do not deploy` : '\nALL PASSED — no row crosses accounts');
process.exit(fails ? 1 : 0);
