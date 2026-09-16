// The same isolation proof, run against the REAL Supabase project through its public API
// (what the website itself uses). Runs from the VPS before any deploy; needs three env vars:
//   SUPABASE_URL, SUPABASE_ANON_KEY (both public, same as the site), SUPABASE_SERVICE_KEY (server only,
//   used solely to create + delete two throwaway users). The service key never enters the repo or site.
//
//   SUPABASE_URL=... SUPABASE_ANON_KEY=... SUPABASE_SERVICE_KEY=... node tests/isolation.live.mjs
import { createClient } from '@supabase/supabase-js';
import { randomUUID } from 'node:crypto';

const { SUPABASE_URL: URL, SUPABASE_ANON_KEY: ANON, SUPABASE_SERVICE_KEY: SERVICE } = process.env;
if (!URL || !ANON || !SERVICE) { console.error('set SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_KEY'); process.exit(2); }

let fails = 0;
const ok = (label, cond, extra = '') => { console.log((cond ? 'ok   ' : 'FAIL ') + label + (cond ? '' : '  ' + extra)); if (!cond) fails++; };
const admin = createClient(URL, SERVICE, { auth: { persistSession: false, autoRefreshToken: false } });
const anonClient = () => createClient(URL, ANON, { auth: { persistSession: false, autoRefreshToken: false } });

async function makeUser(tag) {
  const email = `isolation-${tag}-${randomUUID().slice(0, 8)}@example.invalid`, password = randomUUID() + 'Aa1!';
  const { data, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
  if (error) throw error;
  const c = anonClient();
  const { error: e2 } = await c.auth.signInWithPassword({ email, password });
  if (e2) throw e2;
  return { id: data.user.id, c };
}

const TABLES = {
  profiles:   { row: { display_name: 'A' }, key: 'user_id', patch: { display_name: 'hacked' } },
  settings:   { row: { data: { theme: 'dawn' } }, key: 'user_id', patch: { data: {} } },
  plans:      { row: { title: 'Romans in 6 weeks' }, key: 'id', patch: { title: 'hacked' } },
  journal:    { row: { body: 'felt this today', verse_ref: 'Ps 23' }, key: 'id', patch: { body: 'hacked' } },
  umbrellas:  { row: { label: 'Identity', color: '#abc' }, key: 'id', patch: { label: 'hacked' } },
  highlights: { row: { ref: 'John 3:16', note: 'core' }, key: 'id', patch: { note: 'hacked' } },
  questions:  { row: { text: 'why did Jesus weep?' }, key: 'id', patch: { text: 'hacked' } },
  chats:      { row: { messages: [{ role: 'user', text: 'hi' }] }, key: 'id', patch: { messages: [] } },
};

const A = await makeUser('a'), B = await makeUser('b');
try {
  const aIds = {};
  for (const [t, spec] of Object.entries(TABLES)) {
    const { data, error } = await A.c.from(t).insert(spec.row).select().single();
    ok(`${t}: A can insert`, !error, error?.message);
    ok(`${t}: row is stamped with A's id`, data?.user_id === A.id);
    aIds[t] = data?.[spec.key];
    const { data: mine } = await A.c.from(t).select('*');
    ok(`${t}: A sees exactly her row`, mine?.length === 1);
  }
  for (const [t, spec] of Object.entries(TABLES)) {
    const { data: seen } = await B.c.from(t).select('*');
    ok(`${t}: B sees 0 rows`, seen?.length === 0);
    const { data: byId } = await B.c.from(t).select('*').eq(spec.key, aIds[t]);
    ok(`${t}: B sees 0 rows by A's exact id`, byId?.length === 0);
    const { data: upd } = await B.c.from(t).update(spec.patch).eq(spec.key, aIds[t]).select();
    ok(`${t}: B's update of A's row touches 0 rows`, (upd ?? []).length === 0);
    const { data: del } = await B.c.from(t).delete().eq(spec.key, aIds[t]).select();
    ok(`${t}: B's delete of A's row touches 0 rows`, (del ?? []).length === 0);
    const { data: still } = await A.c.from(t).select('*').eq(spec.key, aIds[t]);
    ok(`${t}: A's row is untouched afterwards`, still?.length === 1 && JSON.stringify(still[0]).includes(t === 'settings' ? 'dawn' : t === 'chats' ? 'hi' : Object.values(spec.row)[0]));
  }
  // planting a row "as A"
  const { data: planted } = await B.c.from('journal').insert({ user_id: A.id, body: 'planted' }).select().single();
  ok('journal: a row B inserted "as A" landed in B\'s account', planted?.user_id === B.id);
  const { data: aJ } = await A.c.from('journal').select('body');
  ok('journal: A still has exactly her one entry', aJ?.length === 1 && aJ[0].body === 'felt this today');
  const { error: handoff } = await B.c.from('journal').update({ user_id: A.id }).eq('body', 'planted');
  ok('journal: B cannot hand her row to A', !!handoff);
  // cross references
  const { error: umb } = await B.c.from('highlights').insert({ ref: 'Ps 1:1', umbrella_id: aIds.umbrellas });
  ok('highlights: B cannot attach A\'s umbrella', !!umb);
  const { error: pl } = await B.c.from('chats').insert({ plan_id: aIds.plans });
  ok('chats: B cannot attach a chat to A\'s plan', !!pl);
  // signed-out
  const visitor = anonClient();
  const { data: vSeen, error: vErr } = await visitor.from('journal').select('*');
  ok('anon: cannot read journal', !!vErr || (vSeen ?? []).length === 0);
  const { error: vIns } = await visitor.from('journal').insert({ body: 'x' });
  ok('anon: cannot insert journal', !!vIns);
  // ai_usage
  await admin.from('ai_usage').upsert([{ user_id: A.id, month: '2026-09', calls: 3 }, { user_id: B.id, month: '2026-09', calls: 9 }]);
  const { data: usage } = await A.c.from('ai_usage').select('calls');
  ok('ai_usage: A reads only her own counter', JSON.stringify(usage) === '[{"calls":3}]');
  const { data: bump } = await A.c.from('ai_usage').update({ calls: 0 }).eq('user_id', A.id).select();
  ok('ai_usage: A cannot bump her own counter', (bump ?? []).length === 0);
} finally {
  await admin.auth.admin.deleteUser(A.id).catch(() => {});
  await admin.auth.admin.deleteUser(B.id).catch(() => {});
}
console.log(fails ? `\n${fails} FAILED — do not deploy` : '\nALL PASSED on the live project — no row crosses accounts');
process.exit(fails ? 1 : 0);
