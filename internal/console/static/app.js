'use strict';

const $ = (id) => document.getElementById(id);
let invitation = null;
let state = null;

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (method !== 'GET') {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body ?? {});
  }
  const resp = await fetch('api/' + path, opts);
  if (resp.status === 401) {
    showGate('login');
    throw new Error('Log in again.');
  }
  if (!resp.ok) throw new Error((await resp.text()).trim() || resp.statusText);
  return resp.status === 204 ? null : resp.json();
}

function setupCode() {
  const m = location.hash.match(/setup=([0-9a-f]+)/);
  return m ? m[1] : null;
}

async function start() {
  const s = await api('GET', 'session');
  $('title').textContent = s.name;
  document.title = s.name + ' · Launchpad';
  if (setupCode()) return showGate('setup');
  if (s.state === 'ok') return showConsole();
  showGate(s.state);
}

function showGate(kind) {
  $('console').hidden = true;
  $('logout').hidden = true;
  $('gate').hidden = false;
  $('gate-error').textContent = '';
  const setup = kind === 'setup';
  const canSetup = setup && setupCode();
  $('gate-title').textContent = setup ? 'Set the console password' : 'Log in';
  $('gate-text').textContent = setup
    ? canSetup
      ? 'This password protects this page only, so guests on your network can\'t pair devices. The app doesn\'t need it.'
      : 'No password yet. Open the setup link from the launchpad\'s log, or run "minstrel-launchpad console" on the launchpad for a new one.'
    : 'Forgot it? Run "minstrel-launchpad console" on the launchpad for a link to set a new one.';
  $('gate-form').hidden = setup && !canSetup;
  $('confirm-row').hidden = !setup;
  $('confirm').required = setup;
  $('password').autocomplete = setup ? 'new-password' : 'current-password';
  $('gate-button').textContent = setup ? 'Set password' : 'Log in';
  $('gate-form').dataset.kind = setup ? 'setup' : 'login';
  $('password').focus();
}

$('gate-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = $('password').value;
  const err = $('gate-error');
  err.textContent = '';
  try {
    if (e.target.dataset.kind === 'setup') {
      if (password !== $('confirm').value) throw new Error('The passwords don\'t match.');
      await api('POST', 'setup', { code: setupCode(), password });
      history.replaceState(null, '', location.pathname);
    } else {
      await api('POST', 'login', { password });
    }
    $('password').value = $('confirm').value = '';
    showConsole();
  } catch (x) {
    err.textContent = x.message;
  }
});

$('logout').addEventListener('click', async () => {
  await api('POST', 'logout').catch(() => {});
  showGate('login');
});

async function showConsole() {
  $('gate').hidden = true;
  $('console').hidden = false;
  $('logout').hidden = false;
  await load();
}

async function load() {
  render(await api('GET', 'state'));
}

const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });
const timeFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

function ago(iso) {
  if (!iso) return 'never';
  const s = (Date.now() - new Date(iso)) / 1000;
  if (s < 90) return 'just now';
  if (s < 3600) return Math.round(s / 60) + ' minutes ago';
  if (s < 86400 * 2) return Math.round(s / 3600) + ' hours ago';
  if (s < 86400 * 30) return Math.round(s / 86400) + ' days ago';
  return dateFmt.format(new Date(iso));
}

function until(iso) {
  const s = (new Date(iso) - Date.now()) / 1000;
  if (s < 3600) return 'in ' + Math.max(1, Math.round(s / 60)) + ' min';
  if (s < 86400 * 2) return 'in ' + Math.round(s / 3600) + ' hours';
  return 'in ' + Math.round(s / 86400) + ' days';
}

function cell(text, key, secondary) {
  const td = document.createElement('td');
  if (key) td.dataset.k = key;
  td.append(text);
  if (secondary) {
    const span = document.createElement('span');
    span.className = 'secondary';
    span.textContent = secondary;
    td.append(span);
  }
  return td;
}

function button(text, onClick) {
  const td = document.createElement('td');
  td.className = 'action';
  const b = document.createElement('button');
  b.className = 'danger';
  b.textContent = text;
  b.addEventListener('click', () => onClick(b));
  td.append(b);
  return td;
}

function fill(tbody, empty, rows) {
  $(tbody).replaceChildren(...rows);
  $(empty).hidden = rows.length > 0;
  $(tbody).closest('table').hidden = rows.length === 0;
}

function isLAN(ip) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|f[cd]|fe80:|::1$)/i.test(ip || '');
}

function render(s) {
  state = s;
  $('title').textContent = s.name;
  $('subtitle').textContent = 'minstrel-launchpad ' + s.version;
  $('fingerprint').textContent = s.fingerprint;
  for (const el of document.querySelectorAll('.port')) el.textContent = s.port;
  $('lan').textContent = s.lan.length ? s.lan.join(', ') : 'no home-network address (check the network)';

  // Unsaved edits stay until saved.
  if (!$('name').dataset.dirty) $('name').value = s.name;
  $('name').disabled = $('name-save').disabled = s.nameLocked;
  $('name-locked').hidden = !s.nameLocked;
  if (!$('public').dataset.dirty) $('public').value = s.public.join('\n');
  $('public').disabled = $('public-save').disabled = s.publicLocked;
  $('public-locked').hidden = !s.publicLocked;
  if (!$('manual').dataset.dirty) $('manual').value = s.manual.join('\n');
  $('manual').disabled = $('servers-save').disabled = s.serversLocked;
  $('servers-locked').hidden = !s.serversLocked;

  fill('invitations', 'no-invitations', s.invitations.map((inv) => {
    const tr = document.createElement('tr');
    tr.append(
      cell(inv.label || 'Anyone'),
      cell(dateFmt.format(new Date(inv.created)), 'Created'),
      cell(until(inv.expires), 'Expires'),
      button('Cancel', async (b) => {
        b.disabled = true;
        await api('DELETE', 'invitations/' + inv.id).catch(alertError);
        if (invitation?.id === inv.id) hideInvitation();
        load();
      }),
    );
    return tr;
  }));
  if (invitation && !s.invitations.some((i) => i.id === invitation.id)) hideInvitation();

  fill('devices', 'no-devices', s.devices.map((d) => {
    const tr = document.createElement('tr');
    const from = d.lastAddr ? (isLAN(d.lastAddr) ? 'home network' : 'outside') : '';
    tr.append(
      cell(d.name, null, [d.label && d.label !== d.name ? 'for ' + d.label : '', 'id ' + d.id].filter(Boolean).join(' · ')),
      cell(dateFmt.format(new Date(d.created)), 'Paired'),
      cell(ago(d.lastSeen), 'Last access', d.lastSeen ? timeFmt.format(new Date(d.lastSeen)) : ''),
      cell(d.lastAddr || '—', 'From', from),
      button('Revoke', async (b) => {
        if (!confirmInline(b, 'Revoke?')) return;
        b.disabled = true;
        await api('DELETE', 'devices/' + d.id).catch(alertError);
        load();
      }),
    );
    return tr;
  }));

  fill('servers', 'no-servers', s.servers.map((srv) => {
    const tr = document.createElement('tr');
    let addr = srv.location;
    try { addr = new URL(srv.location).host; } catch { /* keep as is */ }
    tr.append(
      cell(srv.name, null, srv.manual ? 'added by hand' : ''),
      cell([srv.manufacturer, srv.model].filter(Boolean).join(' ') || '—', 'Model'),
      cell(addr, 'Address'),
    );
    return tr;
  }));
}

// Two-step buttons instead of browser dialogs: the first click asks.
function confirmInline(b, question) {
  if (b.dataset.armed) return true;
  const text = b.textContent;
  b.dataset.armed = '1';
  b.textContent = question;
  setTimeout(() => { delete b.dataset.armed; b.textContent = text; }, 4000);
  return false;
}

function alertError(x) {
  const el = $('invite-error');
  el.textContent = x.message;
}

for (const id of ['name', 'public', 'manual']) {
  $(id).addEventListener('input', () => { $(id).dataset.dirty = '1'; });
}

async function saveSettings(form, body, errorId) {
  $(errorId).textContent = '';
  const btn = form.querySelector('button[type=submit]');
  btn.disabled = true;
  try {
    const s = await api('PUT', 'settings', body);
    delete form.querySelector('textarea, input').dataset.dirty;
    render(s);
    btn.textContent = 'Saved';
    setTimeout(() => { btn.textContent = 'Save'; }, 1500);
  } catch (x) {
    $(errorId).textContent = x.message;
  } finally {
    btn.disabled = false;
  }
}

const lines = (id) => $(id).value.split(/[\n,]/).map((l) => l.trim()).filter(Boolean);

$('name-form').addEventListener('submit', (e) => {
  e.preventDefault();
  saveSettings(e.target, { name: $('name').value }, 'name-error');
});

$('public-form').addEventListener('submit', (e) => {
  e.preventDefault();
  saveSettings(e.target, { public: lines('public') }, 'public-error');
});

$('servers-form').addEventListener('submit', (e) => {
  e.preventDefault();
  saveSettings(e.target, { servers: lines('manual') }, 'servers-error');
});

$('refresh').addEventListener('click', async (e) => {
  e.target.disabled = true;
  await api('POST', 'servers/refresh').catch(() => {});
  setTimeout(async () => { await load().catch(() => {}); e.target.disabled = false; }, 4000);
});

for (const tab of document.querySelectorAll('.tab')) {
  tab.addEventListener('click', () => {
    for (const t of document.querySelectorAll('.tab')) {
      t.setAttribute('aria-selected', String(t === tab));
      $('tab-' + t.dataset.tab).hidden = t !== tab;
    }
  });
}

$('invite-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('invite-error').textContent = '';
  if (state && state.public.length === 0 && $('valid').value !== '10m') {
    $('invite-error').textContent = 'No outside address is set, so this device will only connect at home.';
  }
  try {
    invitation = await api('POST', 'invitations', { label: $('label').value.trim(), valid: $('valid').value });
    $('qr').src = invitation.qr;
    $('inv-for').textContent = invitation.label ? 'For ' + invitation.label : 'For any device';
    $('inv-expires').textContent = timeFmt.format(new Date(invitation.expires));
    $('inv-code').textContent = invitation.code;
    $('invitation').hidden = false;
    $('label').value = '';
    load();
  } catch (x) {
    $('invite-error').textContent = x.message;
  }
});

function hideInvitation() {
  invitation = null;
  $('invitation').hidden = true;
  $('qr').removeAttribute('src');
}

$('done').addEventListener('click', hideInvitation);

$('download').addEventListener('click', () => {
  if (!invitation) return;
  const blob = new Blob([invitation.uri + '\n'], { type: 'application/x-minstrel-pairing' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = invitation.file;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});

$('copy').addEventListener('click', async (e) => {
  if (!invitation) return;
  await navigator.clipboard.writeText(invitation.uri);
  e.target.textContent = 'Copied';
  setTimeout(() => { e.target.textContent = 'Copy link'; }, 1500);
});

// Keep "last access" and the server list current while the page is open.
setInterval(() => { if (!$('console').hidden && !document.hidden) load().catch(() => {}); }, 30000);

start().catch((x) => { $('gate').hidden = false; $('gate-error').textContent = x.message; });
