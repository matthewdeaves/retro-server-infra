// Live updates. Polls /api/status and patches the numbers in place, so the
// page does not have to be reloaded to see who joined.
//
// In its own file for the same reason as app.js: kept inside a Python string
// literal, an escape sequence can silently rewrite the code before the browser
// sees it. That happened once and cost every piece of interactivity on the
// site.
(function () {
  const $ = (id) => document.getElementById(id);
  const setHTML = (id, v) => { const e = $(id); if (e && v != null && e.innerHTML !== v) e.innerHTML = v; };
  let expiresAt = null;               // epoch ms your game access runs out
  let failures = 0;

  // The games are not behind Cloudflare, so a grant made from an IPv6 visit
  // (post_allow, the Allow button) never reaches them -- see
  // post_allow_ipv4 for the full reasoning. [data-probe-v4] only exists in
  // the markup when the server saw this visit arrive over IPv6, so an IPv4
  // visitor never makes this request at all. api4.ipify.org has no AAAA
  // record of its own, so a reply proves this browser's IPv4 genuinely
  // works, and reports what it is -- the one thing this page cannot learn
  // any other way, since a single connection only ever carries one address
  // family. Runs once per page load, not on the 8s poll: the address does
  // not change every few seconds, and post_allow_ipv4 already resets the
  // timeout on every call, so nothing is lost by only doing this once.
  if (document.querySelector('[data-probe-v4]')) {
    fetch('https://api4.ipify.org', { mode: 'cors' })
      .then((r) => (r.ok ? r.text() : null))
      .then((ip) => {
        ip = (ip || '').trim();
        if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return;
        return fetch('/allow-ipv4', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'ip=' + encodeURIComponent(ip),
        });
      })
      .then((r) => (r && r.ok ? r.json() : null))
      .then((d) => {
        // A refused relay address is the one outcome the person has to be
        // told about: nothing else on the page would ever mention it, and
        // the pill will keep saying "can play" for the relay address while
        // their game sits there timing out. #you-warn is already the slot
        // for "you are not actually getting in", so it says so here too.
        if (d && d.relay && d.advice) {
          const w = $('you-warn');
          if (w) w.textContent = d.advice;
        }
      })
      // Best-effort. api4.ipify.org being unreachable, or this browser
      // having no real IPv4 path either, both mean the same thing: nothing
      // to grant, quietly leave the existing IPv6-only state as it is.
      .catch(() => {});
  }

  function fmt(s) {
    if (s == null) return '';
    if (s <= 0) return 'expired';
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
    if (h) return h + 'h ' + String(m).padStart(2, '0') + 'm left';
    if (m) return m + 'm left';
    return Math.floor(s) + 's left';
  }

  // How close the grant is to lapsing, as a class name.
  //
  // The countdown has always been correct and has always been the same muted
  // grey at three hours as at four minutes, so it read as decoration. It is
  // not: when it reaches zero every Mac stops being able to reach every game
  // port, and the four bays carry on reporting all four servers up -- which
  // they are. Nothing on the page connected "these are fine" to "and you
  // cannot reach any of them".
  function level(s) {
    if (s == null) return '';
    if (s <= 0) return 'gone';
    if (s <= 600) return 'danger';
    if (s <= 3600) return 'warn';
    return '';
  }

  // Said in full rather than as a colour, because the colour alone does not
  // tell you what to do about it and this page is used from a phone by
  // someone who did not set the firewall up.
  const BLOCKED = 'The servers are up. This device cannot reach the game ' +
                  'ports until you press Let me in.';

  function lapseText(s) {
    if (s == null || s > 3600) return '';
    if (s <= 0) return BLOCKED;
    const m = Math.max(1, Math.round(s / 60));
    return 'Your access to the game ports runs out in about ' + m +
           (m === 1 ? ' minute' : ' minutes') + '. The servers stay up; this ' +
           'device stops being able to reach them. Press Extend to keep it.';
  }

  function setClass(id, v) { const e = $(id); if (e && e.className !== v) e.className = v; }

  function paintTtl(secs) {
    setHTML('you-ttl', fmt(secs));
    setClass('you-ttl', ('ttl ' + level(secs)).trim());
    setHTML('you-warn', lapseText(secs));
  }

  // Counts down between polls, so the number moves every second instead of
  // jumping every eight.
  setInterval(() => {
    if (expiresAt == null) return;
    paintTtl((expiresAt - Date.now()) / 1000);
  }, 1000);

  // Say so, and make saying so actionable. Added to a Home Screen there is no
  // address bar and no reload button, so "reload to sign in again" was an
  // instruction with nothing to carry it out — the only way back was to close
  // the app and reopen it.
  function stale(msg) {
    const b = $('livebar');
    if (!b || b.classList.contains('stale')) return;
    b.textContent = msg;
    b.className = 'live stale';
    b.setAttribute('role', 'button');
    b.setAttribute('tabindex', '0');
    b.onclick = () => window.location.reload();
    b.onkeydown = (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); window.location.reload(); }
    };
  }

  async function poll() {
    // Nothing on this page is worth a request while it is in a background tab.
    if (document.hidden) return;
    let r;
    try { r = await fetch('/api/status', {headers: {Accept: 'application/json'}}); }
    catch (e) {
      // Offline, or the request was blocked. Counted like any other failure:
      // returning silently forever leaves a Home Screen app showing numbers
      // from whenever it last worked, with nothing saying so.
      if (++failures >= 3) stale('Offline \u2014 tap to retry');
      return;
    }

    // An expired Access session redirects to the Cloudflare login, which is
    // HTML. Without this the page just quietly stops updating and shows stale
    // numbers, which is worse than saying so.
    const ct = r.headers.get('content-type') || '';
    if (r.status === 403 || !ct.includes('application/json')) {
      if (++failures >= 2) stale('Session expired \u2014 tap to sign in');
      return;
    }
    failures = 0;
    const bar = $('livebar');
    if (bar && bar.classList.contains('stale')) {
      bar.textContent = 'live';
      bar.className = 'live';
      bar.onclick = null;
    }
    const s = await r.json();

    for (const [g, v] of Object.entries(s.games || {})) {
      // The server decides the verdict; this only paints it. Working the
      // three states out here as well as in Python is how the two drift, and
      // the amber one — unit up, engine not answering — is the whole reason
      // there are three.
      const p = $('state-' + g);
      const label = v.label || v.state;
      if (p && (p.textContent !== label || p.className !== 'pill ' + (v.pill || 'off'))) {
        p.textContent = label;
        p.className = 'pill ' + (v.pill || 'off');
      }
      // The bay's left spine carries the same verdict, so a server that stops
      // answering turns amber without a reload.
      const bay = p && p.closest ? p.closest('.bay, .game') : null;
      if (bay && v.rag) {
        bay.classList.remove('up', 'warn', 'down');
        bay.classList.add(v.rag);
      }
      setHTML('meta-' + g, v.meta);
      setHTML('life-' + g, v.life || '');
      // The bays show chips; a game page showing the match chart does not,
      // because that would be the same four names twice with the same numbers.
      // Which element exists tells us which page we are on.
      const onGamePage = !!$('match-' + g);
      setHTML('who-' + g, onGamePage ? (v.who_page || '') : v.who);
      setHTML('match-' + g, v.match || '');
    }
    if (s.host) {
      setHTML('hoststats', 'up ' + (s.host.uptime || '?') + ' \u00b7 load ' + (s.host.load || '?'));
      updateHealth(s.host, s.total_players);
    }
    setHTML('players-list', s.players_list);
    setHTML('admins-list', s.admins_list);
    setHTML('activity', s.activity);
    // s.played is always page 1 -- patching it while looking at an older page
    // of history would silently swap what's on screen for something else
    // every 8 seconds, so this only runs on page 1 (no ?page=, or page=1).
    const playPage = new URLSearchParams(location.search).get('page');
    if (!playPage || playPage === '1') setHTML('played', s.played);
    if (s.total_players != null) {
      const t = $('totalplayers');
      if (t) t.textContent = s.total_players === 0 ? 'nobody playing'
             : (s.total_players + (s.total_players === 1 ? ' player' : ' players') + ' online');
    }
    if (s.you) {
      expiresAt = s.you.expires != null ? Date.now() + s.you.expires * 1000 : null;
      const pill = $('you-pill');
      if (pill) {
        pill.textContent = s.you.allowed ? 'can play' : 'blocked';
        pill.className = 'pill ' + (s.you.allowed ? 'on' : 'off');
      }
      if (!s.you.allowed) {
        setHTML('you-ttl', '');
        setClass('you-ttl', 'ttl');
        setHTML('you-warn', BLOCKED);
      } else {
        paintTtl(s.you.expires);
      }
    }
    const b = $('livebar');
    if (b) { b.textContent = 'live'; b.className = 'live'; }
  }

  poll();
  setInterval(poll, 8000);
  // Catch up straight away when you come back to the tab.
  document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
})();

// ------------------------------------------------------------- health gauges
//
// Repaints the numbers, the bars and the traces from each poll. The history is
// only ever what this page has seen, so the graph fills in over the first few
// minutes rather than pretending to know what happened before you arrived.

function fmtBytes(n) {
  if (n == null) return '?';
  const units = ['B', 'kB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i < 2 ? n.toFixed(0) : n.toFixed(1)) + ' ' + units[i];
}

function setGauge(key, value, frac, note, warn, danger) {
  const v = document.getElementById('g-' + key);
  if (v && v.textContent !== value) v.textContent = value;
  if (note != null) {
    const n = document.getElementById('n-' + key);
    if (n && n.textContent !== note) n.textContent = note;
  }
  const bar = document.getElementById('b-' + key);
  if (bar) {
    const pct = Math.max(0, Math.min(1, frac || 0));
    const fill = bar.firstElementChild;
    if (fill) fill.style.width = (pct * 100).toFixed(1) + '%';
    const level = pct >= (danger != null ? danger : 0.9) ? 'bad'
                : pct >= (warn != null ? warn : 0.75) ? 'warn' : 'ok';
    const box = bar.closest('.gauge');
    if (box && !box.classList.contains(level)) {
      box.classList.remove('ok', 'warn', 'bad');
      box.classList.add(level);
    }
  }
  const svg = document.querySelector('svg[data-trace="' + key + '"]');
  if (svg) drawTrace(svg, key, 1);
}

function updateHealth(h, totalPlayers) {
  const cores = h.cores || 1;
  const load = parseFloat(h.load);
  if (isFinite(load)) {
    pushSample('load', load / cores);
    setGauge('load', h.load, load / cores);
  }
  if (h.mem_used && h.mem_total) {
    const f = h.mem_used / h.mem_total;
    pushSample('mem', f);
    setGauge('mem', fmtBytes(h.mem_used), f, 'of ' + fmtBytes(h.mem_total));
  }
  if (h.disk_used && h.disk_total) {
    const f = h.disk_used / h.disk_total;
    pushSample('disk', f);
    setGauge('disk', fmtBytes(h.disk_used), f, 'of ' + fmtBytes(h.disk_total));
  }
  if (h.sent != null) {
    const allowance = 10 * Math.pow(1024, 4);
    const f = h.sent / allowance;
    pushSample('sent', f);
    setGauge('sent', fmtBytes(h.sent), f);
  }
  if (totalPlayers != null && h.seats) {
    const f = totalPlayers / h.seats;
    pushSample('players', f);
    setGauge('players', String(totalPlayers), f, 'of ' + h.seats +
             ' seats across four servers', 1.1, 1.2);
  }
}
