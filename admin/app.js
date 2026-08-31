// The admin UI's behaviour, in its own file on purpose.
//
// This used to live inside a Python triple-quoted string. Python resolved the
// \" escapes in it before the browser ever saw it, so a line that read
//     "<img src=\"" + o.dataset.img + "\">"
// was served as
//     "<img src="" + o.dataset.img + "">"
// which is a syntax error, which meant NOT ONE LINE of script ever ran on the
// live site — no image dropdowns, no tabs, no live updates, no copy button.
// The page still worked, because everything here is an enhancement over
// markup that stands up on its own, so nothing looked broken from the server.
//
// Kept as a real .js file it is syntax-checked before every deploy, and there
// is no escaping layer left to corrupt it.

// A native <select> cannot hold images — there is no markup for it. So dress a
// real one with a custom listbox and keep the select as the actual value, which
// means this degrades to a working plain dropdown if the script never runs.
function buildPickers() {
  document.querySelectorAll("select[data-picker]").forEach(sel => {
    if (sel.dataset.built) return;
    sel.dataset.built = "1";
    sel.hidden = true;

    const wrap = document.createElement("div");
    wrap.className = "picker";
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "picktrigger";
    btn.setAttribute("aria-haspopup", "listbox");
    btn.setAttribute("aria-expanded", "false");
    const list = document.createElement("div");
    list.className = "picklist";
    list.setAttribute("role", "listbox");
    list.hidden = true;

    const label = o => {
      const img = o.dataset.img
        ? '<img src="' + o.dataset.img + '" alt="" loading="lazy">'
        : '<i class="picknone" aria-hidden="true"></i>';
      return img + "<span>" + o.textContent + "</span>";
    };
    const paint = () => {
      const o = sel.options[sel.selectedIndex];
      btn.innerHTML = o ? label(o) + '<i class="chev" aria-hidden="true"></i>' : "";
    };
    const close = () => {
      list.hidden = true;
      btn.setAttribute("aria-expanded", "false");
    };

    Array.from(sel.options).forEach((o, i) => {
      const row = document.createElement("div");
      row.className = "pickitem";
      row.setAttribute("role", "option");
      row.innerHTML = label(o);
      row.onclick = () => {
        sel.selectedIndex = i;
        sel.dispatchEvent(new Event("change", {bubbles: true}));
        paint();
        close();
        btn.focus();
      };
      list.appendChild(row);
    });

    const mark = () => {
      Array.from(list.children).forEach((row, i) =>
        row.setAttribute("aria-selected", i === sel.selectedIndex ? "true" : "false"));
    };

    btn.onclick = e => {
      e.preventDefault();
      if (list.hidden) {
        document.querySelectorAll(".picklist").forEach(l => { if (l !== list) l.hidden = true; });
        list.hidden = false;
        btn.setAttribute("aria-expanded", "true");
        mark();
        const cur = list.children[sel.selectedIndex];
        if (cur) cur.scrollIntoView({block: "nearest"});
      } else {
        close();
      }
    };

    btn.onkeydown = e => {
      if (e.key === "Escape") close();
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        const n = sel.selectedIndex + (e.key === "ArrowDown" ? 1 : -1);
        if (n >= 0 && n < sel.options.length) {
          sel.selectedIndex = n;
          sel.dispatchEvent(new Event("change", {bubbles: true}));
          paint();
          mark();
        }
      }
    };

    document.addEventListener("click", e => { if (!wrap.contains(e.target)) close(); });
    sel.parentNode.insertBefore(wrap, sel);
    wrap.appendChild(btn);
    wrap.appendChild(list);
    wrap.appendChild(sel);
    paint();
  });
}

// Tabs. With no script every panel simply shows, which is the old layout and
// is still perfectly usable.
//
// The selected tab survives a reload, because every control on this page is a
// form that POSTs and redirects. Add a bot from the Bots tab and you came back
// to Play, having to find your way back to where you already were, once per
// bot. The tab is part of where you are, so it belongs in the URL: ?tab=bots
// is shareable, survives the redirect, and back/forward do the right thing.
function tabKey(bar) {
  return bar.getAttribute("data-tabs") || "tab";
}

function selectTab(bar, btn, push) {
  const btns = Array.from(bar.querySelectorAll(".tab"));
  btns.forEach(o => {
    const on = o === btn;
    o.classList.toggle("here", on);
    o.setAttribute("aria-selected", on ? "true" : "false");
    const panel = document.getElementById(o.dataset.tab);
    if (panel) panel.toggleAttribute("data-hide", !on);
  });
  buildPickers();   // a panel revealed for the first time needs dressing
  if (push) {
    try {
      const u = new URL(window.location.href);
      u.searchParams.set(tabKey(bar), btn.dataset.tab || "");
      history.replaceState(null, "", u);
    } catch (e) { /* file:// and friends; the tab still works */ }
  }
}

function buildTabs() {
  document.querySelectorAll(".tabs").forEach(bar => {
    const btns = Array.from(bar.querySelectorAll(".tab"));
    btns.forEach(b => { b.onclick = () => selectTab(bar, b, true); });

    // Restore from the URL, and carry it onto every form in the panels so a
    // POST redirect comes back to the same tab.
    let want = null;
    try { want = new URL(window.location.href).searchParams.get(tabKey(bar)); }
    catch (e) { want = null; }
    const match = want && btns.find(b => b.dataset.tab === want);
    if (match) selectTab(bar, match, false);

    const current = () => {
      const on = btns.find(b => b.getAttribute("aria-selected") === "true");
      return on ? on.dataset.tab : "";
    };
    btns.forEach(b => {
      const panel = document.getElementById(b.dataset.tab);
      if (!panel) return;
      panel.querySelectorAll("form").forEach(f => {
        f.addEventListener("submit", () => {
          let h = f.querySelector("input[name=tab]");
          if (!h) {
            h = document.createElement("input");
            h.type = "hidden";
            h.name = "tab";
            f.appendChild(h);
          }
          h.value = current();
        });
      });
    });
  });
}

function copyAddr(id, btn) {
  const text = document.getElementById(id).textContent;
  const done = () => {
    const original = btn.textContent;
    btn.textContent = "Copied";
    btn.classList.add("copied");
    setTimeout(() => { btn.textContent = original; btn.classList.remove("copied"); }, 1200);
  };
  // navigator.clipboard needs a secure context; this page always is, but the
  // fallback keeps it working if that ever stops being true.
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(done, done);
    return;
  }
  const area = document.createElement("textarea");
  area.value = text;
  document.body.appendChild(area);
  area.select();
  try { document.execCommand("copy"); } catch (e) { /* nothing better to offer */ }
  document.body.removeChild(area);
  done();
}

// Behaviour that used to be an onclick= / onsubmit= attribute in the markup.
//
// Those two attributes were the only reason the page's CSP had to allow
// 'unsafe-inline' for scripts, which is the directive that turns any HTML
// injection into code execution. Every value on the page is escaped, so there
// was no known way in — but the whole point of the header is to not have to be
// sure of that. Moved here, the script sources are two known blocks that the
// CSP can name by hash, and inline script is refused outright.
//
// Delegated from the document rather than bound per element, so anything
// re-rendered later is covered without rebinding.
function bindDelegates() {
  document.addEventListener("click", e => {
    const btn = e.target.closest("[data-copy]");
    if (btn) copyAddr(btn.dataset.copy, btn);
  });

  document.addEventListener("submit", e => {
    const form = e.target.closest("form[data-confirm]");
    if (form && !confirm(form.dataset.confirm)) e.preventDefault();
  });
}

// Each of these independently, and navigation FIRST.
//
// They ran as four bare calls in a row, so an exception in any one of them
// took out every one after it — and keepNavigationInApp was last, which is the
// one whose absence is most visible: without it, added to the Home Screen,
// every link in the nav hands itself to the browser and throws a sheet with
// "Done" over the app. A picker failing to find an image should not cost you
// the ability to navigate.
function safely(fn) {
  try { fn(); } catch (e) { /* one broken piece, not four */ }
}

// A trackpad already sends horizontal delta on a two-finger swipe, and
// touch-scrolling nav needs nothing extra either -- both already work with
// plain overflow-x. This is for a plain vertical mouse wheel over the game
// list on desktop: without it, the only way to reach a game past the edge is
// to know it's a drag-scroll target and grab it, which nothing tells you.
function wireHorizontalWheelScroll(el) {
  el.addEventListener("wheel", e => {
    // Already-horizontal input (trackpad swipe) — leave it alone.
    if (Math.abs(e.deltaX) >= Math.abs(e.deltaY)) return;
    if (el.scrollWidth <= el.clientWidth) return;   // nothing to scroll
    e.preventDefault();
    el.scrollLeft += e.deltaY;
  }, {passive: false});
}

document.addEventListener("DOMContentLoaded", () => {
  safely(keepNavigationInApp);
  safely(buildPickers);
  safely(buildTabs);
  safely(buildPullToRefresh);
  safely(bindDelegates);
  safely(notifyInit);
  safely(() => {
    const nav = document.querySelector("nav");
    if (nav) wireHorizontalWheelScroll(nav);
  });
});

// ------------------------------------------------------------ notifications
//
// #5, docs/adr/0002. The service worker exists only to receive push (sw.js),
// and everything about SUBSCRIBING to it is here rather than there, because
// a service worker cannot ask the user for permission or read the page's own
// origin -- it can only be told, from a tab, what to register for.

// The applicationServerKey the browser wants is raw bytes, and the box hands
// out base64url. Nothing in the platform converts one to the other.
function urlB64ToUint8Array(b64) {
  const pad = "=".repeat((4 - (b64.length % 4)) % 4);
  const raw = atob((b64 + pad).replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function postForm(path, fields) {
  return fetch(path, {
    method: "POST",
    headers: {"Content-Type": "application/x-www-form-urlencoded"},
    body: new URLSearchParams(fields).toString(),
  });
}

// iOS delivers Web Push only to a Home Screen app, 16.4 and later, never to
// a Safari tab -- ADR 0002 names this rather than leaving it to be
// discovered as "the button did nothing". iPadOS reports as Mac in its user
// agent since 13, and is told apart by having touch points a real Mac does
// not.
function iosNeedsHomeScreen() {
  const ua = navigator.userAgent || "";
  const ios = /iP(hone|ad|od)/.test(ua) ||
              (navigator.platform === "MacIntel" && (navigator.maxTouchPoints || 0) > 1);
  return ios && !isStandalone();
}

function setNotifyState(btn, on) {
  btn.disabled = false;
  btn.className = on ? "on" : "";
  btn.textContent = on ? "Notifications on — tap to turn off" : "Notify this device";
}

async function notifyInit() {
  const btn = document.getElementById("notify-btn");
  if (!btn) return;                       // not on this page
  if (!("serviceWorker" in navigator) || !("PushManager" in window) || !window.isSecureContext) {
    btn.textContent = "Not supported in this browser";
    return;
  }
  if (iosNeedsHomeScreen()) {
    btn.textContent = "Add to Home Screen first";
    const hint = document.getElementById("notify-hint");
    if (hint) hint.textContent = "iOS only delivers these to an app added to " +
                                 "the Home Screen — not to a Safari tab.";
    return;
  }
  if (Notification.permission === "denied") {
    btn.textContent = "Blocked in this browser's settings";
    return;
  }
  try {
    const reg = await navigator.serviceWorker.register("/pwa/sw.js");
    const sub = await reg.pushManager.getSubscription();
    setNotifyState(btn, !!sub);
  } catch (e) {
    btn.textContent = "Could not check";
  }
  btn.addEventListener("click", toggleNotify);
}

async function toggleNotify(e) {
  const btn = e.currentTarget;
  if (btn.disabled) return;
  btn.disabled = true;
  const was = btn.textContent;
  try {
    const reg = await navigator.serviceWorker.register("/pwa/sw.js");
    const existing = await reg.pushManager.getSubscription();
    if (existing) {
      await postForm("/unsubscribe", {endpoint: existing.endpoint});
      await existing.unsubscribe();
      setNotifyState(btn, false);
      return;
    }
    const perm = await Notification.requestPermission();
    if (perm !== "granted") {
      btn.disabled = false;
      btn.textContent = "Blocked — allow notifications for this site";
      return;
    }
    const keyResp = await fetch("/api/vapid-key");
    const {key} = await keyResp.json();
    if (!key) {
      btn.disabled = false;
      btn.textContent = "This box cannot sign notifications";
      return;
    }
    const sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlB64ToUint8Array(key),
    });
    const r = await postForm("/subscribe", {sub: JSON.stringify(sub.toJSON())});
    if (!r.ok) {
      await sub.unsubscribe();
      throw new Error("subscribe rejected");
    }
    setNotifyState(btn, true);
  } catch (e) {
    btn.disabled = false;
    btn.textContent = was === "Notifications on — tap to turn off" ? was
                     : "Could not enable — try again";
  }
}

// ---------------------------------------------------------------- sparklines
//
// Live traces under the health gauges. Written by hand rather than pulled from
// a charting library: the page's CSP is `default-src 'none'` and every asset is
// served from this box, so a CDN would be blocked and vendoring a library would
// mean carrying a few hundred kilobytes of somebody else's code into a machine
// whose whole security story is "nothing gets in". This is sixty lines and
// draws an SVG path.
//
// History lives in the page, not on the server: nothing to store, nothing to
// grow without bound, and a reload starts a fresh window. That is the right
// trade for a page you open to see what is happening right now.

const TRACE_POINTS = 45;          // at one sample per poll, six minutes of it
const traces = {};

function pushSample(key, value) {
  if (value == null || !isFinite(value)) return;
  (traces[key] = traces[key] || []).push(value);
  if (traces[key].length > TRACE_POINTS) traces[key].shift();
}

// A path through the samples, scaled to the box. `ceiling` fixes the top of the
// scale so a trace does not silently rescale itself and make a flat line look
// dramatic; pass null to let it fit what it has.
function tracePath(values, w, h, ceiling) {
  if (!values.length) return "";
  const top = ceiling != null ? ceiling : Math.max(...values, 0.0001);
  const span = Math.max(top, 0.0001);
  const step = values.length > 1 ? w / (values.length - 1) : w;
  return values.map((v, i) => {
    const x = i * step;
    const y = h - Math.max(0, Math.min(1, v / span)) * h;
    return (i ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1);
  }).join(" ");
}

function drawTrace(el, key, ceiling) {
  const values = traces[key];
  if (!el || !values || values.length < 2) return;
  const w = 100, h = 26;
  const line = tracePath(values, w, h, ceiling);
  // The same path closed along the bottom, for a soft fill under the line.
  const last = (values.length - 1) * (w / (values.length - 1 || 1));
  const area = line + " L" + last.toFixed(1) + " " + h + " L0 " + h + " Z";
  el.setAttribute("viewBox", "0 0 " + w + " " + h);
  el.setAttribute("preserveAspectRatio", "none");
  el.innerHTML =
    '<path class="trace-fill" d="' + area + '"/>' +
    '<path class="trace-line" d="' + line + '"/>';
}

// --------------------------------------------------------------- standalone
//
// Added to the Home Screen, this runs with no browser chrome: no address bar,
// no back button, and no pull-to-refresh. Everything below only applies there
// — in a normal tab the browser already does all of it, and doing it twice is
// how you get a page that fights the user.
function isStandalone() {
  // navigator.standalone is the iOS one and is what matters here. The
  // display-mode query is checked too but guarded: it is the newer of the two
  // and this must not be the thing that throws.
  if (window.navigator && window.navigator.standalone === true) return true;
  try {
    return !!(window.matchMedia && window.matchMedia("(display-mode: standalone)").matches);
  } catch (e) {
    return false;
  }
}

// Pull down to refresh, because without browser chrome there is no other way
// to ask for fresh numbers, and this page is mostly numbers.
function buildPullToRefresh() {
  if (!isStandalone()) return;

  const bar = document.createElement("div");
  bar.className = "ptr";
  bar.innerHTML = "<span class=ptr-spin></span>";
  document.body.appendChild(bar);

  const TRIGGER = 70;      // far enough that a scroll gesture cannot trip it
  const MAX = 110;
  let startY = null, pulled = 0, busy = false;

  const reset = () => {
    bar.style.transform = "";
    bar.classList.remove("ptr-armed", "ptr-live");
    pulled = 0; startY = null;
  };

  document.addEventListener("touchstart", e => {
    // Only from the very top, and never mid-gesture or during a refresh.
    if (busy || e.touches.length !== 1) return;
    if ((window.scrollY || document.documentElement.scrollTop) > 0) return;
    startY = e.touches[0].clientY;
  }, {passive: true});

  document.addEventListener("touchmove", e => {
    if (startY === null || busy) return;
    const dy = e.touches[0].clientY - startY;
    if (dy <= 0) { reset(); return; }
    // Resisted, so it feels like pulling against something rather than a
    // free-running element that shoots off the screen.
    pulled = Math.min(MAX, dy * 0.5);
    bar.style.transform = "translateY(" + pulled + "px)";
    bar.classList.add("ptr-live");
    bar.classList.toggle("ptr-armed", pulled >= TRIGGER);
  }, {passive: true});

  document.addEventListener("touchend", () => {
    if (startY === null || busy) return;
    if (pulled >= TRIGGER) {
      busy = true;
      bar.classList.add("ptr-armed");
      bar.style.transform = "translateY(" + TRIGGER + "px)";
      window.location.reload();
      return;
    }
    reset();
  }, {passive: true});
}

// Keep navigation inside the app.
//
// iOS opens a link in Safari the moment it leaves the manifest scope, and once
// it has, the standalone window is left behind on whatever page it was showing.
// Cloudflare Access logging you back in is exactly that: a hop to
// <team>.cloudflareaccess.com and back. Nothing here can keep a cross-origin
// login inside the app, but same-origin links can be made to navigate in place
// rather than being handed to the browser, which is the case that was actually
// breaking.
function keepNavigationInApp() {
  if (!isStandalone()) return;
  // Capture phase, so this runs before anything else can act on the click.
  document.addEventListener("click", e => {
    // closest() from the event target, which may be an <img> inside the link —
    // every game entry in the nav is exactly that.
    const node = e.target && e.target.nodeType === 3 ? e.target.parentNode : e.target;
    const a = node && node.closest ? node.closest("a[href]") : null;
    if (!a) return;
    if (a.target === "_blank" || a.hasAttribute("download")) return;
    if (e.defaultPrevented) return;
    if (e.metaKey || e.ctrlKey || e.shiftKey || (e.button && e.button !== 0)) return;
    const href = a.getAttribute("href") || "";
    if (href.charAt(0) === "#") return;          // in-page anchor, not a navigation
    let url;
    try { url = new URL(a.href, window.location.href); } catch (err) { return; }
    if (url.origin !== window.location.origin) return;   // deliberately leaves
    e.preventDefault();
    window.location.assign(url.href);
  }, true);
}
