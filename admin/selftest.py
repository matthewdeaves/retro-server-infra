#!/usr/bin/env python3
"""Drive the admin UI over real HTTP, on the box, with Access stubbed out.

Run it with `retro selftest`, which uploads it alongside a candidate
retro-admin.py and runs it there — it needs the game content to be present, so
it cannot usefully run on a laptop.

Why it exists: the one bug that ever reached the live site was a 502 on the
first successful render, from code that had only ever been exercised down its
refusal path. Checking that a request without a token is refused proves very
little. This asks for every page as an authenticated caller would, then fetches
every image those pages reference and checks it actually decodes to bytes.

Exits non-zero on any failure, so it can gate a deploy.
"""
import html
import importlib.util
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request

PORT = 8099
MODULE = sys.argv[1] if len(sys.argv) > 1 else "/opt/retro-admin/retro-admin.py"

os.environ["STATE_DIRECTORY"] = "/tmp/retro-selftest-state"
os.makedirs(os.environ["STATE_DIRECTORY"], exist_ok=True)

spec = importlib.util.spec_from_file_location("ra", MODULE)
ra = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ra)

# Stand in for Cloudflare Access. Everything behind it is what we want to test;
# the verification itself is exercised at the end.
ra.verify_access = lambda token: "selftest@example.invalid"

server = ra.Server(("127.0.0.1", PORT), ra.Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
time.sleep(0.4)

FAILURES = []


def check(label, ok):
    print("  %-56s %s" % (label, "ok" if ok else "FAIL"))
    if not ok:
        FAILURES.append(label)


def get(path, timeout=120):
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (PORT, path),
                                 headers={"Cf-Access-Jwt-Assertion": "stub"})
    with urllib.request.urlopen(req, timeout=timeout) as f:
        return f.status, f.read()


# ---------------------------------------------------------------- every page
pages = {}
for path in ["/", "/access", "/activity"] + ["/game/%s" % g for g in ra.GAMES]:
    try:
        code, body = get(path)
    except Exception as exc:
        print("  %-56s FAIL (%s)" % (path, exc))
        FAILURES.append(path)
        continue
    print("  %-40s %s %7d bytes" % (path, code, len(body)))
    if code != 200:
        FAILURES.append("%s returned %s" % (path, code))
    pages[path] = body.decode("utf-8", "replace")

# ---------------------------------------------------------------- the CSP
# The page carries its script inline and the CSP names it by hash, so if the
# bytes between the tags are not EXACTLY what was hashed the browser refuses to
# run any of it. Nothing about that is visible from the server: the markup is
# right, the response is 200, and every enhancement on the page quietly stops —
# which is precisely the failure mode of the escaping bug that put this script
# in its own file in the first place.
req = urllib.request.Request("http://127.0.0.1:%d/" % PORT,
                             headers={"Cf-Access-Jwt-Assertion": "stub"})
with urllib.request.urlopen(req, timeout=60) as f:
    CSP = f.headers.get("Content-Security-Policy", "")

script_src = ""
for part in CSP.split(";"):
    if part.strip().startswith("script-src"):
        script_src = part.strip()

check("the CSP refuses arbitrary inline script",
      bool(script_src) and "'unsafe-inline'" not in script_src)

inline = []
for body in pages.values():
    inline += re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", body, re.S)
unnamed = [b for b in inline
           if ra._csp_sha256(b) not in script_src]
check("every inline script is named by the CSP (%d block(s))" % len(inline),
      bool(inline) and not unnamed)

# `default-src 'none'` is a deny-all, and every kind of subresource the page
# pulls needs its own directive or it is refused. The manifest was refused for
# exactly this reason for weeks: the HTML linked it, the server served it, and
# the browser dropped it on the floor with a console message nobody was reading.
# So assert the directive exists for anything the page actually asks for.
for attr, directive in (("rel=manifest", "manifest-src"),):
    linked = any(attr in body for body in pages.values())
    check("the CSP allows the %s the page links" % directive.split("-")[0],
          not linked or any(part.strip().startswith(directive)
                            for part in CSP.split(";")))

# An on*= attribute is inline script too, and the hashed CSP refuses it. It
# would look perfectly correct in the markup and simply never fire.
#
# Only the markup: the scripts are inlined into the same document, so scanning
# the whole body finds every mention of "onclick=" in their comments too. The
# first run of this check failed on a comment explaining why there are no
# inline handlers left.
def markup_only(body):
    return re.sub(r"<(script|style)\b[^>]*>.*?</\1>", "", body, flags=re.S)


handlers = sorted({m for body in pages.values()
                   for m in re.findall(r"<[^>]*?\s(on[a-z]+)=", markup_only(body))})
check("no inline event handlers in the markup", not handlers)
if handlers:
    print("      the CSP will refuse: %s" % ", ".join(handlers))

# ------------------------------------------------------------------ artwork
# Not a count: the icons appear in the nav as well as on the bays, so counting
# was a check on the layout rather than on the artwork.
check("overview shows an icon for every game",
      all("/emblem/%s.png" % g in pages.get("/", "") for g in ra.GAMES))
for game in ra.GAMES:
    check("%s has an icon" % game, bool(ra.emblem_png(game)))

for game in ra.GAMES:
    body = pages.get("/game/%s" % game, "")
    # Only the map dropdown. Scraping every <option> on the page also picks up
    # the bot roster and the skill choices, which made Quake III look as though
    # it listed 68 maps.
    picker = re.search(r"<select name=map\b.*?</select>", body, re.S)
    listed = re.findall(r"<option value='([^']+)'",
                        picker.group(0) if picker else "")
    shots = [m for m in listed if ra.map_shot_png(game, m)]
    tiles = body.count("class='shot")
    if ra.GAMES[game].get("has_shots"):
        check("%s: every listed map that has a picture shows one (%d)"
              % (game, len(shots)), tiles == len(shots) and tiles > 0)
    elif ra.GAMES[game].get("has_plans"):
        # These two ship no artwork, so the picture is a floorplan drawn from
        # the level's own geometry. Assert most of them render rather than all:
        # a map whose BSP yields fewer than four upward faces gets no plan on
        # purpose, and one unrenderable level should not fail the suite.
        check("%s: floorplans drawn for its levels (%d of %d listed)"
              % (game, len(shots), len(listed)),
              bool(listed) and len(shots) >= max(1, int(len(listed) * 0.8))
              and tiles == len(shots))
    else:
        check("%s: offers no level pictures, and claims none" % game,
              tiles == 0 and "/shot/%s/" % game not in body)

    titles = ra.map_titles(game)
    named = [m for m in listed if m in titles]
    if ra.GAMES[game].get("has_titles"):
        # Compare against escaped text: "Tokay's Towers" reaches the page as
        # "Tokay&#x27;s Towers", and comparing the raw string failed on it.
        # "at least one listed map has a name" is mode-dependent and therefore
        # wrong: Quake III takes its names from .arena longnames and only five
        # maps have one, none of them CTF. Switching the server to Capture the
        # Flag failed this check on a page that was entirely correct. The real
        # invariant is that the game knows SOME names, and every listed map
        # that has one shows it.
        check("%s: level names reach the dropdown (%d of %d listed)"
              % (game, len(named), len(listed)),
              bool(titles) and all(html.escape("%s — %s" % (m, titles[m])) in body
                                   for m in named))
    else:
        check("%s: no level names offered" % game, not titles)

check("half-life never claims the Black Mesa Inbound name",
      "Black Mesa Inbound" not in pages.get("/game/halflife", ""))
check("quake III still lists its bots",
      pages.get("/game/quake3", "").count("/icon/quake3/") >= 32)

# Anything the HTML points at has to resolve — a broken <img> is invisible in
# a log and obvious on a phone.
refs = sorted({m for body in pages.values() for m in
               re.findall(r"(?:src|data-img)='(/(?:emblem|shot|icon)/[^']+)'", body)})
broken = []
for ref in refs:
    try:
        code, data = get(ref)
        if code != 200 or not data:
            broken.append((ref, code, len(data)))
    except Exception as exc:
        broken.append((ref, "exception", str(exc)))
check("all %d referenced images resolve" % len(refs), not broken)
for ref in broken[:10]:
    print("     broken:", ref)

# Cloudflare's Email Obfuscation rewrites any address it finds into a link to
# /cdn-cgi/l/email-protection, which nobody here can open. Every address on
# these pages must therefore sit inside the opt-out, and this has regressed
# twice by being applied one element at a time.
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
leaks = []
for path, body in pages.items():
    inside = body.split("<!--email_off-->")
    outside = inside[0] + "".join(part.split("<!--/email_off-->", 1)[1]
                                  for part in inside[1:] if "<!--/email_off-->" in part)
    found = [e for e in EMAIL.findall(outside) if not e.endswith(".png")]
    if found:
        leaks.append((path, found[:3]))
check("every email address sits inside the obfuscation opt-out", not leaks)
for leak in leaks:
    print("     outside the opt-out:", leak)

# A name that is not a map must not come back as a picture. Quake III falls
# back to id's unknownmap placeholder, so this is easy to get wrong.
try:
    get("/shot/quake3/not_a_real_map.jpg", timeout=20)
    check("a made-up map name is refused", False)
except urllib.error.HTTPError as exc:
    check("a made-up map name is refused (%d)" % exc.code, exc.code == 404)

# ----------------------------------------------------------------- refusal
def _deny(token):
    raise ra.AuthError("selftest")


ra.verify_access = _deny
try:
    urllib.request.urlopen("http://127.0.0.1:%d/" % PORT, timeout=10)
    check("a request without a valid token is refused", False)
except urllib.error.HTTPError as exc:
    check("a request without a valid token is refused (%d)" % exc.code,
          exc.code == 403)

print("\n%s" % ("ALL OK" if not FAILURES else "%d FAILURES" % len(FAILURES)))
sys.exit(1 if FAILURES else 0)
