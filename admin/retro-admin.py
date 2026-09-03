#!/usr/bin/env python3
"""
retro-admin — web UI for the four retro game servers.

Binds 127.0.0.1 only and is reachable exclusively through the Cloudflare
tunnel, so Access has authenticated the caller before any request arrives.
There is deliberately no login here. That is not the same as trusting blindly:

  * The Access assertion is VERIFIED, not read. Cloudflare signs a JWT with
    keys published at the team domain; signature, issuer and audience are all
    checked on every request. The plaintext Cf-Access-Authenticated-User-Email
    header is never trusted — it would be forgeable the moment anyone exposed
    port 8080 to debug something.

  * State-changing requests check Origin. Access authenticates with a cookie
    and browsers attach cookies to cross-site form posts, so without this any
    page on the internet could restart a server while you had a live session.

  * Every granted address expires. Grants are written into nftables sets with
    a kernel-enforced timeout, so an address opens and closes itself even if
    this process dies.

Why the allowlist exists at all: Cloudflare protects THIS page but cannot
protect the games — proxying UDP needs Spectrum, an Enterprise product. So the
game ports face the internet directly, and the allowlist is all that stands in
front of them. All four engines answer unauthenticated status queries with far
more than they were asked for — Half-Life measures 101x — so an open port is a
usable DDoS reflector firing under Oracle's addresses. Quake II, Quake III and
Half-Life each carry a per-address query limiter of their own now; QuakeSpasm
carries none, and none of the four throttle joining. Those limiters are a
second layer, not a replacement for this allowlist.
"""
import base64
import bisect
import glob
import hashlib
import hmac
import html
import ipaddress
import json
import os
import random
import re
import socket
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

ALLOW_TTL = os.environ.get("RETRO_ALLOW_TTL", "12h")
# .invalid is reserved (RFC 2606) and guaranteed never to resolve, so an
# unconfigured deployment fails obviously instead of quietly pointing at
# somebody else's real domain.
TEAM_DOMAIN = os.environ.get("RETRO_TEAM_DOMAIN", "your-team.cloudflareaccess.com")
ACCESS_AUD = os.environ.get("RETRO_ACCESS_AUD", "")
# The same two addresses Cloudflare's policy names, enforced again here.
#
# Not redundant. Cloudflare decides WHO gets a token; this file decides who is
# allowed in once they have one, and the two decisions should not be the same
# decision made twice in one place. Verifying the signature, the audience and
# the issuer proves a token was minted by Cloudflare for THIS application — it
# does not prove the policy behind that application still says what it said
# when it was written. A second policy added to the app in the dashboard, or an
# include rule widened by a stray Terraform apply, would mint perfectly valid
# tokens for somebody else and every check above would pass them.
#
# So the list lives in two places on purpose, and an address has to be in both.
ADMIN_EMAILS = frozenset(
    e.strip().lower()
    for e in os.environ.get("RETRO_ADMIN_EMAILS", "").split(",")
    if e.strip()
)
PUBLIC_HOST = os.environ.get("RETRO_PUBLIC_HOST", "admin.example.invalid")
GAMES_HOST = os.environ.get("RETRO_GAMES_HOST", "games.example.invalid")
STATE_DIR = os.environ.get("STATE_DIRECTORY", "/var/lib/retro-admin")
GRANTS_FILE = os.path.join(STATE_DIR, "grants.json")
CERTS_URL = "https://%s/cdn-cgi/access/certs" % TEAM_DOMAIN

try:
    import jwt as _jwt
    from jwt import PyJWKClient
    _jwks = PyJWKClient(CERTS_URL, cache_keys=True)
except Exception:                                    # pragma: no cover
    _jwt = None
    _jwks = None


# ---------------------------------------------------------------------------
# Game table.
#
# `mapcmd` is not cosmetic. Quake and Half-Life MUST use changelevel: their
# `map` calls CL_Disconnect() first and drops every player
# (Quake/host_cmd.c:850), while changelevel is commented "Goes to a new map,
# taking all clients along" (:921). Quake III carries clients through `map`
# (code/server/sv_init.c:535). Quake II's gamemap broadcasts a reconnect.
#
# Every mode preset sets a LATCHED cvar, which does nothing until the level
# reloads, so applying a mode always ends with a map change.
#
# `settings` are the per-game knobs each engine actually supports. They differ
# because the engines differ — Quake III has capturelimit and a bot skill,
# Quake has a skill cvar that Quake III does not, Half-Life prefixes
# everything mp_.
# ---------------------------------------------------------------------------
GAMES = {
    "quake": {
        "label": "Quake", "unit": "quakespasm-server", "port": 26000,
        "has_plans": True,
        "repo": "old-mac-quakespasm",
        "accent": "var(--quake)",
        "fifo": "/run/quakespasm-server/console", "mapcmd": "changelevel",
        "dir": "/opt/quakespasm-server/id1", "paks": "*.pak",
        "has_titles": True,   # worldspawn "message", verified correct
        # server.cfg sets deathmatch 1 / coop 0 / teamplay 0, and NetQuake
        # does not report a gametype, so this is the honest starting guess.
        "default_mode": "dm",
        "campaign_start": "start",
        "modes": {
            "dm":   ("Deathmatch", ["deathmatch 1", "coop 0", "teamplay 0"]),
            "team": ("Team play",  ["deathmatch 1", "coop 0", "teamplay 2"]),
            "coop": ("Co-op",      ["coop 1", "deathmatch 0", "teamplay 0"]),
        },
        "settings": [
            ("fraglimit", "Frag limit", "int", (0, 200)),
            ("timelimit", "Time limit (min)", "int", (0, 120)),
            ("skill", "Skill", "choice", [("0", "Easy"), ("1", "Normal"),
                                          ("2", "Hard"), ("3", "Nightmare")]),
            ("noexit", "Block level exit", "bool", None),
            # Movement house-rules. Live, no restart -- QuakeSpasm's own
            # CVAR_NOTIFY broadcasts the new value to every connected player
            # the moment it changes (host.c, Host_Callback_Notify), so unlike
            # most of this panel these actually announce themselves.
            ("sv_gravity", "Gravity", "int", (0, 3200)),      # default 800
            ("sv_friction", "Friction", "int", (0, 16)),      # default 4
            ("sv_maxspeed", "Max speed", "int", (0, 1000)),   # default 320
            ("sv_accelerate", "Acceleration", "int", (0, 50)),# default 10
            ("pausable", "Players may pause", "bool", None),  # default on
        ],
    },
    "quake2": {
        "label": "Quake II", "unit": "q2ded", "port": 27910,
        "has_plans": True,
        "repo": "old-mac-quake2",
        "accent": "var(--quake2)",
        "fifo": "/run/quake2-server/console", "mapcmd": "gamemap",
        "dir": "/opt/quake2-server/baseq2", "paks": "*.pak",
        "has_titles": True,   # worldspawn "message" — "The Edge", "Lava Tomb"
        # Written to baseq2/mode.cfg, which server.cfg execs last, and applied
        # by restarting the unit. A console `set` cannot work here: coop and
        # deathmatch are latched, Cvar_GetLatchedVars() runs only in
        # SV_InitGame, and a running server's gamemap skips straight to
        # SV_SpawnServer. See sv_init.c:332.
        "mode_needs_restart": True,
        "mode_file": "/opt/quake2-server/baseq2/mode.cfg",
        # Settings that share mode.cfg's restart mechanism because the
        # engine only reads them at CVAR_LATCH time (server/sv_main.c:621
        # for maxclients, game/savegame/savegame.c for skill -- both
        # verified CVAR_LATCH). post_set routes these through the same
        # merge-then-restart path post_mode uses, not a live console `set`.
        "restart_settings": {"maxclients", "skill"},
        "campaign_start": "base1",
        "modes": {
            "dm":   ("Deathmatch", ["set deathmatch 1", "set coop 0"]),
            "coop": ("Co-op",      ["set coop 1", "set deathmatch 0"]),
        },
        "settings": [
            ("fraglimit", "Frag limit", "int", (0, 200)),
            ("timelimit", "Time limit (min)", "int", (0, 120)),
            ("dmflags", "Rules", "bits", [
                (4,     "Weapons stay"),
                (16,    "Instant items"),
                (8,     "No falling damage"),
                (2048,  "No armour"),
                (1,     "No health"),
                (8192,  "Infinite ammo"),
                (16384, "Quad drops on death"),
                (1024,  "Force respawn"),
                (512,   "Spawn farthest"),
                (256,   "No friendly fire"),
                (4096,  "Allow exit"),
            ]),
            # password/spectator_password are CVAR_USERINFO, not CVAR_NOSET --
            # plain `set`, no special ACL beyond rcon_password itself
            # (savegame.c:290-291). needpass is CVAR_SERVERINFO and derived
            # automatically from these two (g_main.c:341-361); it is not
            # listed here because it is read-only -- setting it directly
            # would just be overwritten on the next password change.
            ("password", "Join password", "text", None),
            ("spectator_password", "Spectator password", "text", None),
            # Default is 1 (blocklist) at the engine, verified against
            # savegame.c:293 -- `gi.cvar("filterban", "1", 0)` -- not 0 as
            # first reported. Off flips addip/removeip into an allowlist
            # instead of a blocklist (g_svcmds.c:179-183).
            ("filterban", "IP list blocks (off: IP list is the only ones allowed)",
             "bool", None),
            # Space/comma/newline-separated map names, in the order the
            # rotation plays them (verified against the actual separator set
            # in EndDMLevel, g_main.c:262: " ,\n\r"). When fraglimit or
            # timelimit ends the round and the CURRENT map is found in this
            # list, the next one in the list loads; wrapping to the first at
            # the end. Empty (the default) falls back to the map's own
            # `nextmap` key instead -- one map at a time, same as the map
            # changer already does.
            ("sv_maplist", "Map rotation (space or comma separated)", "text", None),
            # Both CVAR_LATCH -- see restart_settings above. maxclients'
            # engine default is 1 (sv_main.c:621), which is not remotely
            # what a dedicated server actually runs with in practice, so
            # the range floor is 2, not 1: a one-player "multiplayer"
            # server is not a real setting anyone here would choose.
            ("maxclients", "Max players (restarts the server)", "int", (2, 16)),
            ("skill", "Difficulty (restarts the server)", "choice",
             [("0", "Easy"), ("1", "Medium"), ("2", "Hard"), ("3", "Hard+")]),
        ],
    },
    "quake3": {
        "label": "Quake III", "unit": "ioq3ded", "port": 27960,
        "repo": "old-mac-quake3",
        "accent": "var(--quake3)",
        "fifo": "/run/quake3-server/console", "mapcmd": "map",
        "dir": "/opt/quake3-server/baseq3", "paks": "*.pk3",
        "has_titles": True,   # .arena longname
        "has_shots": True,    # levelshots/*.tga
        # Quake III is the only one of the four with bots, which makes it the
        # only one you can meaningfully test on your own. The roster is read
        # from the pk3s rather than listed here.
        "has_bots": True,
        "modes": {
            "ffa":  ("Free for all", ["set g_gametype 0"]),
            "duel": ("Tournament",   ["set g_gametype 1"]),
            "team": ("Team DM",      ["set g_gametype 3"]),
            "ctf":  ("Capture flag", ["set g_gametype 4"]),
            # GT_1FCTF/GT_OBELISK/GT_HARVESTER (bg_public.h:106-108) exist as
            # enum values and g_gametype accepts 5/6/7 without erroring, but
            # do NOT add them here: the actual gameplay code for all three is
            # inside #ifdef MISSIONPACK in g_items.c (flag/obelisk/cube
            # checks and scoring), and this build is compiled with
            # BUILD_MISSIONPACK=0 on purpose (scripts/build-gamedylibs-
            # arm64.sh:57, "we ship baseq3 only"). Verified live on the box,
            # 2026-09-03: setting g_gametype 6 and loading q3dm17 logged
            # "0 teams with 0 entities" -- it runs as deathmatch with no
            # obelisk ever spawning, not an error, just silently pointless.
            # An earlier source-only survey called these "fully implemented,
            # just not in the dropdown" -- that was wrong; it grepped the
            # source tree without checking the build flags actually used.
        },
        "settings": [
            ("fraglimit", "Frag limit", "int", (0, 200)),
            ("timelimit", "Time limit (min)", "int", (0, 120)),
            ("capturelimit", "Capture limit", "int", (0, 50)),
            ("g_friendlyFire", "Friendly fire", "bool", None),
            ("g_weaponrespawn", "Weapon respawn (s)", "int", (0, 60)),
            ("g_motd", "Message of the day", "text", None),
            ("g_password", "Join password", "text", None),
            ("g_allowVote", "Voting enabled", "bool", None),         # default on
            ("g_warmup", "Warmup length (s)", "int", (0, 120)),      # default 20
            ("g_doWarmup", "Warmup before matches", "bool", None),   # default off
            ("g_teamAutoJoin", "Auto-assign new players to a team", "bool", None),
            ("g_teamForceBalance", "Keep teams balanced", "bool", None),
        ],
    },
    "halflife": {
        "label": "Half-Life", "unit": "xash-server", "port": 27015,
        "repo": "old-mac-half-life-1",
        "accent": "var(--halflife)",
        "fifo": "/run/half-life-server/console", "mapcmd": "changelevel",
        "dir": "/opt/half-life-server/valve", "paks": "*.pak",
        # Half-Life ships a top-down render of every deathmatch level in
        # valve/overviews, meant for the spectator map. It is not a levelshot,
        # but it is a picture of the level drawn by the people who built it,
        # and it covers all eleven deathmatch maps.
        "has_shots": True,
        "shots": ("overviews", ".bmp"),
        # mp_teamplay defaults to 0 and server.cfg does not set it, so a
        # freshly started server really is in plain deathmatch.
        "default_mode": "dm",
        "modes": {
            "dm":   ("Deathmatch", ["mp_teamplay 0"]),
            "team": ("Team play",  ["mp_teamplay 1"]),
        },
        # Half-Life's shipped server.cfg leaves every one of these commented
        # out, and the engine publishes none of them, so without this the whole
        # panel read "unknown". These are Valve's own defaults and have not
        # moved in twenty-odd years; the UI labels them as defaults rather than
        # as anything the server confirmed.
        "defaults": {"mp_fraglimit": "0", "mp_timelimit": "0",
                     "mp_friendlyfire": "0", "mp_falldamage": "0",
                     "mp_footsteps": "1"},
        "settings": [
            ("mp_fraglimit", "Frag limit", "int", (0, 200)),
            ("mp_timelimit", "Time limit (min)", "int", (0, 120)),
            ("mp_friendlyfire", "Friendly fire", "bool", None),
            ("mp_falldamage", "Fall damage", "bool", None),
            ("mp_footsteps", "Footsteps", "bool", None),
            # Movement house-rules. Engine-level (FCVAR_SERVER|FCVAR_MOVEVARS,
            # sv_main.c:86-98), not the missing game DLL, so these are
            # confirmed present on this build unlike the mp_* rules above.
            ("sv_gravity", "Gravity", "int", (0, 3200)),          # default 800
            ("sv_friction", "Friction", "int", (0, 16)),          # default 4
            ("sv_maxspeed", "Max speed", "int", (0, 1000)),       # default 320
            ("sv_accelerate", "Acceleration", "int", (0, 50)),    # default 10
            ("sv_airaccelerate", "Air acceleration", "int", (0, 50)), # default 10
        ],
    },
    "alephone": {
        "label": "Aleph One", "unit": "alephone-server", "port": 4226,
        "repo": "alephone",
        "accent": "var(--alephone)",
        "fifo": "/run/alephone-server/console",
        # BUILD-INFO.txt lives one level up from the content dir, same as
        # every other game (server_build(), #6) -- without this key the
        # version line silently never rendered for this game. No "paks" key:
        # nothing here reads cfg["paks"] except through a guard (has_bots,
        # a bot-face lookup, cfg.get("paks")) that already skips alephone.
        "dir": "/opt/alephone-server/Scenarios",
        "gatherer": True,
        # The one game here whose data ships INSIDE the download, because it
        # is the one whose data is free: Bungie released the Marathon trilogy,
        # so the DMG carries Marathon at its top level and Marathon 2 and
        # Infinity under Scenarios/ -- 184 MB of content in a 104 MB image,
        # all three scenarios complete. Quake, Quake II, Quake III and
        # Half-Life ship an engine and nothing else, because their data is
        # retail and has to come from a copy you own.
        #
        # Say so on the downloads page. Without this the Aleph One row simply
        # had no game-data link and gave no reason, which reads identically to
        # "someone forgot to upload it" -- and on 2026-09-02 that is exactly
        # what it was read as, nearly costing a 141 MB zip of files every
        # client already had.
        "data_in_build": True,
        "modes": {},
        "settings": [],
    },
}

# Download-only entries: a client that has no dedicated server on this box at
# all, so none of the GAMES machinery applies (no unit, no port, no fifo, no
# nftables rule, no live status poll) -- just a tile on the downloads list.
# KeeperFX is a personal client-only fork (see the keeperfx repo's own
# README); there is no server-* release for it to deploy, so it can never
# join GAMES the way the five dedicated servers do. Kept separate rather than
# padding GAMES with keys that would silently mean nothing everywhere else
# GAMES is read (health checks, nav, mode/settings panels, ...).
DOWNLOAD_EXTRAS = {
    "keeperfx": {
        "label": "KeeperFX", "repo": "keeperfx",
        # Only repo here without a .dmg client release -- ships a self-
        # contained KeeperFX.app zipped instead.
        "asset_exts": (".zip",),
    },
}

# Which maps suit which mode. Campaign maps in a deathmatch list are noise, and
# deathmatch maps in a co-op list have no monsters in them.
MAP_RULES = {
    "quake":    [("dm", r"^dm\d+$"), ("team", r"^dm\d+$"),
                 ("coop", r"^(start|e[1-4]m\d+)$")],
    "quake2":   [("dm", r"^(q2dm\d+|match\d+|ndm\d+|dm\d+)$"),
                 ("coop", r"^(base\d+|bunk\d+|jail\d+|mine\d+|fact\d+|city\d+|boss\d+|"
                          r"biggun|command|cool1|hangar\d+|lab|security|space|strike|"
                          r"train|ware\d+|waste\d+|sewer\d+)$")],
    "quake3":   [("ffa", r"^(pro-)?q3dm\d+$"), ("team", r"^(pro-)?q3(dm|tourney)\d+$"),
                 ("duel", r"^(pro-)?q3tourney\d+$"), ("ctf", r"^(pro-)?q3ctf\d+$")],
    "halflife": [("dm", r"^(?!c\d|t0a|ba_|of\d)"), ("team", r"^(?!c\d|t0a|ba_|of\d)")],
    "alephone": [],
}
MAP_JUNK = re.compile(r"^(b_|\*)")           # brush models, not levels
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_+.-]{1,64}$")
# Anything sent to a game console must not carry a newline: the FIFO is a
# command stream, so an embedded newline is a second command.
SAFE_SAY = re.compile(r"^[^\r\n\x00;\"]{1,120}$")


class AuthError(Exception):
    pass


def field(form, name, default=""):
    """One value out of a parsed form.

    parse_qs hands back a list per name and every caller here wants the first,
    which was fourteen copies of the same `or [""]` dance. Worth naming: the
    list is also why a <select> beats a <button> that shares its name."""
    return (form.get(name) or [default])[0]


# ------------------------------------------------------ the nftables snapshot
#
# Held here, above run(), only so run() can invalidate it without a forward
# reference. _all_sets() further down is what fills it.
_SETS_TTL = 1.0
_SETS_LOCK = threading.Lock()
_sets_cache = {"at": 0.0, "sets": None}


def _sets_invalidate():
    with _SETS_LOCK:
        _sets_cache["at"], _sets_cache["sets"] = 0.0, None


def run(args, stdin=None, timeout=15):
    r = subprocess.run(args, input=stdin, capture_output=True, text=True, timeout=timeout)
    # Centralised on purpose. Grants are written from four different places
    # (post_allow's v4 and v6 branches, post_allow_ipv4, post_allow_blocked)
    # and revoked from a fifth, and every one of them reads a set back
    # afterwards to prove the write landed -- which is the whole point of the
    # delete-then-add dance, since a bare `add` on an existing element exits 0
    # and changes no timeout. A read-back answered from a snapshot taken
    # before the write would confirm the wrong thing and look identical to
    # working. Invalidating here means a new grant path cannot forget to.
    if len(args) > 2 and args[0] == "sudo" and args[1] == "nft" \
            and args[2] in ("add", "delete", "flush", "replace"):
        _sets_invalidate()
    return r


def verify_access(token):
    """Return the verified email address, or raise AuthError."""
    if not ACCESS_AUD:
        raise AuthError("RETRO_ACCESS_AUD not configured")
    if _jwt is None:
        raise AuthError("PyJWT not installed")
    if not token:
        raise AuthError("no Cf-Access-Jwt-Assertion header")
    # Everything below is parsing attacker-controlled bytes, so every failure
    # in it means "not authenticated" and nothing else. Caught broadly and
    # deliberately: PyJWT raises a family of its own exceptions (DecodeError,
    # ExpiredSignatureError, InvalidAudienceError, PyJWKClientError...) and the
    # JWKS lookup is a network call that can raise anything a socket can.
    # Listing them individually means the one that was not listed escapes.
    #
    # It escaped. A header of `Cf-Access-Jwt-Assertion: not.a.jwt` raised
    # jwt.exceptions.DecodeError out of get_signing_key_from_jwt, past the
    # handler, and the client got an empty reply and a stack trace in the
    # journal instead of a 403. It failed closed, which is the important half,
    # but an auth path that throws is one that cannot be reasoned about — and
    # every probe of it cost a traceback in the log.
    try:
        key = _jwks.get_signing_key_from_jwt(token).key
        claims = _jwt.decode(token, key, algorithms=["RS256"], audience=ACCESS_AUD,
                             issuer="https://%s" % TEAM_DOMAIN)
    except AuthError:
        raise
    except Exception as e:
        raise AuthError("token rejected: %s: %s" % (e.__class__.__name__, e))
    email = claims.get("email")
    if not email:
        raise AuthError("token carries no email claim")
    # Fail closed if the list is missing entirely: an empty allowlist means the
    # unit did not set RETRO_ADMIN_EMAILS, and "no list configured" must not
    # quietly degrade into "everybody with a valid token".
    if not ADMIN_EMAILS:
        raise AuthError("RETRO_ADMIN_EMAILS not configured")
    if email.strip().lower() not in ADMIN_EMAILS:
        raise AuthError("address %s is not on the admin list" % email)
    return email


# ------------------------------------------------------------- grant bookkeeping
#
# nftables stores the address and its remaining lifetime but nothing about who
# opened it. That is the interesting part of an audit trail, so it is kept
# alongside. The firewall stays the source of truth for *access*; this file is
# only ever decoration on top of it.
def _load_grants():
    try:
        with open(GRANTS_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_grants(d):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = GRANTS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(d, f)
        os.replace(tmp, GRANTS_FILE)
    except OSError:
        pass


def remembered_mode(game):
    return _load_grants().get("_mode", {}).get(game)


def remember_mode(game, mode):
    g = _load_grants()
    g.setdefault("_mode", {})[game] = mode
    _save_grants(g)


def remembered_stop(game):
    """Who stopped this server, and when. None if nobody here did.

    #9. The permission to stop a server and the record of who
    stopped it ship together: without this, a parked server and a server that
    died look identical on the page, and telling those apart is most of what
    the page is for."""
    rec = _load_grants().get("_stopped", {}).get(game)
    return rec if isinstance(rec, dict) else None


def remember_stop(game, who):
    g = _load_grants()
    g.setdefault("_stopped", {})[game] = {"by": who, "at": int(time.time())}
    _save_grants(g)


def forget_stop(game):
    """Starting or restarting clears the record. A server that is running was
    not stopped by anybody, whatever the file still says."""
    g = _load_grants()
    if g.get("_stopped", {}).pop(game, None) is not None:
        _save_grants(g)


def remembered_setting(game, key):
    return _load_grants().get("_settings", {}).get(game, {}).get(key)


def remember_setting(game, key, value):
    g = _load_grants()
    g.setdefault("_settings", {}).setdefault(game, {})[key] = value
    _save_grants(g)


def record_grant(ip, who):
    g = _load_grants()
    g[ip] = {"by": who, "at": int(time.time())}
    _save_grants(g)


def forget_grant(ip):
    g = _load_grants()
    if g.pop(ip, None) is not None:
        _save_grants(g)


# ------------------------------------------------------------- the play log
#
# #8: Activity kept only the lines the web app printed about itself, so the
# page could say what it had been told to do and never that anyone had played.
# "Did anyone use this last night" was unanswerable, which is the question
# that decides whether any of the port work matters.
#
# Two things in the ticket's plan turned out to be wrong when I read the code,
# and both change the design:
#
# 1. /api/status does NOT query the engines every 8 seconds. It queries them
#    when a browser asks it to. Close every tab and nothing runs. A record
#    built there would only exist while someone was watching, which is the
#    same defect #5 is about and would answer "did anyone play last night"
#    with whatever happened to be on screen. So the sampling lives in
#    maintainer(), which is a daemon thread and runs whether or not anyone
#    has the page open.
#
# 2. Half-Life reports no player names at all. The halflife branch of
#    _live_state_uncached parses A2S_INFO, which carries a player COUNT and
#    nothing else -- it never appends to out["players"] (:1575-1590). Names
#    would need A2S_PLAYER and its challenge handshake. A name-based record
#    would therefore have read "nobody played" for Half-Life for ever, on
#    every input, which is the failure this repo keeps catching.
#
# So the unit recorded here is a SESSION built from the count, with names
# attached where the engine gives them. Count is available for all four, and
# count is what the question actually needs.
PLAY_FILE = os.path.join(STATE_DIR, "play-log.json")
# Sessions kept, oldest dropped first. A session is about 130 bytes, so this
# is roughly 130 kB and it never grows past that. Two people who play most
# evenings generate a handful a day, so 1000 is on the order of a year of
# their actual use. The cap exists because the health card watches a 50 GB
# boot volume and an unbounded append would eat it quietly.
PLAY_MAX = 1000
# An engine that misses a reply while people are playing must not split one
# evening into two sessions, so a session survives one bad sample and closes
# on the second. At the 20s maintainer() interval that is a 40s grace.
PLAY_GRACE = 2
# An open session is written on every pass that has anyone in it, so its end
# time is always on disk and a crash loses nothing. That is a write every 20s
# WHILE SOMEONE IS PLAYING and none at all otherwise -- an evening of actual
# play is a few hundred writes of a file that never exceeds ~60 kB, measured.
# A cheaper checkpoint was tried first and was wrong: the end time then came
# from the last time something else happened to change, so a steady session
# recorded a finish minutes before everyone actually left.
_PLAY_LOCK = threading.Lock()


def _load_play():
    try:
        with open(PLAY_FILE) as f:
            d = json.load(f)
    except (OSError, ValueError):
        d = {}
    if not isinstance(d, dict):
        d = {}
    d.setdefault("open", {})
    d.setdefault("done", [])
    if not isinstance(d["open"], dict):
        d["open"] = {}
    if not isinstance(d["done"], list):
        d["done"] = []
    return d


def _save_play(d):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = PLAY_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(d, f)
        os.replace(tmp, PLAY_FILE)
    except OSError:
        pass


def human_players(game, st):
    """How many PEOPLE are in this server, and their names if it says.

    Quake III is the only one of the four with bots, and top_up() puts them
    there deliberately, so counting them would report a full server every
    night whatever anyone did. A bot answers the status query with a ping of
    0; a person coming in over the internet does not.

    Returns (count, names). names is empty for Half-Life, which publishes no
    names -- not because nobody is there."""
    if not st.get("up"):
        return None, []
    rows = st.get("players") or []
    if rows:
        # Decided on the RAW roster, before the bots come out. Falling back to
        # st["count"] when the FILTERED list is empty put the bots straight
        # back: a server holding three bots and nobody else reported three
        # players, because count is len(players) before the filter. That is
        # the same answer for every input, every night, and it is what the
        # test at the bot control exists to catch.
        if GAMES.get(game, {}).get("has_bots"):
            rows = [p for p in rows if str(p.get("ping") or "") != "0"]
        return len(rows), [p.get("name") or "" for p in rows
                           if (p.get("name") or "").strip()]
    # No roster at all. Half-Life answers A2S_INFO, which carries a count and
    # no names, so this is the only number there is for it.
    n = _as_int(st.get("count"))
    return (n if n is not None else 0), []


def play_sample(now=None):
    """One pass: open, extend or close a session per game.

    Called from maintainer(), not from a request, so the record is of what
    happened rather than of what someone was looking at."""
    now = int(now if now is not None else time.time())
    with _PLAY_LOCK:
        d = _load_play()
        dirty = False
        for game in GAMES:
            try:
                n, names = human_players(game, live_state(game))
            except Exception:                        # never take the UI down
                continue
            cur = d["open"].get(game)
            if n:
                if cur is None:
                    cur = {"a": now, "b": now, "peak": n, "names": [], "miss": 0}
                    d["open"][game] = cur
                    dirty = True
                cur["miss"] = 0
                cur["b"] = now
                # Always. b is the answer to "until when", and an update kept
                # only in memory is discarded at the end of the pass.
                dirty = True
                if n > cur.get("peak", 0):
                    cur["peak"] = n
                for nm in names:
                    if nm not in cur["names"]:
                        cur["names"].append(nm)
            elif cur is not None:
                # A missed reply is not an empty server. Ride out PLAY_GRACE
                # of them before believing everyone left.
                cur["miss"] = cur.get("miss", 0) + 1
                # Persisted, not just incremented. The counter lives in the
                # file, and without marking the write the increment was thrown
                # away at the end of the pass -- so miss went 1, 1, 1 for ever
                # and a finished session never closed.
                dirty = True
                if cur["miss"] < PLAY_GRACE:
                    continue
                d["open"].pop(game, None)
                _close(d, game, cur)
                dirty = True
        if dirty:
            _save_play(d)


def _close(d, game, cur):
    """Move a finished session into the record, and hold the cap."""
    d["done"].append({"g": game, "a": cur["a"], "b": cur["b"],
                      "peak": cur.get("peak", 1),
                      "names": cur.get("names", [])[:8]})
    if len(d["done"]) > PLAY_MAX:
        del d["done"][:len(d["done"]) - PLAY_MAX]


def play_recover():
    """Close anything left open by a previous run of this process.

    An open session says people were playing when we stopped watching. It
    cannot say they stayed, so it is closed at the last time actually written
    down rather than extended to now -- inventing the tail would make the
    record say something nobody measured."""
    with _PLAY_LOCK:
        d = _load_play()
        if not d["open"]:
            return
        for game, cur in list(d["open"].items()):
            d["open"].pop(game, None)
            _close(d, game, cur)
        _save_play(d)


def play_sessions(n=20, offset=0):
    """Finished sessions, newest first, with anything still running on top.

    Returns (rows, total) so a caller can page without a second pass over the
    file — total is the full count behind the cap this page didn't ask for."""
    with _PLAY_LOCK:
        d = _load_play()
    live = [{"g": g, "a": c["a"], "b": c["b"], "peak": c.get("peak", 1),
             "names": c.get("names", []), "live": True}
            for g, c in d["open"].items()]
    live.sort(key=lambda s: s["a"], reverse=True)
    rows = live + d["done"][::-1]
    return rows[offset:offset + n], len(rows)


# ------------------------------------------------------------------ Web Push
#
# #5: the page reports state when you look at it, and nothing reaches anyone
# who is not looking. Web Push is the only mechanism that costs nothing and
# needs no third party. this is the decision to have a service worker
# at all, and why it is forbidden from caching.
#
# The keypair is generated here on first use rather than in Terraform. It is a
# per-box secret with no Cloudflare or Oracle resource behind it, and putting
# it in state would print it in cleartext for nothing.
VAPID_FILE = os.path.join(STATE_DIR, "vapid.pem")
SUBS_FILE = os.path.join(STATE_DIR, "push-subs.json")
# Identifies this sender to the push service. It must be a URL or a mailto:,
# and it is contact information for whoever runs the server, not a secret.
VAPID_SUBJECT = os.environ.get("RETRO_VAPID_SUBJECT", "mailto:admin@example.invalid")

_VAPID_LOCK = threading.Lock()


def _b64u(b):
    """base64url with the padding stripped, which is what every part of the
    Web Push stack expects and what none of them will do for you."""
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def vapid_key():
    """The server's identity to the push services. Generated once, then read.

    Returns the private key object, or None if this box cannot do ES256 at
    all. Never raises: a box without `cryptography` should lose notifications
    and keep serving the admin UI, not fail to start."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError:
        return None
    with _VAPID_LOCK:
        try:
            with open(VAPID_FILE, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=None)
        except (OSError, ValueError):
            pass
        try:
            k = ec.generate_private_key(ec.SECP256R1())
            os.makedirs(STATE_DIR, exist_ok=True)
            tmp = VAPID_FILE + ".tmp"
            # 0600 before anything is written to it. The default umask would
            # leave the private key group-readable for the moment between
            # creation and the chmod, and this process is long-lived.
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(k.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()))
            os.replace(tmp, VAPID_FILE)
            return k
        except (OSError, ValueError):
            return None


def vapid_public_b64():
    """The applicationServerKey the browser subscribes with.

    The uncompressed P-256 point, 65 bytes, base64url. Anything else and
    `pushManager.subscribe` rejects with a DOMException that does not say
    why."""
    k = vapid_key()
    if k is None:
        return ""
    try:
        from cryptography.hazmat.primitives import serialization
        return _b64u(k.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint))
    except (ImportError, ValueError):
        return ""


def _hkdf(salt, ikm, info, length):
    """RFC 5869, one output block, which is all Web Push ever needs.

    Written out rather than pulled from a library because the whole of the
    key schedule below is four calls to this and one AES-GCM, and a
    dependency that has to be installed on the box is a dependency that can
    be missing on the box."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


def encrypt_push(p256dh, auth, payload, salt=None, as_key=None):
    """Encrypt a payload for one subscription. RFC 8291, aes128gcm.

    salt and as_key are injectable ONLY so the RFC 8291 section 5 test vector
    can be reproduced -- see admin/push-test.py. Everything real generates
    both fresh, and reusing either would leak the plaintext.

    Returns the request body: the RFC 8188 header, then one record."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    ua_pub_bytes = _b64u_decode(p256dh)
    auth_secret = _b64u_decode(auth)
    ua_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), ua_pub_bytes)
    if as_key is None:
        as_key = ec.generate_private_key(ec.SECP256R1())
    as_pub_bytes = as_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint)

    shared = as_key.exchange(ec.ECDH(), ua_pub)
    # The order is receiver then sender, and getting it the other way round
    # produces a body the browser rejects with no diagnostic at all.
    key_info = b"WebPush: info\x00" + ua_pub_bytes + as_pub_bytes
    ikm = _hkdf(auth_secret, shared, key_info, 32)

    if salt is None:
        salt = os.urandom(16)
    cek = _hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = _hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12)

    # RFC 8188: the final record ends with the delimiter 0x02. One record
    # here, always -- these payloads are a title and a sentence.
    record = AESGCM(cek).encrypt(nonce, payload + b"\x02", None)
    header = salt + struct.pack(">I", 4096) + bytes([len(as_pub_bytes)]) + as_pub_bytes
    return header + record


def vapid_auth(endpoint, now=None):
    """The Authorization header value for one push service. RFC 8292.

    The signature has to be the raw 64-byte r||s pair. `cryptography` signs
    to DER, and handing DER over is refused by the push services with a 401
    that says nothing useful."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

    k = vapid_key()
    if k is None:
        return ""
    u = urllib.parse.urlsplit(endpoint)
    aud = "%s://%s" % (u.scheme, u.netloc)
    now = int(now if now is not None else time.time())
    head = _b64u(json.dumps({"typ": "JWT", "alg": "ES256"},
                            separators=(",", ":")).encode())
    claims = _b64u(json.dumps({"aud": aud, "exp": now + 12 * 3600,
                               "sub": VAPID_SUBJECT},
                              separators=(",", ":")).encode())
    signing_input = ("%s.%s" % (head, claims)).encode()
    der = k.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, sig_s = asym_utils.decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + sig_s.to_bytes(32, "big")
    # `t=` is the WHOLE jwt -- header.claims.signature, three parts. This
    # read `t=header.claims, k=signature` until push-test.py's round trip
    # caught it: no push service would have accepted it, and the failure
    # mode is a bare 401 with nothing in it that points back here. `k=` is
    # the base64url public key (RFC 8292), which had never been sent at all.
    jwt = "%s.%s.%s" % (head, claims, _b64u(raw))
    pub = vapid_public_b64()
    return "vapid t=%s, k=%s" % (jwt, pub), pub


def send_push(endpoint, rec, message, ttl=3600):
    """Deliver one notification. Returns the push service's status code, or 0.

    A subscription the service has retired answers 404 or 410, and the only
    correct response is to drop it: keeping it means every future send spends
    a request proving the same thing again."""
    import urllib.request
    try:
        body = encrypt_push(rec["p256dh"], rec["auth"],
                            json.dumps(message).encode())
        auth = vapid_auth(endpoint)
        if not auth:
            return 0
        req = urllib.request.Request(endpoint, data=body, method="POST")
        req.add_header("Authorization", auth[0])
        req.add_header("Content-Encoding", "aes128gcm")
        req.add_header("Content-Type", "application/octet-stream")
        req.add_header("TTL", str(ttl))
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 410):
            forget_sub(endpoint)
            print("retro-admin: push subscription retired (%d)" % exc.code, flush=True)
        else:
            print("retro-admin: push refused %d" % exc.code, flush=True)
        return exc.code
    except Exception as exc:                          # never take the UI down
        print("retro-admin: push failed: %s" % exc, flush=True)
        return 0


def notify(title, body, tag="retro"):
    """Tell every subscribed device. Returns how many accepted it.

    Every push is a few hundred bytes to Apple or Google over TLS. Against
    the 10 TB monthly egress allowance this is not measurable, which is why
    it is the mechanism the ADR chose."""
    sent = 0
    for endpoint, rec in list(_load_subs().items()):
        if send_push(endpoint, rec, {"title": title, "body": body, "tag": tag}) in (200, 201, 202):
            sent += 1
    return sent


def _load_subs():
    try:
        with open(SUBS_FILE) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_subs(d):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = SUBS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(d, f)
        os.replace(tmp, SUBS_FILE)
    except OSError:
        pass


def record_sub(sub, who):
    """Remember a browser that wants to be told. Keyed on the endpoint, so
    re-subscribing the same device replaces rather than duplicates."""
    ep = sub.get("endpoint") or ""
    keys = sub.get("keys") or {}
    if not ep.startswith("https://") or not keys.get("p256dh") or not keys.get("auth"):
        return False
    d = _load_subs()
    d[ep] = {"p256dh": keys["p256dh"], "auth": keys["auth"],
             "who": who, "at": int(time.time())}
    _save_subs(d)
    return True


def forget_sub(endpoint):
    d = _load_subs()
    if d.pop(endpoint, None) is not None:
        _save_subs(d)


# --------------------------------------------------------------- health watch
#
# #5. The page can say a server crashed once you open it. Nothing reaches
# anyone who is not looking. This is what fixes that, and it is built on
# three things the fleet's own quakespasm-CI incident showed the same morning
# this was written, so they are named here rather than left to be rediscovered
# the same way.
#
# 1. An absence is not an error, and a check that waits for a bad RESULT
#    cannot see one -- Actions was disabled at the repository, in front of
#    the workflows, and every run before that kept reading green because
#    nothing had failed; there was simply nothing running. So this does not
#    ask "did the last query fail". It asks "how long since an engine
#    actually answered", and fires on the gap.
# 2. "active" was true and useless -- an accurate answer to a question
#    nobody was asking. So a notification here carries a clock time, not a
#    state word: "Quake II last answered 14:02" cannot be quietly correct
#    while everything is broken.
# 3. A cached last-known-good has to say what was good and when, or it
#    vouches for something that no longer exists. _WATCH holds "seen": the
#    epoch of the last confirmed answer, never just a flag.
#
# unit state is not the input, deliberately. Measured the same morning: a
# server stopped deliberately through #9 leaves systemd reporting `failed`,
# identical to a crash. Only the engine actually answering its own status
# query is evidence of anything.
_WATCH = {}
# Passes of no reply before believing it, not queries. _udp() already retries
# a single query 3 times because a busy engine can drop one status packet;
# this is the next layer up, riding out a bad run of THOSE. At the 20s
# maintainer() interval, 3 misses is a minute of silence.
WATCH_MISSES = 3


def watch_sample(now=None):
    """One pass: has each engine answered, and has that changed."""
    now = int(now if now is not None else time.time())
    for game in GAMES:
        try:
            up = live_state(game).get("up")
        except Exception:                              # never take the UI down
            up = None
        rec = _WATCH.setdefault(game, {"seen": now, "miss": 0, "down": False})
        if up:
            was_down = rec["down"]
            rec["seen"] = now
            rec["miss"] = 0
            rec["down"] = False
            if was_down:
                notify("%s is back" % GAMES[game]["label"],
                      "Answering again as of %s." % time.strftime("%H:%M", time.localtime(now)),
                      tag="watch-%s" % game)
            continue
        rec["miss"] += 1
        if rec["miss"] >= WATCH_MISSES and not rec["down"]:
            rec["down"] = True
            last = time.strftime("%H:%M", time.localtime(rec["seen"]))
            notify("%s stopped answering" % GAMES[game]["label"],
                  "Last answered %s. Check whether it needs restarting." % last,
                  tag="watch-%s" % game)


# The other thing that reaches nobody who is not looking: the access grant
# itself. #10 decided a session may not renew it -- the TTL is the security
# control, the address moves, and the identity proof is a person with a PIN.
# What a session CAN do is say so before it lapses, the same reasoning that
# put the countdown on the Access page this morning. This is that countdown's
# reach extended to a closed app.
GRANT_WARN_SECS = 1800
_GRANT_WARNED = set()


def grant_watch(now=None):
    """Warn once per grant as it nears expiry, and forget it once it is gone.

    Keyed on (ip, rounded deadline) rather than on the IP alone, so a renewal
    -- which moves the deadline hours out -- earns a fresh warning near the
    NEW time rather than being silently covered by the old one."""
    now = int(now if now is not None else time.time())
    live_keys = set()
    for setname, label in (("players", "reach the game servers"),
                           ("players6", "reach the game servers"),
                           ("admins_dyn", "reach SSH")):
        for addr, secs in set_members(setname):
            if secs is None:
                continue
            key = (str(addr), setname, round((now + secs) / 60.0))
            live_keys.add(key)
            if 0 < secs <= GRANT_WARN_SECS and key not in _GRANT_WARNED:
                _GRANT_WARNED.add(key)
                notify("Access running out",
                      "%s will stop being able to %s in about %d minutes."
                      % (addr, label, max(1, round(secs / 60.0))),
                      tag="grant-%s-%s" % (setname, addr))
    # Nothing keyed on an address no longer holding a grant is worth
    # remembering -- it either expired, or was revoked, or was renewed under
    # a new key above.
    _GRANT_WARNED.intersection_update(live_keys)


# --------------------------------------------------------------- map listing
def _pak_maps(path):
    """id PAK: 'PACK', int32 dirofs, int32 dirlen, then 64-byte entries."""
    out = []
    try:
        with open(path, "rb") as f:
            if f.read(4) != b"PACK":
                return out
            ofs, ln = struct.unpack("<ii", f.read(8))
            f.seek(ofs)
            for _ in range(ln // 64):
                name = f.read(56).split(b"\0")[0].decode("latin-1")
                f.read(8)
                low = name.lower()
                if low.startswith("maps/") and low.endswith(".bsp"):
                    out.append(os.path.basename(name)[:-4])
    except (OSError, struct.error, UnicodeDecodeError):
        pass
    return out


def _pk3_maps(path):
    out = []
    try:
        for n in zipfile.ZipFile(path).namelist():
            low = n.lower()
            if low.startswith("maps/") and low.endswith(".bsp"):
                out.append(os.path.basename(n)[:-4])
    except (OSError, zipfile.BadZipFile):
        pass
    return out


_BOTS_CACHE = {}
_ICON_CACHE = {}

# Decoded artwork is cached to disk and never re-derived, so changing which
# file an image comes from, or how it is processed, has to change the cache
# name too — otherwise the old picture survives the deploy and the change
# looks like it silently did nothing. Bump this whenever either changes.
ART_REV = 9

# Letterbox colour behind a level picture that is not 4:3. Matches the card
# background in the stylesheet.
TILE_BG = (26, 26, 30)

# Where each kind of derived image is kept. warm_art() sweeps these by name,
# and drops anything not carrying the current ART_REV.
_ART_DIRS = {"emblem": "emblems", "appicon": "emblems",
             "shot": "shots", "boticon": "icons"}


def cached_art(kind, parts, produce):
    """Memory, then disk, then derive it — for one picture.

    Four functions used to carry their own copy of this, and the copies drifted:
    the Home Screen icon shipped as a single 96px image served for 180, 192 and
    512 because one of them left the size out of the memory key while its file
    name still had it. Here the key and the file name are the same tuple, so
    they cannot disagree — adding a dimension to one adds it to the other.

    `produce` runs only on a miss. It may return None for "there is no such
    picture", which is remembered in memory so a miss costs the search once,
    but is not written to disk."""
    parts = tuple(str(x) for x in parts)
    key = (kind,) + parts
    if key in _ICON_CACHE:
        return _ICON_CACHE[key]

    cache_dir = os.path.join(STATE_DIR, _ART_DIRS[kind])
    cached = os.path.join(cache_dir,
                          "%s-%s-r%d.png" % (kind, "-".join(parts), ART_REV))
    try:
        with open(cached, "rb") as f:
            data = f.read()
        _ICON_CACHE[key] = data
        return data
    except OSError:
        pass

    data = produce()
    if data:
        try:
            os.makedirs(cache_dir, exist_ok=True)
            with open(cached, "wb") as f:
                f.write(data)
        except OSError:
            pass
    _ICON_CACHE[key] = data
    return data


def bot_models(game):
    """{bot name: (pk3 path, entry)} for each bot's face icon.

    scripts/bots.txt gives `model lucy/angel`, meaning directory `lucy` and
    skin `angel`, so the icon is icon_angel.tga rather than icon_default.tga.
    Getting that wrong silently hands you the wrong face."""
    cfg = GAMES[game]
    if not cfg.get("has_bots"):
        return {}
    models = {}
    for path in sorted(glob.glob(os.path.join(cfg["dir"], cfg["paks"]))):
        try:
            z = zipfile.ZipFile(path)
        except (OSError, zipfile.BadZipFile):
            continue
        for entry in z.namelist():
            if entry.lower() != "scripts/bots.txt":
                continue
            txt = z.read(entry).decode("latin-1", "replace")
            for blk in re.findall(r"\{(.*?)\}", txt, re.S):
                nm = re.search(r'^\s*name\s+"?([^"\r\n]+?)"?\s*$', blk, re.M)
                md = re.search(r'^\s*model\s+"?([^"\r\n]+?)"?\s*$', blk, re.M)
                if nm and md:
                    models[nm.group(1).strip()] = md.group(1).strip()
    out = {}
    for path in sorted(glob.glob(os.path.join(cfg["dir"], cfg["paks"]))):
        try:
            z = zipfile.ZipFile(path)
        except (OSError, zipfile.BadZipFile):
            continue
        have = {x.lower(): x for x in z.namelist()}
        for bot, model in models.items():
            if bot in out:
                continue
            d, _, skin = model.partition("/")
            for ext in ("tga", "jpg", "png"):
                want = "models/players/%s/icon_%s.%s" % (d, skin or "default", ext)
                if want in have:
                    out[bot] = (path, have[want])
                    break
    return out


# One image per game for the overview tiles. Each engine stores graphics
# differently, so each needs its own route in.
#
# Three of these four were originally picked by filename and never looked at,
# and all three were wrong: pics/quit.pcx is Quake II's credits screen,
# menu/art/gr/grlogo.tga is the GtkRadiant logo that ships inside baseq3, and
# gfx/lambda.bmp is a grey box reading "LOADING...". They are now the plaque,
# the arena logo and Gordon Freeman, which is what each game would show you.
EMBLEMS = {
    "quake":    ("gfx/qplaque.lmp",                  "lmp"),  # QUAKE plaque, id's own format
    "quake2":   ("pics/m_main_plaque.pcx",           "pil"),  # QUAKE II plaque, PCX
    "quake3":   ("textures/sfx/logo512.jpg",         "pil"),  # the arena logo, inside a pk3
    "halflife": ("models/player/gordon/gordon.bmp",  "pil"),  # the model-select portrait
}


def _pak_read(pak, want):
    try:
        with open(pak, "rb") as f:
            if f.read(4) != b"PACK":
                return None
            ofs, ln = struct.unpack("<ii", f.read(8))
            f.seek(ofs)
            for _ in range(ln // 64):
                nm = f.read(56).split(b"\0")[0].decode("latin-1")
                pos, sz = struct.unpack("<ii", f.read(8))
                if nm.lower().replace("\\", "/") == want:
                    f.seek(pos)
                    return f.read(sz)
    except (OSError, struct.error, UnicodeDecodeError):
        pass
    return None


ART_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "art")


def emblem_png(game, size=96):
    """The icon for a game's tile on the overview.

    Preferably the app icon from that game's own repo — the Ranger head with
    each Quake logo, and Gordon — which are far better than anything the games
    ship. See art/SOURCES.md.

    Failing that, dig one out of the game's own data. Quake's .lmp is int32
    width, int32 height, then one palette index per pixel, with the palette in
    gfx/palette.lmp as 768 RGB bytes; nothing reads that but Quake, so it is
    decoded here by hand."""
    # The size is part of the cache key, memory and disk both. It was not, and
    # that is how the Home Screen icon ended up being one 96px image served for
    # 180, 192 and 512: the first caller through decided the size for everyone
    # after. Nothing in the app asks for a non-default size today, so this is a
    # trap rather than a live fault — which is precisely when it is cheap.
    # The size is part of the cache key, memory and disk both, because
    # cached_art derives them from the same tuple. It was not always, and that
    # is how the Home Screen icon ended up being one 96px image served for 180,
    # 192 and 512.
    def produce():
        # The bundled art, when there is some, is the best source and needs no
        # decoding — but it is returned at whatever size it was drawn.
        try:
            with open(os.path.join(ART_DIR, "%s.png" % game), "rb") as f:
                return f.read()
        except OSError:
            pass

        spec = EMBLEMS.get(game)
        if not spec:
            return None
        want, kind = spec
        cfg = GAMES[game]
        raw = None
        if cfg["paks"].endswith("pk3"):
            for path in sorted(glob.glob(os.path.join(cfg["dir"], cfg["paks"]))):
                try:
                    z = zipfile.ZipFile(path)
                except (OSError, zipfile.BadZipFile):
                    continue
                hit = {n.lower(): n for n in z.namelist()}.get(want)
                if hit:
                    raw = z.read(hit)
                    break
        else:
            for path in sorted(glob.glob(os.path.join(cfg["dir"], cfg["paks"]))):
                raw = _pak_read(path, want)
                if raw:
                    break
        if not raw:
            return None

        try:
            from PIL import Image
            import io
            if kind == "lmp":
                pal = None
                for path in sorted(glob.glob(os.path.join(cfg["dir"], cfg["paks"]))):
                    pal = _pak_read(path, "gfx/palette.lmp")
                    if pal:
                        break
                if not pal or len(raw) < 8:
                    return None
                w, h = struct.unpack("<ii", raw[:8])
                if w <= 0 or h <= 0 or len(raw) < 8 + w * h:
                    return None
                im = Image.frombytes("P", (w, h), raw[8:8 + w * h])
                im.putpalette(pal[:768])
                im = im.convert("RGBA")
            else:
                im = Image.open(io.BytesIO(raw)).convert("RGBA")
            im.thumbnail((size, size), Image.LANCZOS)
            buf = io.BytesIO()
            im.save(buf, "PNG", optimize=True)
            return buf.getvalue()
        except Exception:
            return None

    return cached_art("emblem", (game, size), produce)


def _shot_raw(cfg, mapname):
    """The bytes of whatever picture this engine has of a level, or None.

    Quake III has real levelshots inside the pk3s, and its own placeholder for
    a level that has none — using id's placeholder rather than inventing one
    keeps the grid complete without pretending to show a map nobody rendered.

    Half-Life has no levelshots, but valve/overviews holds a top-down render of
    every deathmatch level, drawn for the spectator map. Those live loose on
    disk here and in pak0, so try both."""
    if cfg["paks"].endswith("pk3"):
        fallback = None
        for path in sorted(glob.glob(os.path.join(cfg["dir"], cfg["paks"]))):
            try:
                z = zipfile.ZipFile(path)
            except (OSError, zipfile.BadZipFile):
                continue
            have = {x.lower(): x for x in z.namelist()}
            for ext in ("tga", "jpg", "png"):
                hit = have.get("levelshots/%s.%s" % (mapname.lower(), ext))
                if hit:
                    try:
                        return z.read(hit), False
                    except (OSError, KeyError):
                        pass
            if fallback is None and "menu/art/unknownmap.jpg" in have:
                try:
                    fallback = z.read(have["menu/art/unknownmap.jpg"])
                except (OSError, KeyError):
                    fallback = None
        return (fallback, True) if fallback else (None, False)

    sub, ext = cfg.get("shots") or (None, None)
    if not sub:
        return None, False
    loose = os.path.join(cfg["dir"], sub, mapname + ext)
    try:
        with open(loose, "rb") as f:
            return f.read(), False
    except OSError:
        pass
    for path in sorted(glob.glob(os.path.join(cfg["dir"], cfg["paks"]))):
        raw = _pak_read(path, "%s/%s%s" % (sub, mapname.lower(), ext))
        if raw:
            return raw, False
    return None, False


def _dechroma(im, size):
    """Half-Life's overviews paint everything outside the level pure green,
    which is the engine's transparency colour and looks like a mistake in a
    web page. Drop it, crop to what is left, and letterbox onto a 4:3 tile so
    the grid stays even however oddly shaped the level is."""
    from PIL import Image, ImageChops
    im = im.convert("RGB")
    r, g, b = im.split()
    # Done with band arithmetic rather than a per-pixel loop: these are
    # 1024x768, and 786k Python-level iterations per map turned the first load
    # of the Half-Life page into a visible stall.
    hi = g.point(lambda v: 255 if v > 200 else 0, "1")
    lo_r = r.point(lambda v: 255 if v < 80 else 0, "1")
    lo_b = b.point(lambda v: 255 if v < 80 else 0, "1")
    keyed = ImageChops.logical_and(ImageChops.logical_and(hi, lo_r), lo_b)
    alpha = ImageChops.invert(keyed.convert("L"))

    # Crop on the alpha, not the image: getbbox() on RGBA also counts colour,
    # and the pixels being dropped are bright green, so it would find nothing
    # to trim.
    box = alpha.getbbox()
    if box:
        im, alpha = im.crop(box), alpha.crop(box)

    # Flatten onto the tile colour BEFORE resampling. Resampling with the green
    # still in place drags it into every edge pixel and leaves a fringe.
    im = im.convert("RGBA")
    im.putalpha(alpha)
    im = Image.alpha_composite(Image.new("RGBA", im.size, TILE_BG + (255,)), im)
    im = im.convert("RGB")
    im.thumbnail(size, Image.LANCZOS)
    tile = Image.new("RGB", size, TILE_BG)
    tile.paste(im, ((size[0] - im.size[0]) // 2, (size[1] - im.size[1]) // 2))
    return tile


# ------------------------------------------------------- Quake / Quake II plans
#
# Neither game ships a picture of a level. Quake III has levelshots in its
# pk3s and Half-Life has the spectator overviews; Quake and Quake II have
# nothing at all, which was checked in their pak files rather than assumed.
#
# So the picture is drawn from the level itself. Every BSP carries its own
# geometry, and a top-down projection of the upward-facing faces is a real
# floorplan of the map — the actual rooms, in their actual shape. It is not a
# screenshot and is not trying to be one.
#
# Taken from a fan wiki instead, these would be someone else's screenshots
# under someone else's licence — Fandom is CC-BY-SA, and other wikis vary or
# say nothing. Drawing them from data we already have means nothing to
# attribute and nothing to get wrong, and it matches every other asset here
# being baked in rather than fetched.
#
# Lump numbers differ between the two formats and the header length with them:
# Quake's BSP29 has 15 lumps starting at byte 4, Quake II's IBSP38 has 19
# starting at byte 8. Everything inside — vertex, edge, surfedge, face — has
# the same layout in both, which is why one reader does both games.
_BSP_LUMPS = {
    #            (header, vertexes, faces, edges, surfedges)
    "bsp29":     (4,      3,        7,     12,    13),
    "ibsp38":    (8,      2,        6,     11,    12),
}


def _bsp_faces(fh, base):
    """Upward-facing polygons of a BSP, in world coordinates. [] on anything odd."""
    fh.seek(base)
    head = fh.read(8)
    if len(head) < 8:
        return []
    kind = "ibsp38" if head[:4] == b"IBSP" else "bsp29"
    hoff, L_VERT, L_FACE, L_EDGE, L_SURF = _BSP_LUMPS[kind]

    def lump(i):
        fh.seek(base + hoff + i * 8)
        return struct.unpack("<ii", fh.read(8))

    def raw(i):
        off, ln = lump(i)
        if ln <= 0 or ln > 32_000_000:
            return b""
        fh.seek(base + off)
        return fh.read(ln)

    vraw, fraw, eraw, sraw = raw(L_VERT), raw(L_FACE), raw(L_EDGE), raw(L_SURF)
    if not (vraw and fraw and eraw and sraw):
        return []
    nv = len(vraw) // 12
    verts = struct.unpack("<%df" % (nv * 3), vraw[:nv * 12])
    ne = len(eraw) // 4
    edges = struct.unpack("<%dH" % (ne * 2), eraw[:ne * 4])
    ns = len(sraw) // 4
    surf = struct.unpack("<%di" % ns, sraw[:ns * 4])

    out = []
    for i in range(len(fraw) // 20):
        rec = fraw[i * 20:i * 20 + 20]
        firstedge, numedges = struct.unpack("<iH", rec[4:10])
        if numedges < 3 or firstedge < 0 or firstedge + numedges > ns:
            continue
        poly = []
        for k in range(numedges):
            se = surf[firstedge + k]
            ei = abs(se)
            if ei >= ne:
                poly = []
                break
            vi = edges[ei * 2 + (0 if se >= 0 else 1)]
            if vi >= nv:
                poly = []
                break
            poly.append((verts[vi * 3], verts[vi * 3 + 1], verts[vi * 3 + 2]))
        if len(poly) < 3:
            continue
        # Face normal from the polygon itself rather than the plane lump: the
        # plane's normal is unsigned with respect to which side the face is on,
        # and getting that backwards turns every floor into a ceiling.
        (ax, ay, az), (bx, by, bz), (cx, cy, cz) = poly[0], poly[1], poly[2]
        ux, uy, uz = bx - ax, by - ay, bz - az
        wx, wy, wz = cx - ax, cy - ay, cz - az
        nz = ux * wy - uy * wx
        nx = uy * wz - uz * wy
        ny = uz * wx - ux * wz
        mag = (nx * nx + ny * ny + nz * nz) ** 0.5
        if mag < 1e-6:
            continue
        # Floors only. Including walls fills the plan in solid, and including
        # ceilings draws the roof on top of the rooms it covers.
        if abs(nz / mag) < 0.7:
            continue
        out.append(poly)
    return out


def _bsp_plan(game, mapname, size):
    """Render a level's floorplan, or None if the map yields nothing to draw."""
    cfg = GAMES[game]
    faces = []
    try:
        loose = os.path.join(cfg["dir"], "maps", mapname + ".bsp")
        if os.path.exists(loose):
            with open(loose, "rb") as fh:
                faces = _bsp_faces(fh, 0)
        else:
            for pak in sorted(glob.glob(os.path.join(cfg["dir"], cfg["paks"]))):
                hit = _pak_index(pak).get("maps/%s.bsp" % mapname.lower())
                if hit:
                    with open(pak, "rb") as fh:
                        faces = _bsp_faces(fh, hit[0])
                    break
    except (OSError, struct.error, ValueError, KeyError):
        return None
    if len(faces) < 4:
        return None

    xs = [v[0] for f in faces for v in f]
    ys = [v[1] for f in faces for v in f]
    zs = [v[2] for f in faces for v in f]
    minx, maxx, miny, maxy = min(xs), max(xs), min(ys), max(ys)
    minz, maxz = min(zs), max(zs)
    spanx, spany = maxx - minx, maxy - miny
    if spanx <= 0 or spany <= 0:
        return None

    try:
        from PIL import Image, ImageDraw
        import io
    except ImportError:
        return None

    # Drawn at 3x and scaled down: these are hard-edged polygons and the
    # diagonal walls of a Quake level alias badly at 160px without it.
    SS = 3
    w, h = size[0] * SS, size[1] * SS
    pad = 6 * SS
    # Fit each axis to its own extent and take the tighter of the two, so the
    # plan fills the frame. Scaling both axes by the LARGER extent — which is
    # what this did first — fits the map's bounding square into the box and
    # leaves a wide level floating in the middle of it at half size.
    scale = min((w - 2 * pad) / spanx, (h - 2 * pad) / spany)
    ox = (w - spanx * scale) / 2
    oy = (h - spany * scale) / 2

    im = Image.new("RGB", (w, h), TILE_BG)
    d = ImageDraw.Draw(im)
    # Painted low to high so upper floors sit on top of the ones below, and
    # lit by height: a flat fill of one colour reads as a blob, while a ramp
    # shows the storeys and makes the shape legible at 160 pixels wide.
    faces.sort(key=lambda f: sum(v[2] for v in f) / len(f))
    zr = (maxz - minz) or 1.0
    for f in faces:
        t = ((sum(v[2] for v in f) / len(f)) - minz) / zr
        shade = int(58 + 150 * t)
        pts = [(ox + (v[0] - minx) * scale, h - (oy + (v[1] - miny) * scale))
               for v in f]
        d.polygon(pts, fill=(shade, shade, int(shade * 1.06) + 6))
    im = im.resize(size, Image.LANCZOS)
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=78, optimize=True)
    return buf.getvalue()


def app_icon_png(size):
    """The Home Screen icon, at the size the manifest actually promises.

    Not emblem_png(game, size): that returns the bundled art file byte for byte
    when there is one, ignoring the size argument entirely, and caches under a
    key with no size in it. Asking it for 180, 192 and 512 gave three identical
    files — which is a manifest that declares a 512 icon and serves a 96 one,
    and looks like a blurry app on the Home Screen.

    Squared and padded rather than stretched. A Home Screen icon is always
    square, and letting the platform crop a non-square source is how you lose
    the top of Ranger's head."""
    def produce():
        raw = emblem_png("quake3")
        if not raw:
            return None
        try:
            from PIL import Image
            import io
            im = Image.open(io.BytesIO(raw)).convert("RGB")
            side = max(im.size)
            canvas = Image.new("RGB", (side, side), TILE_BG)
            canvas.paste(im, ((side - im.size[0]) // 2, (side - im.size[1]) // 2))
            canvas = canvas.resize((size, size), Image.LANCZOS)
            buf = io.BytesIO()
            canvas.save(buf, "PNG", optimize=True)
            return buf.getvalue()
        except Exception:
            return None

    return cached_art("appicon", (size,), produce)


def map_shot_png(game, mapname, size=(160, 120)):
    """A picture of a level, as JPEG, cached.

    Quake III and Half-Life have one each, by different routes. Quake and
    Quake II genuinely ship no per-level artwork of any kind — checked, not
    assumed — so their map pickers stay text."""
    if not GAMES[game].get("has_shots") and not GAMES[game].get("has_plans"):
        return None
    cfg = GAMES[game]

    def produce():
        if cfg.get("has_plans"):
            return _bsp_plan(game, mapname, size)
        raw, placeholder = _shot_raw(cfg, mapname)
        if not raw:
            return None
        try:
            from PIL import Image
            import io
            im = Image.open(io.BytesIO(raw))
            if cfg.get("shots") and not placeholder:
                im = _dechroma(im, size)
            else:
                im = im.convert("RGB")
                im.thumbnail(size, Image.LANCZOS)
            buf = io.BytesIO()
            im.save(buf, "JPEG", quality=72, optimize=True)
            return buf.getvalue()
        except Exception:
            return None

    # Substitute rather than delete: deleting would map two different map
    # names onto one cache file and serve the wrong picture for one of them.
    safe = re.sub(r"[^A-Za-z0-9_.+-]", "_", mapname)
    return cached_art("shot", (game, safe, "%dx%d" % size), produce)


def bot_icon_png(game, bot, size=64):
    """A bot's face as PNG bytes, cached on disk.

    The originals are 1999-era TGA, which no browser reads, so they are decoded
    once and kept as PNG under the state directory."""
    def produce():
        src = bot_models(game).get(bot)
        if not src:
            return None
        try:
            from PIL import Image
            import io
            with zipfile.ZipFile(src[0]) as z:
                raw = z.read(src[1])
            im = Image.open(io.BytesIO(raw)).convert("RGB")
            im = im.resize((size, size), Image.LANCZOS)
            buf = io.BytesIO()
            im.save(buf, "PNG", optimize=True)
            return buf.getvalue()
        except Exception:
            return None

    safe = re.sub(r"[^A-Za-z0-9_.+-]", "_", bot)
    return cached_art("boticon", (game, safe, size), produce)


def bots_for(game, ttl=3600):
    """The bot roster, read from scripts/bots.txt inside the pk3s.

    That file is what `addbot` resolves a name against, so reading it is the
    only way to be sure every offered name actually works. Note the entries are
    unquoted (`name\t\tXaero`) and the file order is by tier — Xaero hardest,
    Crash easiest — which is not the order anyone wants in a dropdown."""
    if not GAMES[game].get("has_bots"):
        return []
    hit = _BOTS_CACHE.get(game)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    cfg = GAMES[game]
    names, seen = [], set()
    for path in sorted(glob.glob(os.path.join(cfg["dir"], cfg["paks"]))):
        try:
            z = zipfile.ZipFile(path)
        except (OSError, zipfile.BadZipFile):
            continue
        for entry in z.namelist():
            if entry.lower() != "scripts/bots.txt":
                continue
            try:
                txt = z.read(entry).decode("latin-1", "replace")
            except (OSError, KeyError):
                continue
            for n in re.findall(r'^\s*name\s+"?([^"\r\n]+?)"?\s*$', txt, re.M):
                n = n.strip()
                if SAFE_TOKEN.match(n) and n.lower() not in seen:
                    seen.add(n.lower())
                    names.append(n)
    names.sort(key=str.lower)
    _BOTS_CACHE[game] = (time.time(), names)
    return names


_TITLES_CACHE = {}


def _pak_index(pak):
    out = {}
    try:
        with open(pak, "rb") as f:
            if f.read(4) != b"PACK":
                return out
            ofs, ln = struct.unpack("<ii", f.read(8))
            f.seek(ofs)
            for _ in range(ln // 64):
                nm = f.read(56).split(b"\0")[0].decode("latin-1")
                pos, sz = struct.unpack("<ii", f.read(8))
                out[nm.lower().replace("\\", "/")] = (pos, sz)
    except (OSError, struct.error, UnicodeDecodeError):
        pass
    return out


_ENTS_CACHE = {}


def _all_entities(game, ttl=3600):
    """{map: entity lump text} for every map this game has, loose or in a pak.

    Shared by the level-name reader and the campaign-order walk, because both
    want the same thing and reading a few hundred BSP headers twice would be
    silly."""
    hit = _ENTS_CACHE.get(game)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    cfg = GAMES[game]
    out = {}
    index = {}
    for pak in sorted(glob.glob(os.path.join(cfg["dir"], cfg["paks"]))):
        for k, v in _pak_index(pak).items():
            index.setdefault(k, (pak, v))
    loose = glob.glob(os.path.join(cfg["dir"], "maps", "*.bsp"))
    for name in list(index) + loose:
        try:
            if name in index:
                if not name.startswith("maps/") or not name.endswith(".bsp"):
                    continue
                mapname = os.path.basename(name)[:-4]
                pak, (pos, _sz) = index[name]
                fh = open(pak, "rb")
                base = pos
            else:
                mapname = os.path.basename(name)[:-4]
                fh = open(name, "rb")
                base = 0
            with fh:
                fh.seek(base)
                # 16, not 12. Quake's lump table starts at byte 4 so 12 is
                # enough for it, but Quake II's starts at 8 and a 12-byte read
                # leaves only 4 bytes to unpack 8 from. That threw struct.error
                # into the except below on every single IBSP map, which is why
                # Quake II looked as though it shipped no level names at all.
                # It ships all of them.
                head = fh.read(16)
                if len(head) < 16:
                    continue
                off = 8 if head[:4] == b"IBSP" else 4
                eofs, elen = struct.unpack("<ii", head[off:off + 8])
                if elen <= 0 or elen > 4_000_000:
                    continue
                fh.seek(base + eofs)
                out[mapname] = fh.read(elen).decode("latin-1", "replace")
        except (OSError, struct.error, ValueError):
            continue
    _ENTS_CACHE[game] = (time.time(), out)
    return out


def map_titles(game, ttl=3600):
    """{map: proper name}, where the game actually knows one.

    Three of the four can be trusted, which was worth checking rather than
    assuming:

      Quake      worldspawn "message" is the level name, on 38 of 51 maps
                 including every deathmatch level. Read the WHOLE entity lump —
                 capping it silently loses the name on bigger maps, which made
                 e1m1 look nameless at first.
      Quake II   worldspawn "message" too, on all 47: "The Edge", "Lava Tomb",
                 "Tokay's Towers". This was written off as "empty on every map"
                 for a while, which was a bug in the reader and not a fact
                 about the game — see the 16-byte header read below.
      Quake III  no worldspawn message, but .arena files carry a longname.
                 Only 5 maps here have one; the stock names live in game code.
      Half-Life  worldspawn message holds something else entirely — crossfire's
                 is "desert", a skybox; stalkyard's is "warez". An early
                 version of this reported every map as "Black Mesa Inbound",
                 which is worse than no name at all, so Half-Life is skipped
                 deliberately. Its overview pictures are used instead."""
    hit = _TITLES_CACHE.get(game)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    cfg = GAMES[game]
    titles = {}
    if not cfg.get("has_titles"):
        _TITLES_CACHE[game] = (time.time(), titles)
        return titles

    if cfg["paks"].endswith("pk3"):
        for path in sorted(glob.glob(os.path.join(cfg["dir"], cfg["paks"]))):
            try:
                z = zipfile.ZipFile(path)
            except (OSError, zipfile.BadZipFile):
                continue
            for entry in z.namelist():
                if not entry.lower().endswith(".arena"):
                    continue
                try:
                    txt = z.read(entry).decode("latin-1", "replace")
                except (OSError, KeyError):
                    continue
                for mp, ln in re.findall(r'map\s+"([^"]+)"[^}]*?longname\s+"([^"]+)"',
                                         txt, re.S):
                    titles.setdefault(mp, ln)
    else:
        for mapname, ents in _all_entities(game).items():
            # worldspawn is always the first entity, and only worldspawn's
            # message is the level name — a trigger's is on-screen text.
            m = re.search(r'"message"\s*"([^"]+)"', ents.split("}")[0])
            if m and m.group(1).strip():
                titles.setdefault(mapname, m.group(1).strip())

    _TITLES_CACHE[game] = (time.time(), titles)
    return titles


_MAPS_CACHE = {}


def maps_for(game, ttl=600):
    """{mode: [map...]} plus 'all'. Cached: re-reading 500 MB of pk3s on every
    page load would make the UI feel broken."""
    hit = _MAPS_CACHE.get(game)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    cfg = GAMES[game]
    found = set()
    if cfg.get("dir") and cfg.get("paks"):
        for p in glob.glob(os.path.join(cfg["dir"], cfg["paks"])):
            found |= set(_pk3_maps(p) if p.endswith(".pk3") else _pak_maps(p))
        for p in glob.glob(os.path.join(cfg["dir"], "maps", "*.bsp")):
            found.add(os.path.basename(p)[:-4])
    found = {m for m in found if not MAP_JUNK.match(m) and SAFE_TOKEN.match(m)}
    grouped = {"all": sorted(found)}
    for mode, pattern in MAP_RULES.get(game, []):
        rx = re.compile(pattern, re.I)
        grouped[mode] = sorted(m for m in found if rx.match(m))

    # Co-op is the campaign, and the campaign is defined by the maps rather
    # than by a pattern here. The hand-written one had quietly been missing
    # Quake II's mintro, power1 and power2 for as long as it existed. Keep
    # whatever the pattern also caught — boss1 and boss2 are real levels that
    # nothing changelevels into, because you are teleported.
    if "coop" in cfg["modes"]:
        campaign = set(campaign_order(game))
        if campaign:
            grouped["coop"] = sorted(campaign | set(grouped.get("coop") or []))
    for mode in cfg["modes"]:
        if not grouped.get(mode):
            grouped[mode] = grouped["all"]
    _MAPS_CACHE[game] = (time.time(), grouped)
    return grouped


_ORDER_CACHE = {}


def campaign_order(game, ttl=3600):
    """The campaign in the order it is meant to be played, read out of the maps.

    Co-op is the story, so listing its levels alphabetically puts "biggun"
    third and "boss2" sixth. The real order is in the maps themselves: every
    level carries changelevel entities naming where its exits go, so walking
    that graph from the first level reconstructs the campaign.

    Two things make the entities harder to read than they look. A destination
    can be written "base3$train", where the part after $ is which spawn point
    to arrive at, and it can be written "eou2_.cin+*jail1", meaning "play this
    cinematic, then load jail1" — reading the part before the + gives you the
    name of a video file rather than the level it leads to.

    Exits are followed in name order, because the order entities happen to sit
    in the lump is not the order you meet them in, and within one hub the
    names do run in sequence.

    Returns {map: position}. Anything not reachable — deathmatch levels, the
    boss maps you are teleported into — simply is not in it."""
    hit = _ORDER_CACHE.get(game)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]

    start = GAMES[game].get("campaign_start")
    order = {}
    if not start:
        _ORDER_CACHE[game] = (time.time(), order)
        return order

    graph = {}
    for mapname, ents in _all_entities(game).items():
        dests = []
        for block in ents.split("}"):
            if "changelevel" not in block:
                continue
            m = re.search(r'"map"\s+"([^"]+)"', block)
            if not m:
                continue
            dest = m.group(1).strip()
            if "+*" in dest:
                dest = dest.split("+*", 1)[1]
            dest = dest.split("$")[0].strip().lower()
            if dest and "." not in dest:
                dests.append(dest)
        graph[mapname] = sorted(set(dests))

    seen = []
    stack = [start]
    while stack:
        m = stack.pop(0)
        if m in order or m not in graph:
            continue
        order[m] = len(order)
        seen.append(m)
        stack = graph[m] + stack        # depth first, exits in name order

    _ORDER_CACHE[game] = (time.time(), order)
    return order


def next_map(game, mode, current, listed):
    """The level that comes after this one.

    In co-op that means the next one in the campaign, which is the whole point
    of having worked the campaign order out. In deathmatch there is no such
    thing, so it means the next one in the list, wrapping at the end — which
    is what a map rotation is."""
    if not listed:
        return None
    if current not in listed:
        return listed[0]
    if mode == "coop":
        order = campaign_order(game)
        if order and current in order:
            after = sorted((pos, m) for m, pos in order.items() if pos > order[current])
            for _pos, m in after:
                if m in listed:
                    return m
            return None                      # the end of the campaign is the end
    i = listed.index(current)
    return listed[(i + 1) % len(listed)]


def sort_maps(game, mode, maps):
    """Campaign maps in campaign order; everything else alphabetically."""
    if mode not in ("coop",):
        return maps
    order = campaign_order(game)
    if not order:
        return maps
    # Anything outside the campaign sorts after it, alphabetically.
    return sorted(maps, key=lambda m: (order.get(m, len(order)), m))


# ---------------------------------------------------------- live server state
def _udp(port, payload, timeout=1.0, tries=3):
    """Ask a game engine a question over UDP, and do not take silence for an
    answer the first time.

    These engines are single-threaded: while one is busy running a frame with
    a few bots in it, an inbound status packet can simply be dropped. With one
    attempt that showed up in the UI as "not answering" on a server that was
    perfectly healthy — a lie that is worse than a slow answer."""
    for attempt in range(tries):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(payload, ("127.0.0.1", port))
            return s.recvfrom(16384)[0]
        except OSError:
            if attempt + 1 == tries:
                return None
        finally:
            s.close()
    return None


def _quake_ctl(body):
    """NetQuake control packet: big-endian length with the control flag set,
    then the payload."""
    return struct.pack(">I", 0x80000000 | (len(body) + 4)) + body


def _quake_rules(port):
    """Quake's own cvars, by walking CCREQ_RULE_INFO.

    You ask for the rule after the one you last saw and it hands back a name
    and a value until it runs out. Only cvars the engine chose to publish come
    back — fraglimit, timelimit, teamplay and noexit do; deathmatch and coop do
    not, which is why the mode still has to be remembered for this one."""
    out = {}
    prev = b""
    for _ in range(40):
        d = _udp(port, _quake_ctl(bytes([0x04]) + prev + b"\0"), timeout=0.4, tries=1)
        if not d or len(d) < 6 or d[4] != 0x85:
            break
        name, _, tail = d[5:].partition(b"\0")
        if not name:
            break
        out[name.decode("latin-1")] = tail.partition(b"\0")[0].decode("latin-1")
        prev = name
    return out


def _halflife_rules(port):
    """Half-Life's cvars, via A2S_RULES.

    It answers this without a challenge, and it answers it fully: mp_teamplay,
    the frag and time limits, and mp_fragsleft and mp_timeleft, which are how
    much of the current round is left to play. The UI was guessing at all of
    this while the server was willing to say."""
    d = _udp(port, b"\xff\xff\xff\xffV\xff\xff\xff\xff", timeout=1.0, tries=2)
    if not d or len(d) < 7 or d[4:5] != b"E":
        return {}
    parts = d[7:].split(b"\0")
    out = {}
    for i in range(0, len(parts) - 1, 2):
        if parts[i]:
            out[parts[i].decode("latin-1")] = parts[i + 1].decode("latin-1")
    return out


def _infostring(text):
    parts = text.strip("\\").split("\\")
    return dict(zip(parts[0::2], parts[1::2]))


_LIVE_CACHE = {}


def live_state(game, ttl=2.0):
    """Map, mode, players and scores from the engine's own status protocol.

    Parsing console text would be fragile and engine-version dependent; these
    wire formats are the same ones every server browser has used since 1997.

    Memoised for a couple of seconds because rendering one page asks for this
    several times per game, and each ask is a round trip to an engine that has
    a deathmatch to run."""
    hit = _LIVE_CACHE.get(game)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    out = _live_state_uncached(game)
    _LIVE_CACHE[game] = (time.time(), out)
    return out


def _live_state_uncached(game):
    cfg = GAMES[game]
    out = {"map": None, "mode": None, "count": None, "max": None,
           "players": [], "up": False, "cvars": {}}
    try:
        if game == "quake":
            d = _udp(cfg["port"], bytes([0x80, 0, 0, 12, 2]) + b"QUAKE" + bytes([0, 3]))
            if d:
                out["up"] = True
                f = d[5:].split(b"\0", 3)
                if len(f) > 2:
                    out["map"] = f[2].decode("latin-1")
                if len(f) > 3 and len(f[3]) >= 2:
                    out["count"], out["max"] = f[3][0], f[3][1]

                out["cvars"] = _quake_rules(cfg["port"])
                # teamplay is published; deathmatch and coop are not, so those
                # two still have to be remembered rather than read.
                if out["cvars"].get("teamplay", "0") not in ("0", ""):
                    out["mode"] = "team"

                # Who is in there, and with how many frags. NetQuake answers a
                # per-slot query rather than listing everyone at once, and only
                # for slots that are occupied, so stop once they are all found.
                for slot in range(_as_int(out["max"]) or 8):
                    if len(out["players"]) >= (_as_int(out["count"]) or 0):
                        break
                    pd = _udp(cfg["port"], _quake_ctl(bytes([0x03, slot])),
                              timeout=0.4, tries=1)
                    if not pd or len(pd) < 6 or pd[4] != 0x84:
                        continue
                    name, _, tail = pd[6:].partition(b"\0")
                    if len(tail) < 12:
                        continue
                    _colors, frags, secs = struct.unpack("<iii", tail[:12])
                    out["players"].append({
                        "name": name.decode("latin-1"),
                        "score": str(frags),
                        # NetQuake reports no ping here, but it does report how
                        # long you have been connected, which is worth more.
                        "ping": None,
                        "secs": secs,
                    })
        elif game in ("quake2", "quake3"):
            probe = (b"\xff\xff\xff\xffstatus\n" if game == "quake2"
                     else b"\xff\xff\xff\xffgetstatus\n")
            d = _udp(cfg["port"], probe)
            if d:
                out["up"] = True
                lines = d[4:].decode("latin-1").split("\n")
                info = _infostring(lines[1] if len(lines) > 1 else "")
                out["cvars"] = info
                out["map"] = info.get("mapname")
                out["max"] = info.get("maxclients") or info.get("sv_maxclients")
                for ln in lines[2:]:
                    ln = ln.strip()
                    if not ln:
                        continue
                    m = re.match(r'^(-?\d+)\s+(\d+)\s+"?(.*?)"?$', ln)
                    if m:
                        out["players"].append({"score": m.group(1), "ping": m.group(2),
                                               "name": m.group(3)})
                out["count"] = len(out["players"])
                if game == "quake3":
                    out["mode"] = {"0": "ffa", "1": "duel", "3": "team",
                                   "4": "ctf"}.get(info.get("g_gametype"))
                    # `teams` is one letter per player line, in the order the
                    # player lines came — R red, B blue, S spectator, F free.
                    # Added in old-mac-quake3 server-v0.6.3, asked for in #18.
                    #
                    # Attached HERE, by index, and not later: everything
                    # downstream sorts these players by score, and a positional
                    # key applied after a sort is off by however far the sort
                    # moved them. That is a bug that looks like the engine
                    # reporting the wrong side.
                    letters = info.get("teams") or ""
                    if len(letters) == len(out["players"]):
                        names = {"R": "red", "B": "blue",
                                 "S": "spec", "F": None}
                        for pl, ch in zip(out["players"], letters):
                            pl["team"] = names.get(ch.upper())
                else:
                    # The engine publishes `deathmatch` but never `coop`, and
                    # when deathmatch is 0 the key drops out of serverinfo
                    # altogether. So absent means 0, and on a dedicated server
                    # not-deathmatch means co-op — sv_init.c forces maxclients
                    # to 1 otherwise, and it reports 4 here.
                    out["mode"] = "dm" if info.get("deathmatch") == "1" else "coop"
        elif game == "halflife":
            out["cvars"] = _halflife_rules(cfg["port"])
            # Half-Life does publish its gametype after all, as mp_teamplay.
            # This was being guessed at from a config file that has the line
            # commented out, and the guess was wrong.
            if out["cvars"]:
                out["mode"] = ("team" if out["cvars"].get("mp_teamplay", "0") not in ("0", "")
                               else "dm")
            d = _udp(cfg["port"], b"\xff\xff\xff\xffTSource Engine Query\x00")
            if d and len(d) > 6:
                out["up"] = True
                f = d[6:].split(b"\0")
                if len(f) > 1:
                    out["map"] = f[1].decode("latin-1")
                # name\0 map\0 folder\0 game\0 then int16 appid, byte players, byte max
                if len(f) > 4:
                    tail = d[6:].split(b"\0", 4)[4]
                    if len(tail) >= 4:
                        out["count"], out["max"] = tail[2], tail[3]
        elif game == "alephone":
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect(("127.0.0.1", cfg["port"]))
                s.close()
                out["up"] = True
            except OSError:
                pass
    except (OSError, ValueError, IndexError, UnicodeDecodeError, struct.error):
        pass
    return out


def unit_state(unit):
    return run(["systemctl", "is-active", unit]).stdout.strip() or "unknown"


def _as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def human_bytes(n):
    for unit in ("B", "kB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return "%.0f %s" % (n, unit) if unit in ("B", "kB") else "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%.1f TB" % n


def host_stats():
    """How the box itself is doing.

    Everything here comes out of /proc and statvfs — no extra daemon, nothing
    to install, nothing that costs anything. Each figure is paired with what it
    is a fraction OF, because "load 0.32" means one thing on a 16-core machine
    and quite another on this one, which has exactly one core."""
    out = {"uptime": None, "load": None, "cores": os.cpu_count() or 1,
           "mem_used": None, "mem_total": None,
           "disk_used": None, "disk_total": None,
           "sent": None, "received": None,
           "sent_month": None, "sent_since": None}
    try:
        with open("/proc/uptime") as f:
            secs = int(float(f.read().split()[0]))
        d, rem = divmod(secs, 86400)
        h, m = divmod(rem // 60, 60)
        out["uptime"] = ("%dd %dh" % (d, h)) if d else ("%dh %dm" % (h, m) if h else "%dm" % m)
        with open("/proc/loadavg") as f:
            out["load"] = f.read().split()[0]
    except (OSError, ValueError, IndexError):
        pass

    try:
        info = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, v = line.partition(":")
                info[k] = int(v.split()[0]) * 1024
        out["mem_total"] = info.get("MemTotal")
        if info.get("MemTotal") and info.get("MemAvailable"):
            out["mem_used"] = info["MemTotal"] - info["MemAvailable"]
    except (OSError, ValueError, IndexError):
        pass

    try:
        v = os.statvfs("/")
        out["disk_total"] = v.f_blocks * v.f_frsize
        out["disk_used"] = (v.f_blocks - v.f_bfree) * v.f_frsize
    except OSError:
        pass

    # Transfer out is the only number here that could ever turn into a bill —
    # Always Free includes 10 TB a month, and four 1990s game servers are not
    # going to find the edge of that. Counters reset when the box reboots.
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                name, _, rest = line.partition(":")
                if name.strip().startswith(("enp", "eth", "ens")):
                    cols = rest.split()
                    out["received"] = int(cols[0])
                    out["sent"] = int(cols[8])
                    break
    except (OSError, ValueError, IndexError):
        pass

    vn = vnstat_month()
    if vn:
        out["sent_month"], out["sent_since"] = vn
    return out


def vnstat_month():
    """Bytes sent this calendar month, and the date counting began.

    /proc/net/dev resets at boot, so the figure it gives is "since this box
    last started" — honest, but useless against an allowance measured per
    month. vnstat keeps its own database and survives reboots, which is the
    whole reason it exists.

    Returns (sent_bytes, first_seen_date) or None. Never raises: a box without
    vnstat falls back to the since-boot number rather than showing nothing."""
    try:
        r = run(["vnstat", "--json", "m"], timeout=6)
        if r.returncode != 0:
            return None
        d = json.loads(r.stdout)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    for iface in d.get("interfaces") or []:
        months = ((iface.get("traffic") or {}).get("month")) or []
        if not months:
            # Installed but has not completed a sampling interval yet.
            created = ((iface.get("created") or {}).get("date")) or {}
            if created:
                return (0, "%04d-%02d-%02d" % (created.get("year", 0),
                                               created.get("month", 0),
                                               created.get("day", 0)))
            return None
        now = months[-1]
        date = now.get("date") or {}
        created = ((iface.get("created") or {}).get("date")) or {}
        return (int(now.get("tx") or 0),
                "%04d-%02d-%02d" % (created.get("year", date.get("year", 0)),
                                    created.get("month", date.get("month", 0)),
                                    created.get("day", 1)))
    return None


def unit_memory(unit):
    out = run(["systemctl", "show", unit, "-p", "MemoryCurrent", "--value"])
    try:
        n = int(out.stdout.strip())
        return n if n > 0 else None
    except (ValueError, AttributeError):
        return None


def _systemd_time(s):
    """One of systemd's timestamps as an epoch, or None.

    It prints a weekday in front and the box's own zone behind:
    "Fri 2026-08-22 12:15:22 UTC". Only the date and time are read. The result
    is local-time epoch and everything compared against it is produced on the
    same box, so the zone never enters into it. Empty when a unit has never
    started, which is why None is a real answer and not an error."""
    m = re.search(r"(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})", s or "")
    if not m:
        return None
    y, mo, d, h, mi, sec = (int(x) for x in m.groups())
    try:
        return time.mktime((y, mo, d, h, mi, sec, 0, 0, -1))
    except (OverflowError, ValueError):
        return None


_BUILD_CACHE = {}
_BUILD_LOCK = threading.Lock()


def server_build(game, ttl=60.0):
    """What the installed server says about itself. (#6)

    Every port ships BUILD-INFO.txt at the install root, and `retro deploy`
    already reads its Version line (bin/retro:340-344). This is the same file,
    read for display rather than for a gate.

    THE FIELD NAME IS NOT THE SAME IN ALL FOUR. Quake, Quake II and Quake III
    write `Built from`; Half-Life writes `Our build id`. Matching only the
    first spelling leaves Half-Life permanently blank, which reads as a missing
    file rather than as a different word for the same thing.

    Cached for a minute. It changes only on deploy, and `retro deploy` does not
    restart this process, so it cannot be read once at import and kept.

    Returns {} when there is nothing to say. A server whose BUILD-INFO cannot
    be read should show no provenance line at all, rather than a blank one that
    looks like a build with no source."""
    now = time.time()
    with _BUILD_LOCK:
        hit = _BUILD_CACHE.get(game)
        if hit and now - hit[0] < ttl:
            return hit[1]
    cfg = GAMES.get(game) or {}
    # cfg["dir"] is the game CONTENT directory (.../id1, .../baseq2). The
    # tarball puts BUILD-INFO.txt one level up, at the install root.
    root = os.path.dirname(cfg.get("dir") or "")
    out = {}
    try:
        with open(os.path.join(root, "BUILD-INFO.txt")) as f:
            for ln in f:
                k, _, v = ln.partition(":")
                k = k.strip()
                v = v.strip()
                if not v:
                    continue
                if k == "Version":
                    out["version"] = v[:40]
                elif k in ("Built from", "Our build id"):
                    out["source"] = v[:60]
                elif k == "Built on":
                    out["built"] = v[:40]
    except OSError:
        out = {}
    # ADR 0001: this repo builds nothing and cannot attest that a binary came
    # from the source it names. It can at least show when the artifact says so
    # itself. Quake III v0.6.3 reads "git 768a004d (working tree modified)".
    out["dirty"] = "modif" in (out.get("source") or "").lower()
    with _BUILD_LOCK:
        _BUILD_CACHE[game] = (now, out)
    return out


def build_html(game):
    """The provenance line for one server, or nothing at all."""
    b = server_build(game)
    if not b.get("version"):
        return ""
    bits = ["Server %s" % html.escape(b["version"])]
    src = b.get("source") or ""
    # The artifact writes its own dirty marker into the same field -- quake3
    # reads "git 768a004d (working tree modified)". Leaving it there and then
    # appending the badge printed the fact twice. Strip the parenthetical and
    # let the badge carry it, so the hash stays readable.
    src = re.sub(r"\s*\((?:[^()]*modif[^()]*)\)\s*$", "", src).strip()
    if src:
        bits.append(html.escape(src))
    line = " · ".join(bits)
    if b.get("dirty"):
        # Deliberately visible rather than hidden. ADR 0001 accepted serving
        # an artifact built from a modified tree; it did not decide to keep
        # that fact off the page, and nobody looking at the UI could tell.
        line += " <span class=build-dirty>modified tree</span>"
    return "<p class=build>%s</p>" % line


def unit_health(unit):
    """Whether systemd has had to restart this unit, and when it last started.

    The page showed the state right now and nothing else, so Half-Life
    segfaulting at 12:15 and coming back five seconds later looked exactly
    like a server that had been up all day. Everyone playing at that moment
    was dropped and nothing on the page ever said so. (#2)

    NRestarts counts systemd's own restarts after a failure. Stopping and
    starting deliberately — which is what the Restart button does — leaves it
    at 0 and moves only the start time. That is what makes this worth showing
    instead of noisy: it counts the times nobody asked for.

    Same `systemctl show` call unit_memory() already makes, and it needs no
    privilege retroadmin does not already have."""
    out = run(["systemctl", "show", unit, "-p", "NRestarts",
               "-p", "ActiveEnterTimestamp"])
    vals = {}
    for ln in (out.stdout or "").splitlines():
        k, _, v = ln.partition("=")
        vals[k.strip()] = v.strip()
    return {"restarts": _as_int(vals.get("NRestarts")),
            "since": _systemd_time(vals.get("ActiveEnterTimestamp"))}


def _since_text(epoch):
    """How long ago, in the one unit that reads at a glance."""
    if not epoch:
        return ""
    secs = time.time() - epoch
    if secs < 0:
        return ""
    if secs < 90:
        return "%ds" % int(secs)
    if secs < 5400:
        return "%dm" % int(secs // 60)
    if secs < 172800:
        return "%dh" % int(secs // 3600)
    return "%dd" % int(secs // 86400)


def life_html(game, unit, state):
    """How long this server has been up, and a different sentence when it did
    not stay up by itself.

    When it is not running at all, this is where the page has to say WHY.
    Before #9 nothing could stop a server from the UI, so "not running" always
    meant something had gone wrong. Now it usually means somebody parked it,
    and a parked server must never read like a crashed one."""
    if state != "active":
        stop = remembered_stop(game)
        if stop:
            return ("<span class=parked>stopped by %s, %s</span>"
                    % (html.escape(stop.get("by") or "someone"),
                       html.escape(human_ago(stop.get("at")))))
        # Nobody here claimed it, and systemd cannot say why.
        #
        # This drop-in read `failed` as "it could not stay up" until it was
        # exercised on the box. Measured 2026-08-23: a deliberate
        # `systemctl stop ioq3ded` leaves Result=exit-code, ExecMainStatus=1
        # and is-active reporting FAILED -- the engine exits 1 on SIGTERM, so
        # a clean stop is indistinguishable from a crash at this level.
        #
        # That makes the recorded attribution above the only thing that can
        # tell them apart, rather than a nicety on top of systemd. So this
        # says what is actually known and no more.
        return "<span class=relit>not running, and nobody here stopped it</span>"
    h = unit_health(unit)
    if h["restarts"]:
        at = time.strftime("%H:%M", time.localtime(h["since"])) if h["since"] else "?"
        times = "once" if h["restarts"] == 1 else "%d times" % h["restarts"]
        return ("<span class=relit>restarted itself %s, %s</span>"
                % (times, html.escape(at)))
    up = _since_text(h["since"])
    return ("up %s" % html.escape(up)) if up else ""


def _all_sets():
    """Every named set in the table, from ONE nft call.

    This used to be one `sudo nft -j list set ...` per set. A single
    /api/status asks for five and repeats two of them -- six sudo processes,
    each opening and closing a PAM session, every eight seconds, for every
    open tab. Two things came of that, and neither looked like a caching
    problem from the outside:

      * 74,000 journal lines a day from this one service, more than everything
        else on the box combined, which is what the 2026-09-02 OOM was hiding
        in.
      * the OOM itself. The kernel trace names `systemctl invoked oom-killer`
        inside this cgroup with python3 as the victim -- forking from a
        process already near MemoryMax is what tips it over, and this was by
        far the largest source of forks.

    Held for a moment so the several lookups inside one page render share a
    single call, and thrown away by run() the instant anything writes. The
    window is deliberately shorter than the 8s poll: it exists to collapse
    duplicates within one request, not to serve one request from another.

    A failed call caches an empty dict for that moment, so every set reads
    empty and every allowed-check says no. That is the same fail-closed answer
    the per-set version gave when nft failed, and it is the right way round:
    a firewall we cannot read is not one we should assume let someone in."""
    with _SETS_LOCK:
        if _sets_cache["sets"] is not None \
                and time.monotonic() - _sets_cache["at"] < _SETS_TTL:
            return _sets_cache["sets"]
    # `list sets inet`, not `list table inet filter`. Both return every set
    # with its elements in one call; only the second also hands this process
    # the whole rule chain, which it has no use for. Same saving, nothing
    # widened -- the sudoers grant stays as narrow in what it reveals as the
    # five per-set reads it replaces.
    out = run(["sudo", "nft", "-j", "list", "sets", "inet"])
    sets = {}
    if out.returncode == 0:
        try:
            for obj in json.loads(out.stdout).get("nftables", []):
                s = obj.get("set")
                if not isinstance(s, dict) or "name" not in s:
                    continue
                # Family-wide, so scope it back to our table by hand.
                if s.get("table") != "filter":
                    continue
                found = []
                for e in s.get("elem", []):
                    if isinstance(e, dict) and "elem" in e:
                        found.append((e["elem"]["val"], e["elem"].get("expires")))
                    else:
                        found.append((e, None))
                sets[s["name"]] = found
        except (ValueError, KeyError, TypeError):
            sets = {}
    with _SETS_LOCK:
        _sets_cache["at"], _sets_cache["sets"] = time.monotonic(), sets
    return sets


def set_members(name):
    # A set that does not exist reads as empty, exactly as it did when this
    # shelled out per set and nft exited non-zero for the missing name. That
    # matters for `blocked`, which lives only in the running ruleset on a box
    # whose /etc/nftables.conf predates it -- see firewall_canary in bin/retro.
    return _all_sets().get(name, [])


def human_secs(s):
    if s is None:
        return "permanent"
    if s >= 3600:
        return "%dh %02dm left" % (s // 3600, (s % 3600) // 60)
    if s >= 60:
        return "%dm left" % (s // 60)
    return "%ds left" % max(0, s)


def human_ago(ts):
    d = int(time.time()) - ts
    if d < 90:
        return "just now"
    if d < 5400:
        return "%dm ago" % (d // 60)
    return "%dh ago" % (d // 3600)


# When the copy of the site you are looking at went up.
#
# The mtime of this very file, read once at import. `retro admin` scps the
# module and `install`s it without -p, so that mtime is the moment of the
# deploy, not of the edit -- which is the question the footer is actually
# answering. Not "when was this written" but "is the page in front of me the
# change I just pushed, or is it still the old one?". That question was worth
# an evening on 2026-09-02, when a stale release version and a browser-cached
# zip each looked exactly like a deploy that had silently done nothing.
#
# Read once because the file cannot change under a running process, and a
# deploy restarts the unit, which re-reads it. If that ever stops being true
# the footer starts lying, so it is worth knowing.
try:
    DEPLOYED_AT = int(os.path.getmtime(os.path.abspath(__file__)))
except OSError:
    DEPLOYED_AT = None


def human_when(ts):
    """Relative while that still means something, absolute once it does not.

    human_ago() above tops out at hours, which is right for a grant that lasts
    twelve of them and wrong here -- a site deployed last week would read
    "216h ago", which is a number nobody converts in their head."""
    if ts is None:
        return "unknown"
    d = int(time.time()) - ts
    if d < 90:
        return "just now"
    if d < 3600:
        return "%dm ago" % (d // 60)
    if d < 86400:
        return "%dh ago" % (d // 3600)
    return time.strftime("%d %b", time.localtime(ts)).lstrip("0")


def nft_delete(setname, ip):
    """Drop an address from an nftables set. Returns (ok, error).

    nft exits non-zero when the element is not in the set, and that is the
    ordinary case here: a grant that has already timed out is gone before
    anyone presses Revoke. That is success from the caller's point of view.
    Any OTHER failure means the address is still allowed, and reporting it as
    revoked would be a lie about who can reach the box."""
    r = run(["sudo", "nft", "delete", "element", "inet", "filter", setname,
             "{ %s }" % ip])
    if r.returncode == 0 or "No such file or directory" in (r.stderr or ""):
        return True, ""
    return False, (r.stderr or "").strip() or "nft exited %d" % r.returncode


def console(game, command):
    # tee, not shell redirection: the FIFO is 0600 and owned by the game user.
    return run(["sudo", "tee", GAMES[game]["fifo"]], stdin=command + "\n").returncode == 0


def restart_lines():
    """Any server systemd has had to put back, as words for the log.

    These are synthesised from NRestarts rather than read from the units'
    journals, because retroadmin cannot read those — it is not in
    systemd-journal and has no sudoers line for journalctl. That is a
    deliberate limit and not an oversight: widening it so the page could quote
    the engine's own log is a separate decision for the user to take. (#2)

    The consequence is worth being honest about. Only the LAST restart has a
    time against it, and a unit that crashed and was restarted before the
    counter was reset shows the count without a history."""
    out = []
    for g, cfg in GAMES.items():
        h = unit_health(cfg["unit"])
        if not h["restarts"]:
            continue
        at = time.strftime("%H:%M", time.localtime(h["since"])) if h["since"] else "?"
        out.append("RESTARTED %s by itself, %s most recently (%d since boot)"
                   % (cfg["label"], at, h["restarts"]))
    return out


def activity_lines(n=40):
    """What the Activity page and the live poll both read.

    One function because two call sites drifting apart is how the page and
    its refresh end up disagreeing about what happened."""
    return restart_lines() + audit_tail(n)


def audit_tail(n=12):
    out = run(["journalctl", "-u", "retro-admin", "-n", "400", "--no-pager", "-o", "cat"])
    events = []
    for ln in out.stdout.splitlines():
        if not ln.startswith("retro-admin: "):
            continue
        body = ln[len("retro-admin: "):]
        if body.split(" ")[0] in ("ALLOW", "REVOKE", "MAP", "MODE", "RESTART",
                                  "STOP", "START", "SET", "DENIED"):
            events.append(body)
    return events[-n:][::-1]


ASSET_DIR = os.path.dirname(os.path.abspath(__file__))


def _asset(name):
    """Read a stylesheet or script that lives beside this file.

    They are separate files rather than string literals in here because a
    literal goes through Python's escaping on the way out, and an escaped
    double quote inside a triple-quoted block does not survive that trip: the
    backslash is consumed, the JavaScript string closes early, and the browser
    gets a syntax error. That is exactly what happened to the image dropdowns,
    and it meant not one line of script ran on the live site for days while the
    server looked perfectly healthy — because everything the script does is an
    enhancement over markup that stands up on its own.

    Read once at import. Restarting is how you deploy a change anyway."""
    try:
        with open(os.path.join(ASSET_DIR, name), encoding="utf-8") as f:
            return f.read()
    except OSError as exc:
        print("retro-admin: cannot read %s: %s" % (name, exc), flush=True)
        return ""


CSS = _asset("app.css")
APP_JS = _asset("app.js")
LIVE_JS = _asset("live.js")
# Read at import like the others, so a deploy that forgets to ship it fails
# loudly at start and is rolled back by `retro admin`, rather than 404ing the
# service worker at runtime and losing notifications quietly.
SW_JS = _asset("sw.js")

# Both scripts are inlined into the page — there is no external script anywhere,
# by design, because a CDN would be a third party inside a box whose entire
# security story is that nothing gets in. Inlining them used to mean the CSP had
# to say script-src 'unsafe-inline', which switches off the protection for every
# script on the page.
#
# Naming them by hash instead keeps them inline and still refuses anything else,
# so an injected <script> does not run even if something one day gets past the
# escaping. The hashes cover the EXACT bytes between the tags, so
# `<script>@@appjs@@</script>` must stay flush against the substitution: add a
# newline inside those tags and the browser silently refuses the script.
def _csp_sha256(text):
    return "'sha256-%s'" % base64.b64encode(
        hashlib.sha256(text.encode()).digest()).decode()


SCRIPT_SRC = " ".join(_csp_sha256(t) for t in (APP_JS, LIVE_JS))

SHELL = """<!doctype html><html lang=en><meta charset=utf-8>
<title>@@title@@ &middot; Retro servers</title>
<meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name=color-scheme content="light dark">
<!-- The whole page is exempted from Cloudflare's Email Obfuscation, not just
     the footer. That feature rewrites any address it finds into a script that
     resolves to /cdn-cgi/l/email-protection, which is a page nobody here can
     open — and this page prints the verified email of whoever did something on
     the footer, on every firewall grant, and on every line of the activity log.
     Wrapping them one at a time missed two of the three, twice. The proper fix
     is to turn the feature off for this hostname, but the API token is scoped
     to DNS and Access and cannot reach zone settings, and widening it for a
     cosmetic setting is a bad trade. This comment pair is Cloudflare's own
     documented opt-out. -->
<meta name=mobile-web-app-capable content=yes>
<meta name=apple-mobile-web-app-capable content=yes>
<meta name=apple-mobile-web-app-title content=Retro>
<!-- black-translucent puts the page under the status bar, which is why the
     wrap already pads by env(safe-area-inset-*). The two go together: either
     without the other looks broken on a notched phone. -->
<meta name=apple-mobile-web-app-status-bar-style content=black-translucent>
<meta name=theme-color content="#0d0e12" media="(prefers-color-scheme: dark)">
<meta name=theme-color content="#eceae6" media="(prefers-color-scheme: light)">
<!-- crossorigin=use-credentials is load-bearing, not boilerplate. A manifest
     is fetched with credentials mode "omit" by DEFAULT, so Safari asks for it
     without the Cloudflare Access cookie, Access answers 302 to the login, and
     the browser never receives a manifest at all. With no manifest there is no
     scope; iOS then falls back to the legacy apple-mobile-web-app-capable
     behaviour, where a Home Screen app opens EVERY link in a browser sheet —
     the one with "Done" in the corner that leaves the app where it was. This
     attribute makes the fetch send the cookie, which is the whole difference
     between an installed app and a bookmark that looks like one. -->
<link rel=manifest href="/pwa/manifest.webmanifest" crossorigin="use-credentials">
<link rel=icon href="@@favicon@@">
<link rel=apple-touch-icon href="/pwa/icon-180.png">
<style>@@css@@</style>
<script>@@appjs@@</script>
<main>
<!--email_off-->
<header>
  <h1>@@heading@@</h1>
  <p class=sub>@@subtitle@@</p>
</header>
<nav>@@nav@@</nav>
@@flash@@
<div class=stack>@@body@@</div>
<footer>
  <span class=live id=livebar>live</span> &middot; <span id=hoststats>@@hoststats@@</span><br>
  @@who@@ &middot; games on <code>@@gameshost@@</code><br>
  site updated @@updated@@
</footer>
<!--/email_off-->
</main>
@@script@@
</html>"""

NAV_ITEMS = [("/", "Overview"), ("/access", "Access"), ("/activity", "Activity")]


def nav_html(current):
    out = []
    for href, label in NAV_ITEMS:
        cls = " class=here" if href == current else ""
        out.append("<a href='%s'%s>%s</a>" % (href, cls, label))
    for g, cfg in GAMES.items():
        href = "/game/" + g
        cls = " class=here" if href == current else ""
        # The icon rides along in the nav too: on a phone the game names scroll
        # off, and the picture is recognisable at 18px where the word is not.
        out.append("<a href='%s'%s><img src='%s' alt='' width=18 height=18>%s</a>"
                   % (href, cls, art_url("/emblem/%s.png" % g),
                      html.escape(cfg["label"])))
    return "".join(out)


def shell(title, heading, subtitle, body, current, who, flash="", script="",
          totalplayers="", hoststats="", favicon="quake3"):
    """`favicon` is a game name: the tab gets that game's icon, so four tabs
    open on four servers are told apart at a glance. It also stops every page
    load ending in a 404 for /favicon.ico."""
    out = SHELL
    for k, v in (("@@css@@", CSS), ("@@appjs@@", APP_JS),
                 ("@@title@@", html.escape(title)),
                 ("@@heading@@", html.escape(heading)),
                 ("@@subtitle@@", subtitle), ("@@nav@@", nav_html(current)),
                 ("@@flash@@", flash), ("@@body@@", body),
                 ("@@who@@", html.escape(who)),
                 ("@@gameshost@@", html.escape(GAMES_HOST)),
                 ("@@script@@", script),
                 ("@@favicon@@", art_url("/emblem/%s.png" % favicon)),
                 ("@@totalplayers@@", html.escape(totalplayers)),
                 # Absolute time in the tooltip, because "3h ago" cannot be
                 # compared against the clock on the machine you deployed
                 # from. The box runs UTC and says so rather than implying
                 # local time it does not keep.
                 ("@@updated@@",
                  "<span title='%s'>%s</span>"
                  % (html.escape(time.strftime("%Y-%m-%d %H:%M UTC",
                                               time.gmtime(DEPLOYED_AT))
                                 if DEPLOYED_AT else "unknown"),
                     html.escape(human_when(DEPLOYED_AT)))),
                 ("@@hoststats@@", html.escape(hoststats))):
        out = out.replace(k, v)
    return out





def art_url(path):
    """Stamp the artwork revision onto an image URL.

    Every image here is served `immutable, max-age=604800`, which is right —
    these are 1999 pk3 files and they do not change. But it also means a
    browser that has seen /emblem/quake.png once will not ask again for a week,
    so replacing the picture behind a fixed URL changes nothing for anyone who
    has already loaded the page. That is precisely what happened to the new
    tile icons. The revision goes in the URL so a new image is a new URL."""
    return "%s?v=%d" % (path, ART_REV)


def players_line():
    total = sum((live_state(g).get("count") or 0) for g in GAMES)
    if total == 0:
        return "nobody playing"
    return "%d player%s online" % (total, "" if total == 1 else "s")


def resolve_mode(game, st, remember=False):
    """What mode this server is in.

    Quake III and Quake II say so in their status reply. Quake and Half-Life
    do not, so fall back to what was last applied through here, and failing
    that to what the server's own config leaves it in at startup. Where the
    engine does tell us it wins, and the remembered value is corrected —
    otherwise a mode changed by any other route leaves the UI lying."""
    mode = st.get("mode")
    if mode:
        if remember and remembered_mode(game) != mode:
            remember_mode(game, mode)
        return mode
    return remembered_mode(game) or GAMES[game].get("default_mode")


def meta_html(game, st):
    """Two lines: what is loaded, then how it is being played.

    One line wrapped mid-phrase — "0/8" on one row and "players" on the next —
    which is the sort of thing that makes a readout feel accidental."""
    if not st.get("up"):
        return "<span class=none>not answering</span>"

    where = ""
    if st.get("map"):
        # With the proper name where the game knows one. "q2dm1" tells you
        # nothing from across a room; "The Edge" tells you everything.
        title = map_titles(game).get(st["map"])
        where = ("map <code>%s</code>%s"
                 % (html.escape(st["map"]),
                    " <i>%s</i>" % html.escape(title) if title else ""))

    how = []
    mode = resolve_mode(game, st)
    if mode and mode in GAMES[game]["modes"]:
        how.append(GAMES[game]["modes"][mode][0])
    if st.get("count") is not None:
        # These come out of the engine's infostring rather than from a player,
        # so it takes console access to make them hostile. Escaped anyway —
        # everything that reaches the page from off-box goes through here.
        how.append("%s/%s players" % (html.escape(str(st["count"])),
                                      html.escape(str(st.get("max") or "?"))))

    # Third line: the limits the round is actually being played to, where the
    # engine publishes them, and the port you would type into a client.
    # Half-Life prefixes every one of these mp_, so look under both names
    # rather than silently showing nothing for it.
    cv = st.get("cvars") or {}

    def cvar(name):
        return cv.get(name) or cv.get("mp_" + name)

    rules = []
    frag = cvar("fraglimit")
    cap = cvar("capturelimit")
    # In CTF the captures end the game and the fraglimit does not, so leading
    # with "first to 20" describes a race nobody is running. The engine keeps
    # publishing both; only one of them is the win condition.
    if cap and cap != "0" and mode == "ctf":
        rules.append("first to %s captures" % html.escape(cap))
    elif frag and frag != "0":
        rules.append("first to %s" % html.escape(frag))
    tl = cvar("timelimit")
    if tl and tl != "0":
        rules.append("%s min" % html.escape(tl))
    # Half-Life counts down what is left of the round, which is worth more than
    # the limit it is counting towards.
    left = cv.get("mp_fragsleft")
    if left and left != "0" and frag and frag != "0":
        rules.append("%s to go" % html.escape(left))
    rules.append("udp %d" % GAMES[game]["port"])

    lines = []
    if where:
        lines.append("<span class=l>%s</span>" % where)
    if how:
        lines.append("<span class=l>%s</span>"
                     % " &middot; ".join("<span class=seg>%s</span>" % h for h in how))
    lines.append("<span class='l dim'>%s</span>"
                 % " &middot; ".join("<span class=seg>%s</span>" % r for r in rules))
    return "".join(lines) or "<span class=l>up</span>"


QUAKE3_COLOUR = re.compile(r"\^[0-9a-zA-Z]")


def human_secs_short(secs):
    m, sec = divmod(max(0, int(secs)), 60)
    h, m = divmod(m, 60)
    if h:
        return "%dh%02dm" % (h, m)
    return "%dm" % m if m else "%ds" % sec


def clean_name(game, name):
    """Quake III lets a player colour their name with ^1..^7 escapes, which
    arrive verbatim in the status reply. Bots never use them, so this went
    unnoticed until you imagine somebody actually joining."""
    if game == "quake3":
        name = QUAKE3_COLOUR.sub("", name)
    return name.strip() or "?"


def _limit(st, key):
    v = (st.get("cvars") or {}).get(key)
    try:
        n = int(v)
        return n if n > 0 else None
    except (TypeError, ValueError):
        return None


def render_match(game, st):
    """The match happening right now, as a frag race. Nothing is kept.

    Only drawn when somebody is actually in there — an empty server gets no
    chart, because a row of zero-length bars is worse than no bars.

    Everything here comes out of the status protocol the engine already
    answers: name, score, and ping. No history, no database, nothing to grow
    on disk. Refresh the page and it is recomputed from whatever the server
    says at that moment, which is the only thing that was ever true anyway."""
    players = list(st.get("players") or [])
    if not players:
        return ""

    def as_int(v, default=0):
        try:
            return int(v)
        except (TypeError, ValueError):
            return default

    players.sort(key=lambda p: as_int(p.get("score")), reverse=True)
    top = as_int(players[0].get("score"))
    fraglimit = _limit(st, "fraglimit")
    # The bar is scaled to the fraglimit where there is one, so the length of
    # it means "how close is this game to ending" and not merely "who is
    # winning". With no limit set, scale to the leader instead.
    target = fraglimit or max(top, 1)
    roster = bot_models(game) if GAMES[game].get("has_bots") else {}

    rows = []
    for i, p in enumerate(players):
        score = as_int(p.get("score"))
        pct = max(0.0, min(1.0, score / target)) if target else 0.0
        ping = p.get("ping")
        pn = as_int(ping, -1)
        if ping is None:
            # NetQuake reports no ping, but it does say how long you have been
            # connected, which is the more interesting number anyway.
            secs = as_int(p.get("secs"), 0)
            side = "%dm" % (secs // 60) if secs >= 60 else "%ds" % secs
            sidecls = "mut"
        elif pn <= 0:
            side, sidecls = "bot", "mut"
        else:
            side = "%dms" % pn
            sidecls = "up" if pn < 60 else ("warn" if pn < 120 else "down")
        # Same lookup the chips use, and it has to be exactly the same: the
        # roster is keyed by the CLEANED name and the icon route wants that
        # name url-quoted, not the model behind it. Keying it by model and
        # asking for .jpg — which is what this did first — silently produced no
        # face at all rather than an error.
        name = clean_name(game, p.get("name") or "")[:24]
        face = ""
        if p.get("ping") == "0" and name in roster:
            face = ("<img class=match-face src='%s' alt='' width=20 height=20 loading=lazy>"
                    % art_url("/icon/%s/%s.png" % (game, urllib.parse.quote(name))))
        side = p.get("team") if p.get("team") in ("red", "blue") else ""
        # Kick, not for a bot (bot roster/removal is its own control below)
        # and not for a gatherer game (alephone has no console to send it
        # through at all -- render_say already skips that game for the same
        # reason). The name sent is the RAW name the engine reported, not
        # the display-cleaned one -- post_kick matches it against a fresh
        # live_state() read, and a Quake III colour code stripped for
        # display would never match what the engine actually has on file.
        kick = ""
        if not GAMES[game].get("gatherer") and not (ping == "0" and name in roster):
            kick = ("<form method=post action=/kick data-confirm='Kick %s?'>"
                    "<input type=hidden name=game value='%s'>"
                    "<input type=hidden name=name value='%s'>"
                    "<button class='tiny danger' type=submit>Kick</button></form>"
                    % (html.escape(name), game,
                       html.escape(p.get("name") or "", quote=True)))
        rows.append(
            "<li class='match-row%s%s'>"
            "<span class=match-who>%s<span class=match-name>%s</span></span>"
            "<span class=match-track><span class=match-fill style='width:%.1f%%'></span></span>"
            "<span class=match-score>%d</span>"
            "<span class='match-ping %s'>%s</span>%s</li>"
            % (" lead" if i == 0 and len(players) > 1 and top > 0 else "",
               " side-" + side if side else "",
               face, html.escape(name),
               pct * 100, score, sidecls, side, kick))

    # A line of commentary, which is the whimsy. It is also the fastest way to
    # read the state of a game you are not in.
    note = ""
    if fraglimit and top >= fraglimit:
        note = "frag limit reached"
    elif fraglimit and top >= fraglimit - 1 and len(players) > 1:
        note = "match point"
    elif len(players) > 1:
        gap = top - as_int(players[1].get("score"))
        if top <= 0:
            note = "nobody has scored yet"
        elif gap == 0:
            note = "level pegging"
        elif gap == 1:
            note = "one frag in it"
        else:
            note = "%d clear" % gap
    elif top > 0:
        note = "alone, and winning"
    else:
        note = "warming up"

    # Team modes lead with the teams, because in CTF the individual frag
    # ranking is frequently the wrong answer — the player with the most kills
    # is often on the losing side. score_red and score_blue arrive in the
    # serverinfo as of old-mac-quake3 server-v0.6.2, added for exactly this.
    teams = ""
    cv = st.get("cvars") or {}
    if st.get("mode") in ("team", "ctf") and ("score_red" in cv or "score_blue" in cv):
        red, blue = as_int(cv.get("score_red")), as_int(cv.get("score_blue"))
        cap = _limit(st, "capturelimit") if st.get("mode") == "ctf" else fraglimit
        tt = cap or max(red, blue, 1)
        unit = "captures" if st.get("mode") == "ctf" else "frags"
        rows_t = []
        for label, val, cls in (("Red", red, "red"), ("Blue", blue, "blue")):
            rows_t.append(
                "<li class='team-row %s'>"
                "<span class=team-name>%s</span>"
                "<span class=match-track><span class=team-fill style='width:%.1f%%'></span></span>"
                "<span class=match-score>%d</span></li>"
                % (cls, label, max(0.0, min(1.0, val / tt)) * 100 if tt else 0, val))
        teams = ("<ul class=team-list>%s</ul>"
                 "<p class=match-foot>%s &middot; first to %s</p>"
                 % ("".join(rows_t), unit, cap if cap else "no limit"))
        # The commentary should be about the teams, not the top fragger.
        if cap and max(red, blue) >= cap:
            note = "%s take it" % ("Red" if red > blue else "Blue")
        elif red == blue:
            note = "all square at %d" % red
        else:
            note = "%s by %d" % ("Red" if red > blue else "Blue", abs(red - blue))

    head = "<span>Match</span><span class=match-note>%s</span>" % html.escape(note)
    prog = ""
    if fraglimit:
        prog = ("<div class=match-prog><span style='width:%.1f%%'></span></div>"
                "<p class=match-foot>%d of %d frags</p>"
                % (min(100.0, top / fraglimit * 100), top, fraglimit))
    sub = ""
    if teams:
        # With team bars carrying the score, the per-player progress bar
        # underneath would be measuring the wrong race.
        prog = ""
        # The individual list still needs saying what it is — these are frags,
        # not captures, and the two do not rank the same. Each row now carries
        # the player's side, from the `teams` key added in old-mac-quake3
        # server-v0.6.3 (asked for in #18), so the caption no longer has to
        # apologise for not knowing.
        sub = "<p class=match-sub>Individual frags</p>"
    return ("<div class=match><h3 class=match-head>%s</h3>%s%s"
            "<ul class=match-list>%s</ul>%s</div>"
            % (head, teams, sub, "".join(rows), prog))


def who_html(game, st):
    """Who is in the server right now.

    A bot gets its face next to its name, which is how you tell at a glance
    that the four players in there are three bots and your brother. Bots are
    the ones reporting a ping of zero — the engine has no other flag for it."""
    if not st.get("players"):
        return ""
    roster = bot_models(game) if GAMES[game].get("has_bots") else {}

    def score_of(p):
        try:
            return int(p["score"])
        except (TypeError, ValueError):
            return 0

    # Highest score first, and the leader marked — the engine hands these over
    # in connection order, which is the one order nobody wants to read them in.
    players = sorted(st["players"], key=score_of, reverse=True)
    best = score_of(players[0]) if players else 0
    contested = len(players) > 1 and best > 0

    out = []
    for p in players:
        name = clean_name(game, p["name"])[:24]
        face = ""
        if p.get("ping") == "0" and name in roster:
            face = ("<img src='%s' alt='' width=18 height=18 loading=lazy>"
                    % art_url("/icon/%s/%s.png" % (game, urllib.parse.quote(name))))
        lead = contested and score_of(p) == best
        if p.get("ping") is not None:
            tail = "%sms" % html.escape(str(p["ping"]))
        elif p.get("secs") is not None:
            tail = "%s in" % human_secs_short(p["secs"])
        else:
            tail = ""
        out.append("<span%s>%s<b>%s</b> %s pts%s</span>"
                   % (" class=lead" if lead else "", face, html.escape(name),
                      html.escape(p["score"]), " &middot; " + tail if tail else ""))
    return "".join(out)


def render_connect(game):
    """The address to type into the game, and a one-tap copy — which matters
    on a phone, where retyping a hostname into a 1996 client is the worst part
    of the whole exercise."""
    addr = "%s:%d" % (GAMES_HOST, GAMES[game]["port"])
    return ("<div class=connect><code id='addr-%s'>%s</code>"
            "<button class=tiny type=button data-copy='addr-%s'>Copy</button>"
            "</div>" % (game, html.escape(addr), game))


def render_say(game):
    # alephone's "gatherer" model has no server-side console at all -- its
    # fifo path in GAMES is never actually created (confirmed live on the
    # box, 2026-08-31: `tee` fails, no /run/alephone-server/ directory
    # exists), so offering this form only ever produces an error. Currently
    # that failure surfaces correctly via console()'s return value, but it
    # depends on that directory staying absent; not offering the control at
    # all removes the trap entirely rather than relying on that.
    if GAMES[game].get("gatherer"):
        return ""
    return ("<form method=post action=/say class=sayrow>"
            "<input type=hidden name=game value='%s'>"
            "<input name=text maxlength=120 autocomplete=off"
            " placeholder='Say something to players' aria-label='Message to players'>"
            "<button type=submit>Send</button></form>" % game)


SKILLS = [("1", "I can win"), ("2", "Bring it on"), ("3", "Hurt me plenty"),
          ("4", "Hardcore"), ("5", "Nightmare")]


def render_bots(game, st=None):
    """Quake III is the only one of the four with bots, and they are what makes
    it testable on your own."""
    names = bots_for(game)
    if not names:
        return ""
    skills = "".join("<option value='%s'%s>%s</option>"
                     % (v, " selected" if v == "3" else "", html.escape(t))
                     for v, t in SKILLS)
    botopts = "".join("<option value='%s' data-img='%s'>%s</option>"
                      % (html.escape(n),
                         art_url("/icon/%s/%s.png" % (game, html.escape(n))),
                         html.escape(n))
                      for n in names)
    # `pick`, not `name`. A <select> submits its value on every submit, so a
    # button sharing that field name arrives SECOND in the query string and
    # parse_qs()[0] takes the select's value instead. Every face in this grid
    # added whichever bot the dropdown happened to be showing, and so did
    # Random. A distinct field name is the fix; taking [-1] instead would work
    # today and break the first time the markup is reordered.
    faces = "".join(
        "<button class=face name=pick value='%s' type=submit title='Add %s'>"
        "<img src='%s' alt='' width=48 height=48 loading=lazy>"
        "<span>%s</span></button>"
        % (html.escape(n), html.escape(n),
           art_url("/icon/%s/%s.png" % (game, html.escape(n))), html.escape(n))
        for n in names)

    # Team gametypes want a side, or the engine picks for you.
    mode = (st or {}).get("mode")
    team = ""
    if mode in ("team", "ctf"):
        team = ("<select name=team aria-label='Team'>"
                "<option value=''>Auto</option>"
                "<option value=red>Red</option><option value=blue>Blue</option>"
                "</select>")

    keep = "".join("<option value='%d'%s>%s</option>"
                   % (i, " selected" if str(i) == (remembered_setting(game, "keep") or "0") else "",
                      "off" if i == 0 else "%d players" % i)
                   for i in range(0, 9))

    return ("<form method=post action=/bot>"
            "<input type=hidden name=game value='%s'><input type=hidden name=do value=add>"
            "<div class=botbar><select name=name aria-label='Bot' data-picker>%s</select>"
            "<select name=skill aria-label='Skill'>%s</select>%s"
            "<button type=submit>Add</button>"
            "<button name=pick value=random type=submit class=primaryish>Random</button>"
            "</div>"
            "<div class=faces>%s</div></form>"
            "<form method=post action=/bot class=botrow>"
            "<input type=hidden name=game value='%s'><input type=hidden name=do value=keep>"
            "<select name=count aria-label='Keep this many players'>%s</select>"
            "<button type=submit>Keep topped up</button></form>"
            "<form method=post action=/bot>"
            "<input type=hidden name=game value='%s'><input type=hidden name=do value=clear>"
            "<button class='tiny danger' type=submit>Remove all bots</button></form>"
            ""
            % (game, botopts, skills, team, faces, game, keep, game))


def render_tabs(game, st, listed):
    """The game page outgrew a single column of controls, so its sections
    became tabs. Plain divs plus a little script: with no JavaScript every
    panel is visible, which is exactly the old layout."""
    panels = [("play", "Play", render_shots(game, listed, st.get("map"))),
              ("bots", "Bots", render_bots(game, st)),
              ("set", "Settings", render_settings(game, st)),
              ("conn", "Connect", render_connect(game) + render_say(game))]
    panels = [(k, t, b) for k, t, b in panels if b]
    if len(panels) < 2:
        return "".join(b for _, _, b in panels)
    first = panels[0][0]
    tabs = "".join("<button type=button role=tab aria-selected='%s' class='tab%s' "
                   "data-tab='%s-%s'>%s</button>"
                   % ("true" if k == first else "false",
                      " here" if k == first else "", game, k, html.escape(t))
                   for k, t, _ in panels)
    bodies = "".join("<div class=tabpanel role=tabpanel id='%s-%s'%s>%s</div>"
                     % (game, k, "" if k == first else " data-hide", b)
                     for k, _, b in panels)
    return "<div class=tabs role=tablist>%s</div>%s" % (tabs, bodies)


def render_shots(game, listed, current):
    """Quake III ships a levelshot per map and Half-Life a top-down overview
    per deathmatch map, so in both a level can be picked by looking at it
    rather than by remembering what q3dm13 or subtransit is.

    Quake and Quake II ship neither, so theirs is a floorplan drawn from the
    level's own geometry. Same purpose: dm4 is a shape you recognise long
    before the name means anything."""
    if not (GAMES[game].get("has_shots") or GAMES[game].get("has_plans")):
        return ""
    titles = map_titles(game)
    tiles = []
    for m in listed:
        if not map_shot_png(game, m):
            continue
        tiles.append(
            "<button class='shot%s' name=map value='%s' type=submit title='%s'>"
            "<img src='%s' alt='' width=160 height=120 loading=lazy>"
            "<span>%s</span></button>"
            % (" here" if m == current else "", html.escape(m),
               html.escape(titles.get(m, m)),
               art_url("/shot/%s/%s.jpg" % (game, html.escape(m))), html.escape(m)))
    if not tiles:
        return ""
    return ("<form method=post action=/map>"
            "<input type=hidden name=game value='%s'>"
            "<div class=shots>%s</div></form>"
            % (game, "".join(tiles)))


_CFG_CACHE = {}


def config_defaults(game, ttl=300):
    """What the server's own server.cfg sets, as {cvar: value}.

    NetQuake publishes none of these over its status protocol, so with nothing
    remembered the frag limit read "unknown" on a server that has been running
    to a frag limit of 20 since it started. The config file is where that 20
    comes from, so read it: until somebody changes a value it is exactly right,
    and it is a great deal more use than "unknown".

    Deliberately dumb parsing — `key value`, one per line, // for comments.
    That is all these files are."""
    hit = _CFG_CACHE.get(game)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    out = {}
    path = os.path.join(GAMES[game]["dir"], "server.cfg")
    try:
        with open(path, encoding="latin-1") as f:
            for line in f:
                line = line.split("//")[0].strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue
                key, value = parts[0], parts[1].strip().strip('"')
                if key.lower() == "set" or key.lower() == "seta":
                    parts = value.split(None, 1)
                    if len(parts) != 2:
                        continue
                    key, value = parts[0], parts[1].strip().strip('"')
                out[key] = value
    except OSError:
        pass
    # Quake II applies its mode from a file the UI writes; that wins over the
    # base config for anything it sets.
    mode_file = GAMES[game].get("mode_file")
    if mode_file:
        try:
            with open(mode_file, encoding="latin-1") as f:
                for line in f:
                    parts = line.split("//")[0].strip().split()
                    if len(parts) == 3 and parts[0].lower() == "set":
                        out[parts[1]] = parts[2].strip('"')
        except OSError:
            pass
    _CFG_CACHE[game] = (time.time(), out)
    return out


def mode_file_merge(game, updates):
    """Merge `updates` into mode_file's existing `set key value` lines and
    write the whole thing back, rather than replacing the file.

    post_mode used to `tee` the file with ONLY the mode's own two cvars
    every time -- fine while mode.cfg held nothing else, but
    restart_settings (maxclients, skill) now shares this same file and this
    same restart mechanism, and a plain overwrite would silently erase
    whichever of the two a previous write put there. Read first, update
    just the given keys, write all of them back -- the same parsing
    config_defaults() above already does for this file, kept in step with
    it on purpose."""
    mode_file = GAMES[game]["mode_file"]
    current = {}
    try:
        with open(mode_file, encoding="latin-1") as f:
            for line in f:
                parts = line.split("//")[0].strip().split()
                if len(parts) == 3 and parts[0].lower() == "set":
                    current[parts[1]] = parts[2].strip('"')
    except OSError:
        pass
    current.update(updates)
    body = "\n".join("set %s %s" % kv for kv in current.items()) + "\n"
    w = run(["sudo", "tee", mode_file], stdin=body)
    return w.returncode == 0


def render_settings(game, st):
    """Only some of these can be read back.

    An engine publishes a cvar in its serverinfo string only if it is flagged
    CVAR_SERVERINFO, and most of these are not: Quake and Half-Life publish
    none of them, Quake III publishes three of five. So a control that shows
    "the current value" would be blank or wrong most of the time.

    Two consequences, both handled here. Values fall back to what was last
    applied through this UI. And booleans are a pair of On/Off buttons rather
    than one toggle, because a toggle has to claim it knows the current state
    in order to say what it will do next, and usually it does not.
    """
    cfg = GAMES[game]
    rows = []
    for key, label, kind, extra in cfg["settings"]:
        live = (st.get("cvars") or {}).get(key)
        remembered = remembered_setting(game, key)
        from_cfg = config_defaults(game).get(key)
        from_engine = cfg.get("defaults", {}).get(key)
        cur = next((v for v in (live, remembered, from_cfg, from_engine)
                    if v is not None), None)
        if live is not None:
            known = " (live)"
        elif remembered is not None:
            known = " (last set)"
        elif from_cfg is not None:
            known = " (from server.cfg)"
        elif from_engine is not None:
            known = " (engine default)"
        else:
            known = ""

        # A real for/id pairing rather than a bare <label> sitting next to a
        # control it is not attached to. The old markup left an orphaned label
        # on every row, which is a label that labels nothing.
        fid = "s-%s-%s" % (game, key)

        if kind == "bool":
            btns = "".join(
                "<form method=post action=/set>"
                "<input type=hidden name=game value='%s'><input type=hidden name=key value='%s'>"
                "<input type=hidden name=value value='%s'>"
                "<button class=tiny type=submit aria-pressed='%s'>%s</button></form>"
                % (game, key, v, "true" if cur == v else "false", t)
                for v, t in (("1", "On"), ("0", "Off")))
            rows.append("<div class=knob-row>"
                        "<span class=knob id='%s'>%s<span class=src>%s</span></span>"
                        "<div class=pair role=group aria-labelledby='%s'>%s</div>"
                        "</div>"
                        % (fid, html.escape(label), known, fid, btns))
        elif kind == "choice":
            opts = "".join("<option value='%s'%s>%s</option>"
                           % (v, " selected" if v == cur else "", html.escape(t))
                           for v, t in extra)
            rows.append(
                "<div class=knob-row>"
                "<label class=knob for='%s'>%s<span class=src>%s</span></label>"
                "<form method=post action=/set>"
                "<input type=hidden name=game value='%s'><input type=hidden name=key value='%s'>"
                "<select id='%s' name=value>%s</select>"
                "<button class=tiny type=submit>Set</button></form>"
                "</div>"
                % (fid, html.escape(label), known, game, key, fid, opts))
        elif kind == "bits":
            # One cvar, several independent rules. Shown as what they are —
            # named switches — rather than as the integer they add up to.
            # "dmflags 8212" is a number nobody can read; "Weapons stay,
            # Instant items, Infinite ammo" is the same fact.
            try:
                mask = int(cur or 0)
            except (TypeError, ValueError):
                mask = 0
            sw = []
            for bit, text in extra:
                on = bool(mask & bit)
                sw.append(
                    "<form method=post action=/set class=bit>"
                    "<input type=hidden name=game value='%s'>"
                    "<input type=hidden name=key value='%s'>"
                    "<input type=hidden name=bit value='%d'>"
                    "<input type=hidden name=value value='%d'>"
                    "<button class='chip' type=submit aria-pressed='%s'>%s</button>"
                    "</form>"
                    % (game, key, bit, 0 if on else 1,
                       "true" if on else "false", html.escape(text)))
            rows.append("<div class=knob-row knob-wide>"
                        "<span class=knob id='%s'>%s<span class=src>%s</span></span>"
                        "<div class=chips role=group aria-labelledby='%s'>%s</div>"
                        "</div>" % (fid, html.escape(label), known, fid, "".join(sw)))
        elif kind == "text":
            # A password or MOTD string, not a number. Sent through the same
            # console FIFO everything else uses, so it has to obey the same
            # rule chat already does: SAFE_SAY, because an unescaped newline
            # or semicolon in this field is a second console command, not
            # part of the value.
            rows.append(
                "<div class=knob-row>"
                "<label class=knob for='%s'>%s<span class=src>%s</span></label>"
                "<form method=post action=/set>"
                "<input type=hidden name=game value='%s'><input type=hidden name=key value='%s'>"
                "<input id='%s' name=value type=text maxlength=120 autocomplete=off "
                "value='%s' placeholder='(empty)'>"
                "<button class=tiny type=submit>Set</button></form>"
                "</div>"
                % (fid, html.escape(label), known, game, key, fid,
                   html.escape(str(cur)) if cur is not None else ""))
        else:
            lo, hi = extra
            rows.append(
                "<div class=knob-row>"
                "<label class=knob for='%s'>%s<span class=src>%s</span></label>"
                "<form method=post action=/set>"
                "<input type=hidden name=game value='%s'><input type=hidden name=key value='%s'>"
                "<input id='%s' name=value type=number inputmode=numeric autocomplete=off "
                "min='%d' max='%d' value='%s' placeholder='unknown'>"
                "<button class=tiny type=submit>Set</button></form>"
                "</div>"
                % (fid, html.escape(label), known, game, key, fid, lo, hi,
                   html.escape(str(cur)) if cur is not None else ""))
    # Empty, not a wrapper around nothing: a non-empty string here is what
    # render_tabs's `if b` filter uses to decide whether a tab exists at
    # all, and alephone's cfg["settings"] is genuinely [] -- no cvars, no
    # console to set them through. Returning the empty <div> anyway made a
    # Settings tab that opened onto nothing, found live 2026-08-31.
    if not rows:
        return ""
    # No <details> here: this is already the contents of the Settings tab, and
    # putting a disclosure inside a tab hides the thing behind two taps.
    return ("<div class=knobs>%s</div>"
            ""
            % "".join(rows))


def render_game(game):
    cfg = GAMES[game]
    state = unit_state(cfg["unit"])
    st = live_state(game)
    grouped = maps_for(game)
    # Quake III and Quake II report their gametype in the status reply; Quake
    # and Half-Life do not, so those fall back to what was last applied here.
    # Where the engine does tell us, it wins and the remembered value is
    # corrected — otherwise a mode changed by any other route (a console
    # command, an edited config, a restart) leaves the UI lying.
    current_mode = resolve_mode(game, st, remember=True)

    modes = "".join(
        "<form method=post action=/mode><input type=hidden name=game value='%s'>"
        "<input type=hidden name=mode value='%s'>"
        "<button class=mode type=submit aria-pressed='%s'>%s</button></form>"
        % (game, key, "true" if key == current_mode else "false", html.escape(title))
        for key, (title, _) in cfg["modes"].items())

    listed = sort_maps(game, current_mode,
                       grouped.get(current_mode) or grouped["all"])
    titles = map_titles(game)
    shots = GAMES[game].get("has_shots") or GAMES[game].get("has_plans")
    opts = "".join("<option value='%s'%s%s>%s</option>"
                   % (html.escape(m), " selected" if m == st.get("map") else "",
                      (" data-img='%s'" % art_url("/shot/%s/%s.jpg"
                                                     % (game, html.escape(m)))
                       if shots and map_shot_png(game, m) else ""),
                      html.escape("%s \u2014 %s" % (m, titles[m]) if m in titles else m))
                   for m in listed)

    # One tap to the level that comes next, named so you know where you are
    # going before you press it.
    nxt = next_map(game, current_mode, st.get("map"), listed)
    nextbtn = ""
    if nxt:
        label = titles.get(nxt)
        nextbtn = ("<button name=map value='%s' type=submit title='%s'>Next</button>"
                   % (html.escape(nxt),
                      html.escape("%s \u2014 %s" % (nxt, label) if label else nxt)))

    # A picture of the level that is loaded right now, where the game has one.
    here = st.get("map")
    headshot = ""
    if here and map_shot_png(game, here):
        headshot = ("<img class=ghead-shot src='%s' alt='' width=124 height=93>"
                    % art_url("/shot/%s/%s.jpg" % (game, html.escape(here))))

    glevel, gpill, gtext = rag(game, st, state)
    match = render_match(game, st)
    # The picture of the level you are actually in leads, on the left, at a
    # size worth looking at. It was 84px on the right, tucked past the
    # telemetry, which is the wrong way round on a page whose whole job is
    # "which map is this and do I want a different one".
    #
    # Where a level has no picture the emblem stands in, so the header keeps
    # its shape rather than collapsing by a column.
    lead = headshot or ("<img class=ghead-icon src='%s' alt='' width=54 height=54>"
                        % art_url("/emblem/%s.png" % game))
    modes_html = ("<div class=modes role=group aria-label='Game mode'>%s</div>" % modes) if modes else ""
    if cfg.get("gatherer"):
        maprow = ("<div class=gather-info>Marathon netgames use client-side gathering: "
                  "in Aleph One, select <b>Use Dedicated Server</b> pointing to "
                  "<code>%s:%d</code>, then choose your scenario, level and game type in the game.</div>"
                  % (html.escape(GAMES_HOST), cfg["port"]))
    else:
        maprow = ("<div class=row><form method=post action=/map>"
                  "<input type=hidden name=game value='%s'>"
                  "<select name=map aria-label='Map for %s' data-picker>%s</select>"
                  "<button type=submit>Change map</button></form>"
                  "<form method=post action=/map class=jump>"
                  "<input type=hidden name=game value='%s'>%s"
                  "<button name=map value=random type=submit>Random</button>"
                  "</form></div>"
                  % (game, html.escape(cfg["label"]), opts, game, nextbtn))

    return ("<div class='game %s' style='--accent:%s'>"
            "<div class=ghead>"
            "%s"
            "<span class=ghead-text>"
            "<span class=ghead-top>"
            "<span class=ghead-name>%s</span>"
            "<span class='pill %s' id='state-%s'>%s</span>"
            "</span>"
            "<span class=meta id='meta-%s'>%s</span></span>"
            # Restart + Stop, or Start.
            "%s"
            "</div>"
            # Which build is actually installed (#6). Under the header
            # rather than in a bay, because the Overview is already
            # dense on a phone and this is a detail you go looking for.
            "%s"
            "<div class=who id='who-%s'>%s</div>"
            "<div id='match-%s'>%s</div>"
            "%s"
            "%s"
            "%s</div>"
            % (glevel, cfg["accent"], lead,
               html.escape(cfg["label"]),
               gpill, game, gtext,
               game, meta_html(game, st),
               power_form(game, cfg, state),
               build_html(game),
               game, "" if match else who_html(game, st),
               game, match, modes_html,
               maprow,
               render_tabs(game, st, listed)))


def power_form(game, cfg, state):
    """Restart and Stop while it is running, Start while it is not.

    #9. `systemctl restart` starts a stopped unit perfectly
    well, but a button reading "Restart" on a server that is already off asks
    the person to translate, so the label follows the state.

    Both destructive buttons carry the same confirmation, because stopping
    disconnects everybody exactly as restarting does."""
    label = html.escape(cfg["label"])
    hidden = "<input type=hidden name=game value='%s'>" % game
    if state != "active":
        return ("<div class=restart><form method=post action=/restart>%s"
                "<button class='tiny' type=submit>Start</button></form></div>"
                % hidden)
    return ("<div class=restart>"
            "<form method=post action=/restart "
            "data-confirm='Restart %s? Every connected player is disconnected.'>"
            "%s<button class='tiny danger' type=submit>Restart</button></form>"
            "<form method=post action=/stop "
            "data-confirm='Stop %s? Every connected player is disconnected, and "
            "it stays off until someone starts it again.'>"
            "%s<button class='tiny danger' type=submit>Stop</button></form>"
            "</div>" % (label, hidden, label, hidden))


def render_access(members, grants, revocable, empty_msg):
    if not members:
        return "<li class=none>%s</li>" % html.escape(empty_msg)
    out = []
    for addr, ttl in members:
        g = grants.get(str(addr)) if str(addr) != "_mode" else None
        by = ("<span class=grantby>opened by %s, %s</span>"
              % (html.escape(g["by"]), human_ago(g["at"]))) if g else ""
        rev = ("<form method=post action=/revoke>"
               "<input type=hidden name=ip value='%s'>"
               "<button class='tiny danger' type=submit>Revoke</button></form>"
               % html.escape(str(addr))) if (revocable and ttl is not None) else ""
        out.append("<li><code>%s</code><span class=ttl>%s</span>%s%s</li>"
                   % (html.escape(str(addr)), human_secs(ttl), rev, by))
    return "".join(out)


def _play_day(epoch):
    """today / yesterday / the date. (year, yday) rather than a date string,
    so 31 December and 1 January are not the same day."""
    t = time.localtime(epoch)
    that = (t.tm_year, t.tm_yday)
    now = time.localtime()
    if that == (now.tm_year, now.tm_yday):
        return "today"
    y = time.localtime(time.time() - 86400)
    if that == (y.tm_year, y.tm_yday):
        return "yesterday"
    return time.strftime("%a %d %b", t)


PLAY_PAGE = 20        # rows per page of "Who played" -- also /api/status's page-1 refresh size


def play_html(n=PLAY_PAGE, offset=0):
    """The answer to "did anyone play last night", as list items.

    Only ever called with the default page-1 slice — /api/status's live poll
    refreshes just that, on the theory that older pages are history and don't
    need refreshing (live.js skips the poll patch once you've paged away from
    page 1, so this staying page-1-only is not a bug, see live.js)."""
    rows, _total = play_sessions(n, offset)
    return _play_rows_html(rows, offset)


def _play_rows_html(rows, offset=0):
    """The <li> markup for one page of play_sessions() rows.

    Peak rather than final count, because a session that ends with one person
    still had three in it. Names are what the engine published during the
    session; Half-Life publishes none, and the line says so rather than
    leaving a blank that reads as nobody."""
    if not rows:
        if offset:
            return "<li class=none>Nothing on this page.</li>"
        return ("<li class=none>Nothing recorded yet. This begins at the first "
                "join after it went up and cannot know about earlier "
                "evenings.</li>")
    out = []
    for sess in rows:
        label = GAMES.get(sess["g"], {}).get("label", sess["g"])
        start = time.strftime("%H:%M", time.localtime(sess["a"]))
        end = "now" if sess.get("live") else time.strftime("%H:%M",
                                                           time.localtime(sess["b"]))
        mins = max(1, int((sess["b"] - sess["a"]) // 60))
        peak = sess.get("peak", 1)
        note = "%s \u00b7 %d %s \u00b7 %d min" % (
            _play_day(sess["a"]), peak, "player" if peak == 1 else "players", mins)
        who = ", ".join(nm for nm in (sess.get("names") or []) if nm)
        if who:
            note += " \u00b7 " + who
        elif sess["g"] == "halflife":
            note += " \u00b7 no names published"
        out.append("<li><b>%s</b><span class=ttl>%s\u2013%s</span>"
                   "<span class=grantby>%s</span></li>"
                   % (html.escape(label), start, end, html.escape(note)))
    return "".join(out)


def play_pager_html(page, total, per_page=PLAY_PAGE):
    """Older/Newer for the Who played list, or nothing if it all fits on one
    page. No page numbers to click \u2014 the list only grows one evening at a
    time, so "is there more" matters more than "how many pages exist"."""
    pages = max(1, -(-total // per_page))          # ceil division, no float
    if pages <= 1:
        return ""
    if page > 1:
        newer = "<a href='/activity?page=%d'>&larr; Newer</a>" % (page - 1)
    else:
        newer = "<span class=disabled>&larr; Newer</span>"
    if page < pages:
        older = "<a href='/activity?page=%d'>Older &rarr;</a>" % (page + 1)
    else:
        older = "<span class=disabled>Older &rarr;</span>"
    return ("<div class=pager>%s<span class=ttl>page %d of %d</span>%s</div>"
            % (newer, page, pages, older))


REFRESH_JS = "<script>" + LIVE_JS + "</script>"


def breakable_addr(addr):
    """The address, marked up so it can wrap at its own separators.

    An IPv6 address is one unbreakable token 39 characters long at worst, and
    `.big` is 1.6rem monospace. Measured in Chrome at 440pt, the width an
    iPhone 16 Pro Max reports: 24 characters fit inside the card and the rest
    was painted straight over the border and off the side of the screen. The
    page does not scroll sideways, so those characters were simply gone — an
    address that looks wrong rather than one that looks cut off, which is how
    it was reported.

    A <wbr> after each colon lets it break between groups and nowhere else, so
    it wraps the way an address should read. IPv4 has no colons and is
    unaffected; it fits on one line at any width the site supports."""
    return html.escape(addr).replace(":", ":<wbr>")


def device_label(ua):
    """A name for the thing you are reading this on.

    The card used to lead with the address. On a phone that is a 39-character
    IPv6, because the admin hostname has AAAA records and a mobile network
    reaches Cloudflare over v6, and iOS rotates it for privacy so it differs
    every visit. Reported twice as a wrong address when it was the right one.
    A person recognises "This iPhone"; nobody recognises 2a00:23c7:8f8d:d001.

    This is a guess from the user-agent and it will sometimes be wrong — an
    iPad asking for the desktop site says Macintosh and there is nothing here
    that can tell the difference. That is affordable because it is a label and
    nothing else: no grant, revoke or firewall decision reads it."""
    s = ua or ""
    if "iPhone" in s:
        return "This iPhone"
    if "iPad" in s:
        return "This iPad"
    if "Android" in s:
        return "This Android phone" if "Mobile" in s else "This Android tablet"
    if "Macintosh" in s or "Mac OS X" in s:
        return "This Mac"
    if "Windows" in s:
        return "This PC"
    if "Linux" in s or "X11" in s:
        return "This Linux machine"
    return "This device"


def short_addr(addr):
    """The address, shortened for display and nothing else.

    The middle of an IPv6 address tells a human nothing. First two groups and
    the last one is enough to tell one device from another, and being short it
    cannot overflow the card the way the full string did in #3.

    Display only, and that distinction matters: post_allow reads
    CF-Connecting-IP again rather than anything rendered here, so what gets
    granted is always the whole address. IPv4 is 15 characters at worst and is
    returned untouched."""
    if ":" not in addr:
        return addr
    parts = addr.split(":")
    if len(parts) <= 3 or not parts[-1]:
        return addr
    return "%s:%s:\u2026:%s" % (parts[0], parts[1], parts[-1])


def access_card(ip, allowed, ua=""):
    # The games are not behind Cloudflare, so an IPv6 visitor's grant here
    # never reaches them -- see post_allow_ipv4. The marker tells live.js
    # whether it is worth asking api4.ipify.org at all; an IPv4 visitor
    # needs no second address and gets no extra request.
    try:
        probe = " data-probe-v4=1" if ipaddress.ip_address(ip).version == 6 else ""
    except ValueError:
        probe = ""
    return ("<div class='card wide'%s><h2>Your access to the games</h2>"
            "<div class=me><span class=big>%s</span>"
            "<span class='pill %s' id=you-pill>%s</span>"
            "<span class=ttl id=you-ttl></span></div>"
            "<div class=whoami title='%s'>%s</div>"
            "<form method=post action=/allow>"
            "<button class='primary%s' type=submit>%s</button></form>"
            # Filled by live.js, and empty in the markup on purpose. The
            # countdown ticks locally every second between polls, so the
            # verdict "this is about to lapse" has to be recomputed in the
            # browser as it crosses the hour; rendering a second copy here
            # would be a second thing to keep in step, which is the drift
            # /api/status already warns about at :3770.
            "<p class=access-warn id=you-warn></p>"
            "</div>"
            % (probe,
               html.escape(device_label(ua)),
               "on" if allowed else "off",
               "can play" if allowed else "blocked",
               html.escape(ip),
               breakable_addr(short_addr(ip)),
               " quiet" if allowed else "",
               "Extend for another %s" % ALLOW_TTL if allowed else "Let me in"))


def gauge(label, value, note, frac, warn=0.75, danger=0.9, key=None):
    """One readout: what it is, what it reads, and how full that is.

    The bar exists so the number has a scale attached. A load of 0.32 says
    nothing on its own; a third of one core says everything."""
    frac = 0.0 if frac is None else max(0.0, min(1.0, frac))
    level = "bad" if frac >= danger else ("warn" if frac >= warn else "ok")
    trace = ("<svg class=trace data-trace='%s' aria-hidden=true></svg>" % key) if key else ""
    return ("<div class='gauge %s'>"
            "<div class=gauge-top><span class=gauge-label>%s</span>"
            "<span class=gauge-value id='g-%s'>%s</span></div>"
            "%s"
            "<div class='bar' id='b-%s'><i style='width:%.1f%%'></i></div>"
            "<div class=gauge-note id='n-%s'>%s</div></div>"
            % (level, html.escape(label), key or "", html.escape(value), trace,
               key or "", frac * 100, key or "", html.escape(note)))


# ----------------------------------------------------------------- downloads
#
# The releases page for each game, brought to where you already are.
#
# Deliberately NOT part of a server bay. A bay is live state — what is running
# right now, read at arm's length — and the whole bay is already a link to that
# game's controls, so a second link inside it would be invalid markup and a
# tap-target trap on a phone. Getting a build onto your own Mac is a different
# job from changing the map on the server, so it gets its own card.
#
# Note WHICH release is offered. Each repo carries two tag series: `server-v*`,
# the Linux dedicated server this box runs, and a plain `vN.N.N` client release
# carrying the Mac DMG. GitHub's "latest" is the client one, which is what a
# player actually wants — nobody browsing this page needs the aarch64 server
# tarball. If that ever stops being true the check below will start showing the
# wrong thing, so it filters explicitly rather than trusting "latest".
_RELEASE_CACHE = {}
# Two minutes, not the half hour this used to be. The old value assumed
# releases are cut rarely, which is true on an ordinary day and wrong on the
# day it matters: on 2026-09-02 quakespasm shipped v1.15.8, .9 and .10 inside
# ninety minutes while someone was standing at the download page, and the page
# twice showed a version that had already been superseded. Being told "wait
# half an hour" about a link you are looking at is a bad answer.
#
# Affordable now only because of the ETag below: a poll that finds nothing new
# comes back 304 and does NOT count against GitHub's 60-per-hour limit, so
# frequency costs nothing until something actually changes.
_RELEASE_TTL = 120
_RELEASE_ETAGS = {}          # repo -> ETag of the last body we kept
_RELEASE_LOCK = threading.Lock()
# Distinct from None. None means "the lookup failed, serve the last good answer
# and back off"; this means "GitHub confirmed nothing changed", which is a
# successful poll and must refresh the clock like a real answer does.
NOT_MODIFIED = object()


# ------------------------------------------------------- iCloud Private Relay
#
# Safari with Private Relay on does not reach this site from the machine you
# are sitting at: it comes out of an Apple relay, and the address here is
# Apple's egress, not yours. The games are not behind Cloudflare, so the game
# client -- which Private Relay does not cover, it is Safari-only -- arrives
# from your REAL address, which nothing here has ever seen. Granting the relay
# therefore does nothing except put a shared CDN address in the games
# allowlist, where it can only ever match strangers.
#
# Measured on 2026-09-02, a real evening lost to exactly this: three separate
# grants for one person, 2a09:bac3:3770:23cd::391:82 (relay v6),
# 140.248.40.25 (Fastly relay), 104.28.30.132 (Cloudflare relay), and the page
# telling him each time that he was allowed in. His actual client was on
# 77.97.144.64 the whole time. It only worked when he signed in with Chrome,
# which Private Relay does not touch.
#
# Apple publishes the egress ranges, so this is detectable rather than
# guessable. Verified against that file: all three relay addresses above are
# in it, and both real home addresses are not.
RELAY_CSV = "https://mask-api.icloud.com/egress-ip-ranges.csv"
RELAY_FILE = os.path.join(STATE_DIR, "relay-ranges.json")
_RELAY_TTL = 86400           # Apple edits this file slowly; once a day is plenty
_RELAY_LOCK = threading.Lock()
_RELAY_CACHE = {"at": 0, "v4": None}


def _parse_relay_csv(text):
    """IPv4 egress ranges as sorted (first, last) integer pairs.

    IPv4 only, deliberately. The file is 12 MB and a quarter of a million v6
    ranges; holding those costs real memory on a 6 GB box running five game
    servers, and buys nothing -- an IPv6 grant is refused anyway, since the
    games have no IPv6 address at all (see post_allow)."""
    out = []
    for line in text.splitlines():
        cidr = line.split(",", 1)[0].strip()
        if not cidr or ":" in cidr:
            continue
        try:
            n = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if n.version == 4:
            out.append((int(n.network_address), int(n.broadcast_address)))
    out.sort()
    return out


def _relay_ranges():
    """The cached v4 egress ranges, or None if they cannot be established.

    None means "unknown", and every caller treats unknown as "not a relay" --
    fail open. Apple being unreachable must never take the Allow button with
    it; a wrong grant is recoverable in a way that being locked out of the
    only mechanism for granting anything is not."""
    now = time.time()
    with _RELAY_LOCK:
        if _RELAY_CACHE["v4"] is not None and now - _RELAY_CACHE["at"] < _RELAY_TTL:
            return _RELAY_CACHE["v4"]
    ranges = None
    try:
        import urllib.request
        req = urllib.request.Request(RELAY_CSV, headers={"User-Agent": "retro-admin"})
        with urllib.request.urlopen(req, timeout=20) as r:
            ranges = _parse_relay_csv(r.read().decode("utf-8", "replace"))
    except Exception:
        ranges = None
    if ranges:
        with _RELAY_LOCK:
            _RELAY_CACHE["at"], _RELAY_CACHE["v4"] = now, ranges
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            tmp = RELAY_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(ranges, f)
            os.replace(tmp, RELAY_FILE)
        except OSError:
            pass
        return ranges
    # Fetch failed. Last good answer from disk beats no answer, and is still
    # right: these ranges change slowly.
    try:
        with open(RELAY_FILE) as f:
            ranges = [tuple(p) for p in json.load(f)]
    except (OSError, ValueError):
        return None
    with _RELAY_LOCK:
        _RELAY_CACHE["at"], _RELAY_CACHE["v4"] = now - _RELAY_TTL + 300, ranges
    return ranges


def is_relay_address(ip):
    """True if `ip` is an iCloud Private Relay egress. Unknown counts as False."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version != 4:
        return False
    ranges = _relay_ranges()
    if not ranges:
        return False
    n = int(addr)
    i = bisect.bisect_right(ranges, (n, float("inf")))
    return i > 0 and ranges[i - 1][0] <= n <= ranges[i - 1][1]


# The set nftables drops game-port packets into, so the page can offer the one
# address that matters. Timeout must match the `timeout` on the set itself, or
# "tried N ago" is wrong -- nft reports time REMAINING, not time elapsed.
BLOCKED_TTL = 900            # 15m, matching `nft add set ... timeout 15m`


def blocked_attempts():
    """Who tried to reach a game just now and was refused, newest first.

    This is the answer to the relay problem rather than a report on it. A
    browser behind iCloud Private Relay can only ever tell us Apple's egress
    address; the game client is not relayed, so when it knocks on a game port
    the box sees the real machine. Refused packets are recorded here by
    nftables, which makes the address knowable from the games' own side --
    the one place it was never in doubt.

    Scanners hit these ports constantly, so this is deliberately short-lived
    (BLOCKED_TTL) and shown newest first: the entry a person cares about is
    the one from ten seconds ago, not the noise from ten minutes ago."""
    out = []
    for addr, expires in set_members("blocked"):
        try:
            ago = BLOCKED_TTL - int(expires) if expires is not None else None
        except (TypeError, ValueError):
            ago = None
        out.append((str(addr), ago))
    # Smallest "ago" is the most recent. Unknown ages sort last.
    out.sort(key=lambda r: (r[1] is None, r[1] if r[1] is not None else 0))
    return out


def render_blocked(rows, allowed_now):
    """The blocked list, with a way to let each one in."""
    if not rows:
        return ""
    items = []
    for ip, ago in rows:
        if ip in allowed_now:
            continue          # already in; showing it would just be confusing
        when = ("%ds ago" % ago if ago is not None and ago < 60
                else "%dm ago" % (ago // 60) if ago is not None
                else "recently")
        items.append(
            "<li><code>%s</code><span class=ttl>%s</span>"
            "<form method=post action=/allow-blocked>"
            "<input type=hidden name=ip value='%s'>"
            "<button class='tiny primaryish' type=submit>Let this one in</button>"
            "</form></li>" % (html.escape(ip), when, html.escape(ip)))
    if not items:
        return ""
    return ("<div class='card wide'><h2><span>Tried to play and was blocked</span>"
            "<span>last %d min</span></h2>"
            "<p class=hint>These are addresses the games themselves saw. If you "
            "are trying to get someone in and the button above granted the wrong "
            "address — a relay, a VPN — this is the real one.</p>"
            "<ul class=list>%s</ul></div>"
            % (BLOCKED_TTL // 60, "".join(items)))


RELAY_ADVICE = ("That is an iCloud Private Relay address, not this machine's. "
                "The games never see it, so allowing it cannot let you in. "
                "Turn Private Relay off (Settings, Apple Account, iCloud, "
                "Private Relay) or use another browser, then press Allow again.")


def _fetch_release(repo, asset_exts=(".dmg",)):
    """Latest CLIENT release for a repo, or None. Never raises.

    `asset_exts` is a tuple because it is matched with str.endswith(), which
    only accepts a tuple, not a list. Every game ships a .dmg; keeperfx has no
    macOS installer convention of its own yet and ships KeeperFX.app zipped."""
    import urllib.request
    url = "https://api.github.com/repos/matthewdeaves/%s/releases?per_page=20" % repo
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "retro-admin",
    }
    # Conditional request. GitHub answers an unchanged list with 304 and does
    # not charge it against the hourly limit, which is what makes a short TTL
    # safe: polling costs nothing until a release actually appears.
    with _RELEASE_LOCK:
        etag = _RELEASE_ETAGS.get(repo)
    if etag:
        headers["If-None-Match"] = etag
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.load(r)
            new_etag = r.headers.get("ETag")
        if new_etag:
            with _RELEASE_LOCK:
                _RELEASE_ETAGS[repo] = new_etag
    except urllib.error.HTTPError as e:
        if e.code == 304:
            # Unchanged. Say so distinctly: the caller must keep what it has
            # and refresh the clock, NOT treat this as a failed lookup and
            # start serving a stale answer with a two-minute retry backoff.
            return NOT_MODIFIED
        return None
    except Exception:
        # Offline, rate-limited, GitHub down, anything. A downloads card that
        # cannot reach GitHub is a missing convenience, never a broken page.
        return None
    for rel in data:
        tag = rel.get("tag_name") or ""
        if rel.get("draft") or rel.get("prerelease"):
            continue
        if tag.startswith("server-"):
            continue          # the Linux server series, not what a player wants
        assets = [a for a in rel.get("assets") or []
                  if (a.get("name") or "").lower().endswith(asset_exts)]
        return {
            "tag": tag,
            "url": rel.get("html_url") or "",
            "date": (rel.get("published_at") or "")[:10],
            "asset": assets[0].get("name") if assets else None,
            "asset_url": assets[0].get("browser_download_url") if assets else None,
            "size": assets[0].get("size") if assets else None,
        }
    return None


RELEASES_FILE = os.path.join(STATE_DIR, "releases.json")


def _load_releases():
    try:
        with open(RELEASES_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_releases(d):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = RELEASES_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(d, f)
        os.replace(tmp, RELEASES_FILE)
    except OSError:
        pass


def latest_release(repo, asset_exts=(".dmg",)):
    """The newest client release, and the last one we saw if GitHub says no.

    Takes the repo name directly rather than a GAMES key, so a download-only
    entry with no GAMES row (DOWNLOAD_EXTRAS) can call this too.

    Unauthenticated GitHub allows 60 requests an hour PER IP, shared by
    everything on this box. It is easy to reach: four repos, and any other tool
    that touches the API from here counts against the same budget. The first
    version of this showed "unavailable" the moment that happened, which is a
    worse answer than a slightly old one — the tags change a few times a month,
    so yesterday's number is almost always still today's.

    So the last good answer is kept on disk and served whenever a lookup fails,
    for as long as it takes to succeed again. "Unavailable" now means only what
    it says: nothing has ever been fetched."""
    if not repo:
        return None
    now = time.time()
    with _RELEASE_LOCK:
        hit = _RELEASE_CACHE.get(repo)
        if hit and now - hit[0] < _RELEASE_TTL:
            return hit[1]
        if not _RELEASE_CACHE:
            for k, v in _load_releases().items():
                # Loaded as already-expired so the first request revalidates,
                # but with a value to fall back on if that request fails.
                _RELEASE_CACHE[k] = (0, v)
            hit = _RELEASE_CACHE.get(repo)

    rel = _fetch_release(repo, asset_exts)
    stale = hit[1] if hit else None
    if rel is NOT_MODIFIED:
        # A successful poll that found nothing new. What we hold is current,
        # so restart the clock rather than treating this as a failure -- the
        # answer is not stale, it is confirmed.
        with _RELEASE_LOCK:
            _RELEASE_CACHE[repo] = (now, stale)
        return stale
    with _RELEASE_LOCK:
        if rel:
            _RELEASE_CACHE[repo] = (now, rel)
            _save_releases({k: v[1] for k, v in _RELEASE_CACHE.items() if v[1]})
            return rel
        # Failed. Keep serving the last good answer, and do not retry for a
        # minute, so a rate-limited hour is not also a slow one.
        _RELEASE_CACHE[repo] = (now - _RELEASE_TTL + 60, stale)
    return stale


def render_downloads():
    """One row per game: the current Mac build, and where to get it.

    Chains GAMES with DOWNLOAD_EXTRAS: same row shape (a build to download,
    optionally game data beside it), the extras just have nothing behind them
    on this box to poll or manage."""
    rows = []
    for g, cfg in list(GAMES.items()) + list(DOWNLOAD_EXTRAS.items()):
        rel = latest_release(cfg.get("repo"), cfg.get("asset_exts", (".dmg",)))
        if rel:
            size = (" &middot; %s" % human_bytes(rel["size"])) if rel.get("size") else ""
            if rel.get("asset_url"):
                # target=_blank on purpose. This is the only link on the site
                # that leaves the origin, and added to the Home Screen iOS
                # answers an out-of-scope navigation by throwing an in-app
                # browser over the app — the sheet with "Done" in the corner.
                # Marking it as a deliberate exit means the app is still
                # underneath when that sheet closes, rather than the app itself
                # having been navigated somewhere it cannot come back from.
                link = ("<a class=dl-get href='%s' target=_blank "
                        "rel='noopener noreferrer'>Download %s</a>"
                        % (html.escape(rel["asset_url"]),
                           html.escape(rel["tag"])))
            else:
                link = ("<a class=dl-get href='%s' target=_blank rel='noopener noreferrer'>"
                        "Release %s</a>" % (html.escape(rel["url"]),
                                            html.escape(rel["tag"])))
            note = "%s%s" % (html.escape(rel["date"]), size)
            notes = ""
        else:
            link = "<span class=dl-none>unavailable</span>"
            note = "could not reach GitHub"
            notes = ""
        # The game data sits beside the build because you need both, and the
        # zips are per-game already, so there is nothing to choose between.
        data = gamedata_info(g)
        if data:
            sha = data.get("sha256") or ""
            datalink = ("<a class=dl-data href='/gamedata/%s' "
                        "title='%s&#10;sha256 %s'>Game data &middot; %s</a>"
                        % (g, html.escape(data["name"]),
                           html.escape(sha[:16] + "…" if sha else "not published"),
                           human_bytes(data["size"])))
        elif cfg.get("data_in_build"):
            # Not a link, because there is nothing to fetch. It is here so the
            # row says why it has no game-data button, rather than leaving a
            # gap that looks like an upload someone forgot.
            datalink = ("<span class=dl-included title='Bungie released the "
                        "Marathon trilogy; the download carries all three "
                        "scenarios'>Data included in download</span>")
        else:
            datalink = ""
        rows.append(
            "<li class=dl-row>"
            "<img class=dl-icon src='%s' alt='' width=34 height=34 loading=lazy>"
            "<span class=dl-main><span class=dl-name>%s</span>"
            "<span class=dl-meta>%s%s</span></span>"
            "<span class=dl-actions>%s%s</span></li>"
            % (art_url("/emblem/%s.png" % g),
               html.escape(cfg["label"]), note, notes, datalink, link))
    return ("<ul class=dl-list>%s</ul>" % "".join(rows))


# ----------------------------------------------------------------- game data
#
# The paks and wads themselves, one zip per game, so both machines can be made
# identical without anyone posting a hard drive. Kept on the box rather than in
# the repository — 2.2 GB has no business in git — and picked up by the boot
# volume backup, so imaging the box backs up the game data with everything else.
#
# Served only to an authenticated admin, like everything else here. These are
# commercial game files; the point is two people who own the games keeping
# their own copies in step, and that stays true only while the door stays shut.
GAMEDATA_DIR = os.environ.get("RETRO_GAMEDATA_DIR", "/srv/game-data")
GAMEDATA_FILES = {
    "quake":    "quake-data.zip",
    "quake2":   "quake2-data.zip",
    "quake3":   "quake3-data.zip",
    "halflife": "half-life-data.zip",
    # No alephone entry, deliberately. It named alephone-data.zip, which has
    # never existed and never should: the DMG already carries all three
    # Marathon scenarios (see "data_in_build" in the GAMES table). Naming a
    # file here that is not on disk bought nothing -- gamedata_info() stats
    # the path and returns None either way -- and cost the reader the
    # impression that a download was missing. Do not add it back.
    "keeperfx": "keeperfx-data.zip",
}
_SUMS_CACHE = {}


def _gamedata_sums():
    """The published checksums, read from SHA256SUMS beside the zips.

    Hashing 2.2 GB on one shared core takes long enough to matter, so it is
    done once with sha256sum and read from the file here. The file is the
    record: if it disagrees with the zip, say nothing rather than guess."""
    path = os.path.join(GAMEDATA_DIR, "SHA256SUMS")
    try:
        st = os.stat(path)
    except OSError:
        return {}
    key = (st.st_mtime, st.st_size)
    if _SUMS_CACHE.get("key") == key:
        return _SUMS_CACHE.get("sums", {})
    sums = {}
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) == 2:
                    sums[os.path.basename(parts[1].lstrip("*"))] = parts[0]
    except OSError:
        return {}
    _SUMS_CACHE["key"], _SUMS_CACHE["sums"] = key, sums
    return sums


def gamedata_info(game):
    """Size and checksum for a game's data zip, or None if it is not there."""
    name = GAMEDATA_FILES.get(game)
    if not name:
        return None
    path = os.path.join(GAMEDATA_DIR, name)
    try:
        st = os.stat(path)
    except OSError:
        return None
    if not st.st_size:
        return None
    return {"name": name, "path": path, "size": st.st_size,
            "sha256": _gamedata_sums().get(name)}


def rag(game, st=None, state=None):
    """Red / amber / green for one server, and the words to go with it.

    Three states, not two, because two was not enough. On 2026-08-22 Quake II
    called ShutdownGame and left its process holding the port: systemd still
    said "active", so the page showed a green server nobody could join. That is
    the amber case — the unit is up and the engine is not answering — and it is
    the one worth seeing from across the room.
    """
    st = live_state(game) if st is None else st
    state = unit_state(GAMES[game]["unit"]) if state is None else state
    if state != "active":
        return ("down", "off", state or "stopped")
    if st.get("up"):
        return ("up", "on", "up")
    return ("warn", "warn", "no reply")


def render_health(hs=None):
    """The box itself, at a glance.

    Four numbers that between them say whether anything is wrong: how busy the
    one core is, how much of the memory is gone, how much of the 50 GB boot
    volume is left, and how much has been sent — which is the only figure here
    that could ever become a bill."""
    hs = hs or host_stats()
    cores = hs.get("cores") or 1
    tiles = []

    try:
        load = float(hs.get("load") or 0)
    except (TypeError, ValueError):
        load = 0.0
    tiles.append(gauge("Load", hs.get("load") or "?",
                       "of %d core%s" % (cores, "" if cores == 1 else "s"),
                       load / cores, key="load"))

    mu, mt = hs.get("mem_used"), hs.get("mem_total")
    tiles.append(gauge("Memory",
                       human_bytes(mu) if mu else "?",
                       "of %s" % human_bytes(mt) if mt else "unknown",
                       (mu / mt) if mu and mt else None, key="mem"))

    du, dt = hs.get("disk_used"), hs.get("disk_total")
    tiles.append(gauge("Disk",
                       human_bytes(du) if du else "?",
                       "of %s" % human_bytes(dt) if dt else "unknown",
                       (du / dt) if du and dt else None, key="disk"))

    # 10 TB a month is the Always Free transfer-out allowance, so the figure
    # beside it has to be per month too. /proc/net/dev resets at boot, which
    # made this read "43 MB of 10 TB" a few minutes after a restart no matter
    # what the month had actually done. vnstat keeps a database across reboots
    # and counts calendar months, so it is used when present.
    allowance = 10 * 1024 ** 4
    month, since = hs.get("sent_month"), hs.get("sent_since")
    if month is not None:
        sent = month
        # Say when counting began. vnstat cannot backfill, so the first month
        # after installing it is partial, and a partial figure presented as a
        # month total is the kind of number someone later makes a decision on.
        note = "of 10 TB free each month" if not since else \
               "of 10 TB free this month, counted since %s" % since
    else:
        sent = hs.get("sent")
        note = "of 10 TB free each month, since boot"
    tiles.append(gauge("Sent", human_bytes(sent) if sent is not None else "?",
                       note, (sent / allowance) if sent else 0.0, key="sent"))

    # Players is not a fraction of anything the box constrains, so it gets a
    # trace and a count rather than a bar.
    def as_int(v):
        # maxclients arrives as a string from Quake II and Quake III, which
        # publish it in an infostring, and as an integer from Quake and
        # Half-Life, which publish it as a binary field.
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0

    total = sum(as_int(live_state(g).get("count")) for g in GAMES)
    seats = sum(as_int(live_state(g).get("max")) for g in GAMES)
    tiles.append(gauge("Players", str(total), "of %d seats across %d servers"
                       % (seats, len(GAMES)) if seats else "across %d servers" % len(GAMES),
                       (total / seats) if seats else 0.0, warn=1.1, danger=1.2,
                       key="players"))

    services = []
    for g, cfg in GAMES.items():
        m = unit_memory(cfg["unit"])
        services.append("<li><span>%s</span><code>%s</code></li>"
                        % (html.escape(cfg["label"]), human_bytes(m) if m else "—"))
    for label, unit in (("Web admin", "retro-admin"), ("Tunnel", "cloudflared")):
        m = unit_memory(unit)
        services.append("<li><span>%s</span><code>%s</code></li>"
                        % (label, human_bytes(m) if m else "—"))

    return ("<div class=panel-meta><span id=hoststats>up %s &middot; load %s</span></div>"
            "<div class=gauges id=gauges>%s</div>"
            "<details><summary>Memory per service</summary>"
            "<ul class='list services'>%s</ul></details>"
            % (html.escape(hs.get("uptime") or "?"), html.escape(hs.get("load") or "?"),
               "".join(tiles), "".join(services)))


def page_overview(ip, allowed, ua=""):
    """One bay per server: which game, whether it is up, what is loaded, who is
    in it, and a picture of the level where the game has one.

    The point is that it reads at arm's length. The colour on the left edge is
    the game's own, so you know which server you are looking at before you have
    read a word of it."""
    bays = []
    for g, cfg in GAMES.items():
        st = live_state(g)
        state = unit_state(cfg["unit"])
        shot = ""
        if st.get("map") and map_shot_png(g, st["map"]):
            shot = ("<img class=bay-shot src='%s' alt='' width=76 height=57 loading=lazy>"
                    % art_url("/shot/%s/%s.jpg" % (g, html.escape(st["map"]))))
        level, pill_cls, pill_txt = rag(g, st, state)
        bays.append(
            "<a class='bay %s' href='/game/%s' style='--accent:%s'>"
            "<img class=bay-icon src='%s' alt='' width=58 height=58 loading=lazy>"
            "<span class=bay-main>"
            "<span class=bay-top><span class=bay-name>%s</span>"
            "<span class='pill %s' id='state-%s'>%s</span></span>"
            "<span class=bay-meta id='meta-%s'>%s</span>"
            "<span class=bay-life id='life-%s'>%s</span>"
            "<span class=bay-who id='who-%s'>%s</span>"
            "</span>%s</a>"
            % (level, g, cfg["accent"], art_url("/emblem/%s.png" % g),
               html.escape(cfg["label"]),
               pill_cls, g, pill_txt,
               g, meta_html(g, st), g, life_html(g, cfg["unit"], state),
               # Not who_html(g, st) here on purpose. Quake III is the only
               # game with bots, so it is the only bay that is usually
               # populated — every other bay's roster is empty most of the
               # time, which is what made this look like a Quake III problem
               # rather than a bay-height problem. meta_html already carries
               # the count ("6/8 players"); the per-player chips (name, bot
               # face, score, ping) belong on the game page, where a
               # variable-height list is expected and who_page still
               # supplies them.
               g, "", shot))
    servers = ("<div class=panel-meta><span id=totalplayers>%s</span></div>"
               "<div class=bays>%s</div>"
               % (html.escape(players_line()), "".join(bays)))
    # Formatted before concatenating, not after: % binds tighter than +, so
    # writing `a + b % args` applies the format to b alone — and b here is full
    # of CSS percentages.
    #
    # Three sections, one tab bar (data-tabs="overview" keys it apart from any
    # per-game tabs on other pages) -- app.js's buildTabs() finds every .tabs
    # container on the page and wires it up, no extra script needed here.
    # Servers stays selected by default: it's the one that changes.
    tabs = (
        "<div class='tabs' data-tabs='overview' role=tablist>"
        "<button class=tab data-tab=tab-servers aria-selected=true>Servers</button>"
        "<button class=tab data-tab=tab-downloads aria-selected=false>Get the games</button>"
        "<button class=tab data-tab=tab-health aria-selected=false>Server health</button>"
        "</div>"
        "<div class='card wide tabpanel' id=tab-servers>%s</div>"
        "<div class='card wide tabpanel' id=tab-downloads data-hide>%s</div>"
        "<div class='card wide tabpanel' id=tab-health data-hide>%s</div>"
        % (servers, render_downloads(), render_health()))
    return access_card(ip, allowed, ua) + tabs


def page_game(game, ip, allowed):
    # No back link. The nav is on every page and already has Overview in it, so
    # a second route to the same place is one more thing to read and a stray
    # tap target sitting above the fold on a phone.
    return "<div class='card wide game-wrap'>%s</div>" % render_game(game)


def notify_card():
    """The Web Push opt-in. #5.

    Empty of any state at render time -- app.js fills in whether this device
    is already subscribed once it can ask the browser, which is the only
    place that answer lives. The button starts disabled so a tap during that
    gap cannot race the check."""
    return ("<div class=card><h2>Tell this device</h2>"
            "<p class=hint id=notify-hint>A server that stops answering, or an "
            "access grant about to run out — even with the app closed.</p>"
            "<button id=notify-btn type=button disabled>Checking…</button>"
            "</div>")


def page_access(ip, allowed, ua=""):
    players = set_members("players") + set_members("players6")
    admins = set_members("admins") + set_members("admins_dyn")
    grants = _load_grants()
    return (access_card(ip, allowed, ua)
            + render_blocked(blocked_attempts(),
                             {str(a) for a, _ in players})
            + notify_card()
            + "<div class=card><h2><span>Can play right now</span><span>%s window</span></h2>"
              "<ul class=list>%s</ul></div>"
              "<div class=card><h2>Can reach SSH</h2><ul class=list>%s</ul>"
              "</div>"
            % (html.escape(ALLOW_TTL),
               render_access(players, grants, True,
                             "Nobody — the games are closed to everyone."),
               render_access(admins, grants, True, "Nobody.")))


def page_activity(ip, allowed, page=1):
    events = activity_lines(40)
    rows, total = play_sessions(PLAY_PAGE, (page - 1) * PLAY_PAGE)
    # An out-of-range page (someone edited the URL, or the log shrank under
    # them) still needs to show the nearest real page rather than "nothing on
    # this page" for a page number that no longer exists.
    pages = max(1, -(-total // PLAY_PAGE))
    if page > pages:
        page = pages
        rows, total = play_sessions(PLAY_PAGE, (page - 1) * PLAY_PAGE)
    return ("<div class='card wide'><h2><span>Who played</span>"
            "<span>%d recorded</span></h2><ul class=list id=played>%s</ul>%s</div>"
            "<div class='card wide'><h2>Recent admin activity</h2>"
            "<p class=log id=activity>%s</p></div>"
            % (total, _play_rows_html(rows, (page - 1) * PLAY_PAGE),
               play_pager_html(page, total),
               html.escape("\n".join(events)) or "nothing yet"))


def top_up(game):
    """Keep a game populated with bots.

    The engine's own bot_minplayers does nothing on this build — verified by
    setting it to 4 and watching an empty server stay empty for a minute, then
    seeding a bot by hand and watching it still not fill. So the topping up is
    done here instead, from the same status query the rest of the UI uses.

    Bots are told apart from people by ping: a bot always reports 0."""
    cfg = GAMES.get(game, {})
    if not cfg.get("has_bots"):
        return
    try:
        target = int(remembered_setting(game, "keep") or 0)
    except (TypeError, ValueError):
        return
    if target <= 0:
        return
    st = live_state(game)
    if not st.get("up"):
        return
    players = st.get("players") or []
    bots = [p for p in players if p.get("ping") == "0"]
    total = len(players)
    if total < target:
        roster = bots_for(game)
        if roster:
            pick = random.choice(roster)
            if not console(game, "addbot %s 3" % pick):
                print("retro-admin: top-up could not reach the %s console" % game,
                      flush=True)
    elif total > target and bots:
        # People arriving push bots back out, one per pass.
        if not console(game, "kick %s" % bots[-1]["name"]):
            print("retro-admin: top-up could not reach the %s console" % game, flush=True)


def warm_art():
    """Decode every emblem, level picture and bot face once, in the background.

    All three are cached to disk and never re-derived, so this costs nothing
    after the first run — but the first run is ~80 images, and without this it
    lands on whoever opens the page first after a deploy."""
    # Drop artwork left behind by an older ART_REV. Only the three artwork
    # directories, and only files that do not carry the current revision —
    # the grant bookkeeping in the state directory root is not touched.
    suffix = "-r%d.png" % ART_REV
    for sub in ("emblems", "shots", "icons"):
        d = os.path.join(STATE_DIR, sub)
        try:
            stale = [f for f in os.listdir(d) if not f.endswith(suffix)]
        except OSError:
            continue
        for f in stale:
            try:
                os.remove(os.path.join(d, f))
            except OSError:
                pass
        if stale:
            print("retro-admin: dropped %d stale %s" % (len(stale), sub), flush=True)

    done = 0
    for game in GAMES:
        try:
            if emblem_png(game):
                done += 1
            for m in maps_for(game)["all"]:
                if map_shot_png(game, m):
                    done += 1
            for b in bots_for(game):
                if bot_icon_png(game, b):
                    done += 1
        except Exception as exc:                     # never take the UI down
            print("retro-admin: warm %s: %s" % (game, exc), flush=True)
    print("retro-admin: artwork cache warm, %d images" % done, flush=True)


def maintainer():
    while True:
        time.sleep(20)
        for g in GAMES:
            try:
                top_up(g)
            except Exception:
                pass
        # #8. Here rather than in /api/status, because this thread runs
        # whether or not anyone has the page open and /api/status does not.
        # live_state() is memoised for 2s, so this shares top_up's queries
        # instead of asking the engines a second time.
        try:
            play_sample()
        except Exception:
            pass
        # #5. Same reasoning: has to run whether or not the page is open, or
        # it answers the same question #8's first design mistake did.
        try:
            watch_sample()
        except Exception:
            pass
        try:
            grant_watch()
        except Exception:
            pass


class Handler(BaseHTTPRequestHandler):
    server_version = "retro-admin"
    protocol_version = "HTTP/1.1"

    def _who(self):
        return verify_access(self.headers.get("Cf-Access-Jwt-Assertion"))

    def _ip(self):
        return self.headers.get("CF-Connecting-IP", self.client_address[0])

    def _same_origin(self):
        ref = self.headers.get("Origin") or self.headers.get("Referer") or ""
        if not ref:
            return False
        try:
            return urllib.parse.urlparse(ref).netloc.split(":")[0] == PUBLIC_HOST
        except ValueError:
            return False

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
                         # manifest-src, or the page refuses its OWN manifest.
                         # There is no default for it, so `default-src 'none'`
                         # catches it, and the browser reports the refusal in
                         # the console and nowhere else. That is what broke the
                         # iOS Home Screen app: no manifest means no scope, and
                         # with no scope iOS hands every link to a browser
                         # sheet. Two rounds of Cloudflare Access changes were
                         # spent on a request that never left the browser.
                         "manifest-src 'self'; base-uri 'none'; "
                         # worker-src, or registration is refused by
                         # `default-src 'none'` and the only sign is a console
                         # message. and the worker receives push and
                         # does not cache, which bin/check enforces.
                         "worker-src 'self'; "
                         # style-src keeps 'unsafe-inline' because a handful of
                         # elements carry a style= attribute, which no hash can
                         # cover. Adding a hash here would also make the browser
                         # ignore 'unsafe-inline' and drop those attributes.
                         # Inline CSS cannot execute; inline script can.
                         # api4.ipify.org: the one external call this page
                         # ever makes, and only when the visitor reached us
                         # over IPv6. It has no AAAA record of its own, so a
                         # successful reply proves the visitor's IPv4
                         # actually works -- that address is what the game
                         # servers need and Cloudflare never sees, since the
                         # games are not proxied. See live.js.
                         "script-src %s; "
                         "connect-src 'self' https://api4.ipify.org; "
                         "form-action 'self'; frame-ancestors 'none'" % SCRIPT_SRC)
        self.end_headers()
        self.wfile.write(b)

    def _manifest(self):
        """The web app manifest.

        scope and start_url are both "/", so every page counts as inside the
        app. Without a manifest iOS still runs the page full-screen off the
        apple- meta tags, but treats it as a bookmark rather than an app: no
        name, no icon, and nothing telling it where the app ends."""
        return self._send(200, json.dumps({
            "name": "Retro game servers",
            "short_name": "Retro",
            "id": "/",
            "start_url": "/",
            "scope": "/",
            "display": "standalone",
            "orientation": "any",
            "background_color": "#0d0e12",
            "theme_color": "#0d0e12",
            "description": "Quake, Quake II, Quake III and Half-Life, on one box in London.",
            "icons": [
                {"src": "/pwa/icon-192.png", "sizes": "192x192", "type": "image/png"},
                {"src": "/pwa/icon-512.png", "sizes": "512x512", "type": "image/png"},
                {"src": "/pwa/icon-512.png", "sizes": "512x512", "type": "image/png",
                 "purpose": "maskable"},
            ],
        }), "application/manifest+json")

    def _appicon(self, size):
        data = app_icon_png(size)
        if not data:
            return self._not_found()
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=86400")
        self.end_headers()
        return self.wfile.write(data)

    def _send_file(self, path, size, filename):
        """Stream a file, honouring Range.

        Range matters here rather than being a nicety: the largest of these is
        1.6 GB, and a download that has to start again from zero when the
        wifi drops is one that never finishes. With
        Accept-Ranges advertised, every browser and every curl -C - picks up
        where it stopped.

        Streamed in chunks, obviously — reading 1.6 GB into memory on a box
        with 6 GB of it would take the admin UI down and the game servers with
        it."""
        # Identity of THIS version of the file. mtime+size rather than the
        # published sha256, because SHA256SUMS is regenerated by `retro
        # gamedata` and may lag or be absent, while these two always exist and
        # always change together when the file is replaced.
        try:
            st = os.stat(path)
            etag = '"%x-%x"' % (int(st.st_mtime), st.st_size)
        except OSError:
            etag = None
        if etag and self.headers.get("If-None-Match") == etag:
            # Byte-for-byte what they already hold. Saves re-sending gigabytes.
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if not etag:
            etag = '"unknown"'

        start, end = 0, size - 1
        status = 200
        rng = self.headers.get("Range", "")
        m = re.match(r"bytes=(\d*)-(\d*)$", rng.strip()) if rng else None
        if m:
            a, b = m.group(1), m.group(2)
            if a:
                start = int(a)
                if b:
                    end = min(int(b), size - 1)
            elif b:
                # "bytes=-500" means the LAST 500 bytes, not the first.
                start = max(0, size - int(b))
            if start > end or start >= size:
                self.send_response(416)
                self.send_header("Content-Range", "bytes */%d" % size)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            status = 206
        length = end - start + 1
        self.send_response(status)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(length))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Disposition",
                         'attachment; filename="%s"' % filename)
        # These URLs are stable (/gamedata/quake2 forever) while the file
        # behind them is not: quake2-data.zip was replaced three times on
        # 2026-09-02 as missing client content was found. With no cache
        # headers at all -- which is what this sent until then -- a browser
        # may heuristically reuse the copy it already has, so someone
        # re-downloading to pick up a fix can silently get the old zip again.
        # That is indistinguishable from "the fix did not work".
        #
        # no-cache (revalidate every time, do not serve blind) rather than
        # no-store (never reuse): with the ETag below, an unchanged 2.1 GB
        # half-life-data.zip costs one 304 instead of 2.1 GB, while a changed
        # one is always fetched again.
        self.send_header("Cache-Control", "no-cache")
        self.send_header("ETag", etag)
        if status == 206:
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
        self.end_headers()
        if self.command == "HEAD":
            return
        remaining = length
        try:
            with open(path, "rb") as f:
                f.seek(start)
                while remaining > 0:
                    chunk = f.read(min(262144, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            # Somebody cancelled a 1.6 GB download. Entirely normal; it is not
            # worth a stack trace in the journal.
            pass

    def _not_found(self):
        return self._send(404, "not found", "text/plain; charset=utf-8")

    def _send_image(self, data, ctype):
        """An image, or a 404 if it could not be produced.

        Immutable for a week: every one of these carries ART_REV in its query
        string, so a changed picture is a changed URL and there is nothing for
        a stale cache to hold on to."""
        if not data:
            return self._not_found()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=604800, immutable")
        self.end_headers()
        self.wfile.write(data)

    def _console_unreachable(self, cfg, to):
        """The same refusal, from every control that writes to a console.

        Worth having in one place because the wording is a promise: it says the
        write did not happen. Six call sites had their own copy, and one of them
        had quietly lost its `to`, so a failed setting change dropped you back
        to the overview while every other failure kept you on the game page."""
        return self._redirect("Could not reach the %s console." % cfg["label"],
                              ok=False, to=to)

    def _redirect(self, msg=None, ok=True, to="/"):
        """Back where you came from, including which tab you were on.

        Every control on a game page is a form that POSTs and redirects, so
        without this, adding a bot from the Bots tab returned you to Play —
        once per bot. The tab is part of where you are, so it travels in the
        query string: shareable, and back/forward behave."""
        params = {}
        if msg:
            params["ok" if ok else "err"] = msg
        tab = getattr(self, "_tab", "")
        if tab:
            params["tab"] = tab
        loc = to + ("?" + urllib.parse.urlencode(params) if params else "")
        self.send_response(303)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/healthz":
            return self._send(200, "ok", "text/plain; charset=utf-8")

        # Before the auth check, deliberately, and under one path prefix so the
        # Cloudflare Access bypass that lets them through can be scoped to
        # exactly this and nothing else. Everything under /pwa/ is the app's
        # name, its colours and a Quake III logo — see terraform/cloudflare.
        if u.path == "/pwa/manifest.webmanifest":
            return self._manifest()
        if re.fullmatch(r"/pwa/icon-(180|192|512)\.png", u.path):
            return self._appicon(int(u.path.split("-")[1].split(".")[0]))
        if u.path == "/pwa/sw.js":
            # Served alongside the manifest, before this app's own auth check,
            # for the same reason: Cloudflare Access already gates it at the
            # edge, and the browser re-fetches this file on its own schedule
            # rather than as part of a page load. If that re-fetch could 403,
            # a bad service worker could not be replaced by a good one.
            #
            # no-store so an update is never held back. The script contains no
            # secret; it is the same source that is committed.
            b = SW_JS.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Service-Worker-Allowed", "/")
            self.end_headers()
            return self.wfile.write(b)
        try:
            who = self._who()
        except AuthError as e:
            self.log_message("DENIED GET %s: %s", self.path, e)
            return self._send(403, "forbidden", "text/plain; charset=utf-8")

        if u.path.startswith("/gamedata/"):
            # Authentication already happened above, at the top of do_GET, and
            # this is reached only past it.
            #
            # The game is looked up in a fixed dict and the filename comes from
            # that dict, never from the URL. So there is no path to traverse:
            # "/gamedata/../../etc/shadow" is simply not a key in GAMEDATA_FILES
            # and falls out as a 404.
            info = gamedata_info(u.path[len("/gamedata/"):])
            if not info:
                return self._not_found()
            return self._send_file(info["path"], info["size"], info["name"])

        if u.path.startswith("/emblem/"):
            g = u.path[len("/emblem/"):]
            if not g.endswith(".png") or (g[:-4] not in GAMES and g[:-4] not in DOWNLOAD_EXTRAS):
                return self._not_found()
            return self._send_image(emblem_png(g[:-4]), "image/png")

        if u.path.startswith("/shot/"):
            parts = u.path[len("/shot/"):].split("/")
            if len(parts) != 2 or not parts[1].endswith(".jpg"):
                return self._not_found()
            g, mp = parts[0], parts[1][:-4]
            # The name has to be a map this server actually has. Quake III
            # falls back to id's unknownmap placeholder for a level with no
            # levelshot, so without this check any name at all would come back
            # as a picture — and each one would leave a file in the cache.
            if (g not in GAMES or not SAFE_TOKEN.match(mp)
                    or mp not in maps_for(g)["all"]):
                return self._not_found()
            return self._send_image(map_shot_png(g, mp), "image/jpeg")

        if u.path.startswith("/icon/"):
            parts = u.path[len("/icon/"):].split("/")
            if len(parts) != 2 or not parts[1].endswith(".png"):
                return self._not_found()
            g, bot = parts[0], parts[1][:-4]
            if g not in GAMES or not SAFE_TOKEN.match(bot):
                return self._not_found()
            return self._send_image(bot_icon_png(g, bot), "image/png")

        if u.path == "/api/vapid-key":
            # The applicationServerKey. Public by definition -- it is handed to
            # Apple's and Google's push services on every subscribe -- but
            # there is no reason to serve it to anyone who is not signed in.
            # Empty string means this box cannot sign, and the page says so
            # rather than offering a button that cannot work.
            return self._send(200, json.dumps({"key": vapid_public_b64()}),
                              "application/json; charset=utf-8")

        if u.path == "/api/status":
            games = {}
            for g, c in GAMES.items():
                st = live_state(g)
                gs = unit_state(c["unit"])
                level, pill_cls, pill_txt = rag(g, st, gs)
                gmatch = render_match(g, st)
                games[g] = {"state": gs, "meta": meta_html(g, st),
                            # A server that falls over and is restarted while
                            # the page is open has to say so without a reload,
                            # which is the whole point of showing it.
                            "life": life_html(g, c["unit"], gs),
                            # The bays never want the chips -- Quake III is
                            # the only game usually populated (it's the only
                            # one with bots), so its bay was the only one
                            # whose height wandered. meta already carries the
                            # count. The game page wants the chips only when
                            # there is no chart.
                            "who": "",
                            "who_page": "" if gmatch else who_html(g, st),
                            "players": st.get("count") or 0,
                            # The page needs the verdict, not the ingredients:
                            # working it out in two places is how they drift.
                            "rag": level, "pill": pill_cls, "label": pill_txt,
                            "match": gmatch}
            ip = self._ip()
            players = set_members("players") + set_members("players6")
            grants = _load_grants()
            hs = host_stats()
            hs["seats"] = sum(_as_int(live_state(g).get("max")) for g in GAMES)
            return self._send(200, json.dumps({
                "games": games,
                "host": hs,
                "you": {"ip": ip,
                        "allowed": ip in [str(a) for a, _ in players],
                        "expires": next((t for a, t in players if str(a) == ip), None)},
                "players_list": render_access(players, grants, True,
                                              "Nobody \u2014 the games are closed to everyone."),
                "admins_list": render_access(set_members("admins") + set_members("admins_dyn"),
                                             grants, True, "Nobody."),
                "activity": html.escape("\n".join(activity_lines(40))) or "nothing yet",
                "played": play_html(),
                "total_players": sum(g["players"] for g in games.values()),
            }), "application/json; charset=utf-8")

        q = urllib.parse.parse_qs(u.query)
        flash = ""
        if q.get("ok"):
            flash = "<div class='flash ok'>%s</div>" % html.escape(q["ok"][0][:300])
        elif q.get("err"):
            flash = "<div class='flash err'>%s</div>" % html.escape(q["err"][0][:300])

        ip = self._ip()
        ua = self.headers.get("User-Agent", "")
        allowed = ip in ([str(a) for a, _ in set_members("players")]
                         + [str(a) for a, _ in set_members("players6")])

        hs = host_stats()
        hostline = "up %s \u00b7 load %s" % (hs.get("uptime") or "?", hs.get("load") or "?")
        players_line_text = players_line()

        if u.path == "/":
            return self._send(200, shell("Overview", "Retro game servers",
                                         "Four servers, one box in London.",
                                         page_overview(ip, allowed, ua), "/", who, flash,
                                         REFRESH_JS, players_line_text, hostline))
        if u.path == "/access":
            return self._send(200, shell("Access", "Access",
                                         "Who can reach the games, and for how long.",
                                         page_access(ip, allowed, ua), "/access", who, flash,
                                         REFRESH_JS, players_line_text, hostline))
        if u.path == "/activity":
            try:
                page = max(1, int(q.get("page", ["1"])[0]))
            except ValueError:
                page = 1
            return self._send(200, shell("Activity", "Activity",
                                         "What has been done, and by whom.",
                                         page_activity(ip, allowed, page), "/activity", who, flash,
                                         REFRESH_JS, players_line_text, hostline))
        if u.path.startswith("/game/"):
            game = u.path[len("/game/"):].strip("/")
            if game not in GAMES:
                return self._send(404, "no such game", "text/plain; charset=utf-8")
            cfg = GAMES[game]
            sub = "Port %d &middot; connect to <code>%s</code>" % (
                cfg["port"], html.escape(GAMES_HOST))
            return self._send(200, shell(cfg["label"], cfg["label"], sub,
                                         page_game(game, ip, allowed),
                                         "/game/" + game, who, flash, REFRESH_JS,
                                         players_line_text, hostline, favicon=game))
        return self._not_found()

    # One method per route. This was a single three-hundred-line if-chain, and
    # the length was hiding things: two of the routes reported success when the
    # write to the engine had failed, which is easier to see in a nine-line
    # method than in the middle of a wall.
    #
    # The second table is the routes that act on one game. They all need the
    # same four things resolved and checked first, so that happens once here
    # rather than at the top of each one.
    POST_ROUTES = {"/allow": "post_allow", "/allow-ipv4": "post_allow_ipv4",
                   "/allow-blocked": "post_allow_blocked",
                   "/revoke": "post_revoke",
                   "/subscribe": "post_subscribe",
                   "/unsubscribe": "post_unsubscribe"}
    GAME_POST_ROUTES = {"/mode": "post_mode", "/map": "post_map",
                        "/set": "post_set", "/say": "post_say",
                        "/bot": "post_bot", "/restart": "post_restart",
                        "/stop": "post_stop", "/kick": "post_kick"}

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode() if length else ""
        try:
            who = self._who()
        except AuthError as e:
            self.log_message("DENIED POST %s: %s", self.path, e)
            return self._send(403, "forbidden", "text/plain; charset=utf-8")
        if not self._same_origin():
            self.log_message("DENIED POST %s: cross-origin", self.path)
            return self._send(403, "cross-origin request refused", "text/plain; charset=utf-8")

        form = urllib.parse.parse_qs(raw)
        # Stashed for _redirect. Whitelisted, because it is echoed back into a
        # Location header and then read by script on the way in.
        tab = field(form, "tab")
        self._tab = tab if re.fullmatch(r"[a-z0-9_-]{1,16}", tab or "") else ""

        route = self.POST_ROUTES.get(self.path)
        if route:
            return getattr(self, route)(form, who)

        if self.path not in self.GAME_POST_ROUTES:
            return self._not_found()

        game = field(form, "game")
        if game not in GAMES:
            return self._redirect("Unknown game.", ok=False)
        cfg = GAMES[game]
        back = "/game/" + game

        return getattr(self, self.GAME_POST_ROUTES[self.path])(
            form, who, game, cfg, back)

    def post_allow(self, form, who):
        """Grant `ip` in the game/SSH sets for ALLOW_TTL.

        Deletes before adding, always. `nft add element` on a set element
        that already exists is a no-op that still exits 0 — confirmed live
        on this box, nftables v1.0.9: re-adding an already-granted address
        with a fresh timeout left the real kernel countdown completely
        unchanged, still ticking down from whenever it was FIRST granted.
        record_grant/the log line/the redirect all said the extension
        worked, because nothing here checked the one thing that would have
        caught it — the element's actual remaining time. Pressing "Extend
        for another 12h" a second or third time never extended anything.
        Delete-then-add always lands on a fresh element, so the timeout
        genuinely resets whether this is a first grant or the tenth
        extension. #4/#10's TTL model only holds if this is true."""
        ip = self._ip()
        try:
            family = ipaddress.ip_address(ip).version
        except ValueError:
            return self._redirect("Could not read your address.", ok=False)

        # v6 goes in the v6 set. This used to refuse outright, which broke
        # the one button that matters for anyone on a mobile network that
        # is IPv6-first — the admin hostname has AAAA records, so that is
        # not a corner case.
        #
        # But granting it here does not mean it works: confirmed live
        # 2026-09-02 that the box has no public IPv6 address at all (`ip -6
        # addr show scope global` is empty) and games/g.matthewdeaves.com
        # carry no AAAA record — the game ports are IPv4-only end to end,
        # regardless of what nftables says. A v6 grant can never be
        # followed by a working game connection, so the message must not
        # imply it can — it only used to say "you'll need its own grant",
        # which reads as "also do this" rather than "this path is a dead
        # end". Real case: a v6-only grant here, and no working connection
        # until the same person re-visited on IPv4.
        if family == 6:
            ok, err = nft_delete("players6", ip)
            if not ok:
                self.log_message("ALLOW FAILED %s by %s: %s", ip, who, err)
                return self._redirect("Could not update the firewall.", ok=False)
            r = run(["sudo", "nft", "add", "element", "inet", "filter", "players6",
                     "{ %s timeout %s }" % (ip, ALLOW_TTL)])
            if r.returncode:
                self.log_message("ALLOW FAILED %s by %s: %s", ip, who, r.stderr.strip())
                return self._redirect("Could not update the firewall.", ok=False)
            record_grant(ip, who)
            self.log_message("ALLOW6 %s by %s ttl=%s", ip, who, ALLOW_TTL)
            return self._redirect(
                "%s recorded, but that won't get you in: the game servers "
                "only have an IPv4 address. Turn IPv6 off for this "
                "network, reload this page, and press Allow again to "
                "grant your real IPv4 address." % ip, ok=False)

        # Refuse rather than grant: a relay address in `players` is a shared
        # CDN address that can only ever match strangers, and the person in
        # front of it still cannot join. Saying so is the useful answer.
        if is_relay_address(ip):
            self.log_message("ALLOW REFUSED %s by %s: iCloud Private Relay", ip, who)
            return self._redirect("%s — %s" % (ip, RELAY_ADVICE), ok=False)

        for setname in ("players", "admins_dyn"):
            ok, err = nft_delete(setname, ip)
            if not ok:
                self.log_message("ALLOW FAILED %s by %s: %s", ip, who, err)
                return self._redirect("Could not update the firewall.", ok=False)
        a = run(["sudo", "nft", "add", "element", "inet", "filter", "players",
                 "{ %s timeout %s }" % (ip, ALLOW_TTL)])
        b = run(["sudo", "nft", "add", "element", "inet", "filter", "admins_dyn",
                 "{ %s timeout %s }" % (ip, ALLOW_TTL)])
        if a.returncode or b.returncode:
            self.log_message("ALLOW FAILED %s by %s", ip, who)
            return self._redirect("Could not update the firewall.", ok=False)
        record_grant(ip, who)
        self.log_message("ALLOW %s by %s ttl=%s", ip, who, ALLOW_TTL)
        return self._redirect("%s can reach the games and SSH for %s." % (ip, ALLOW_TTL))

    def post_allow_ipv4(self, form, who):
        """Grant an IPv4 address the browser found for itself, in the
        background, after post_allow only had an IPv6 address to give it.

        live.js sends this: when the page loads over IPv6, it asks
        api4.ipify.org (no AAAA record of its own) what address that request
        used, and if one comes back it is real — the games are not behind
        Cloudflare, so this is the one way to learn the address they will
        actually see, since a single connection only ever carries one family.

        Trust here is weaker than post_allow's, which reads
        CF-Connecting-IP: a network fact, not something a page reports about
        itself. Bounded two ways to keep that acceptable: this route needs
        the same Cloudflare Access session as every other control on the
        site (only the two named admin emails ever reach it), and unlike
        post_allow it never touches admins_dyn — a discovered address can
        only ever open the game ports, never SSH."""
        raw = field(form, "ip") or ""
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            self.log_message("DENIED POST /allow-ipv4: not an address: %r", raw)
            return self._send(400, "bad address", "text/plain; charset=utf-8")
        # is_global alone lets 224.0.0.1 through -- IANA counts multicast
        # space as "global" too, which is true for allocation purposes and
        # useless here: no real client ever connects FROM a multicast
        # address, so it can only be a mistake or a malformed report.
        if (not isinstance(addr, ipaddress.IPv4Address) or not addr.is_global
                or addr.is_multicast):
            self.log_message("DENIED POST /allow-ipv4: not a public IPv4: %s", raw)
            return self._send(400, "not a public IPv4 address", "text/plain; charset=utf-8")
        ip = str(addr)
        # api4.ipify.org answers the RELAY when Private Relay is on, so this
        # path is the most likely place to discover one. Refusing keeps the
        # allowlist clean; the JSON says why so live.js can put it on screen,
        # which is the only way the person finds out -- nothing else about
        # this request is visible to them.
        if is_relay_address(ip):
            self.log_message("ALLOW4-DISCOVERED REFUSED %s by %s: iCloud Private Relay",
                             ip, who)
            return self._send(200, json.dumps({"ok": False, "relay": True,
                                               "ip": ip, "advice": RELAY_ADVICE}),
                              "application/json; charset=utf-8")
        ok, err = nft_delete("players", ip)
        if not ok:
            self.log_message("ALLOW4-DISCOVERED FAILED %s by %s: %s", ip, who, err)
            return self._send(500, "could not update the firewall", "text/plain; charset=utf-8")
        r = run(["sudo", "nft", "add", "element", "inet", "filter", "players",
                 "{ %s timeout %s }" % (ip, ALLOW_TTL)])
        if r.returncode:
            self.log_message("ALLOW4-DISCOVERED FAILED %s by %s: %s", ip, who, r.stderr.strip())
            return self._send(500, "could not update the firewall", "text/plain; charset=utf-8")
        record_grant(ip, who)
        self.log_message("ALLOW4-DISCOVERED %s by %s ttl=%s", ip, who, ALLOW_TTL)
        return self._send(200, json.dumps({"ok": True, "ip": ip}),
                          "application/json; charset=utf-8")

    def post_allow_blocked(self, form, who):
        """Let in an address the games themselves saw being refused.

        The address comes from the page, but unlike post_allow_ipv4 it is not
        taken on trust: it is only accepted if it is in the `blocked` set
        right now, which nftables put there because that address actually
        sent a packet at a game port in the last BLOCKED_TTL. So the thing
        being vouched for is a fact the kernel recorded, not a claim the
        browser made -- you cannot use this to open a port for an address
        that never knocked.

        Games only, never admins_dyn: knocking on a game port says nothing
        about whether someone should reach SSH."""
        raw = field(form, "ip") or ""
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            return self._redirect("Not a valid address.", ok=False)
        ip = str(addr)
        if ip not in {str(a) for a, _ in set_members("blocked")}:
            # Expired while the page sat open, or never there at all.
            self.log_message("DENIED POST /allow-blocked %s by %s: not blocked", ip, who)
            return self._redirect(
                "%s is not in the blocked list any more — reload and try again, or "
                "have them attempt to join once more." % ip, ok=False)
        ok, err = nft_delete("players", ip)
        if not ok:
            self.log_message("ALLOW-BLOCKED FAILED %s by %s: %s", ip, who, err)
            return self._redirect("Could not update the firewall.", ok=False)
        r = run(["sudo", "nft", "add", "element", "inet", "filter", "players",
                 "{ %s timeout %s }" % (ip, ALLOW_TTL)])
        if r.returncode:
            self.log_message("ALLOW-BLOCKED FAILED %s by %s: %s", ip, who, r.stderr.strip())
            return self._redirect("Could not update the firewall.", ok=False)
        record_grant(ip, who)
        self.log_message("ALLOW-BLOCKED %s by %s ttl=%s", ip, who, ALLOW_TTL)
        return self._redirect("%s can reach the games for %s. Tell them to try "
                              "joining again now." % (ip, ALLOW_TTL))

    def post_subscribe(self, form, who):
        """A browser asking to be told when a server falls over.

        The subscription arrives as JSON inside a form field rather than as a
        JSON body, so it goes through the same origin and identity checks in
        do_POST as every other control here. A second POST route with its own
        parsing would be a second place for those checks to be forgotten."""
        try:
            sub = json.loads(field(form, "sub") or "{}")
        except ValueError:
            sub = {}
        if not isinstance(sub, dict) or not record_sub(sub, who):
            self.log_message("DENIED POST /subscribe: malformed subscription")
            return self._send(400, "bad subscription", "text/plain; charset=utf-8")
        self.log_message("SUBSCRIBE %s", who)
        return self._send(200, json.dumps({"ok": True}),
                          "application/json; charset=utf-8")

    def post_unsubscribe(self, form, who):
        ep = field(form, "endpoint") or ""
        forget_sub(ep)
        self.log_message("UNSUBSCRIBE %s", who)
        return self._send(200, json.dumps({"ok": True}),
                          "application/json; charset=utf-8")

    def post_revoke(self, form, who):
        ip = field(form, "ip")
        try:
            family = ipaddress.ip_address(ip).version
        except ValueError:
            return self._redirect("Not a valid address.", ok=False)
        # Every one of these has to come out. Dropping the address from
        # `players` but not `admins_dyn` leaves SSH open while the page
        # says the grant is gone.
        failed = []
        for setname in (["players6"] if family == 6 else ["players", "admins_dyn"]):
            ok, err = nft_delete(setname, ip)
            if not ok:
                failed.append("%s: %s" % (setname, err))
        if failed:
            # The record stays. Forgetting it here would remove the only
            # note that an address which can still get in was ever granted.
            self.log_message("REVOKE FAILED %s by %s: %s", ip, who, "; ".join(failed))
            return self._redirect(
                "%s could not be fully revoked and may still have access." % ip,
                ok=False, to="/access")
        forget_grant(ip)
        self.log_message("REVOKE %s by %s", ip, who)
        return self._redirect("%s revoked." % ip, to="/access")

    def post_mode(self, form, who, game, cfg, back):
        mode = field(form, "mode")
        if mode not in cfg["modes"]:
            return self._redirect("Unknown mode.", ok=False, to=back)
        title, cmds = cfg["modes"][mode]
        grouped = maps_for(game)
        pool = sort_maps(game, mode, grouped.get(mode) or grouped["all"])
        target = (pool or [None])[0]
        if not target:
            return self._redirect("No maps found for %s." % title, ok=False, to=back)

        if cfg.get("mode_needs_restart"):
            # cmds is this codebase's own data (GAMES[...]["modes"]), always
            # "set <key> <value>" -- trusted to parse cleanly, not user input.
            updates = {}
            for c in cmds:
                parts = c.split()
                if len(parts) == 3 and parts[0] == "set":
                    updates[parts[1]] = parts[2]
            if not mode_file_merge(game, updates):
                return self._redirect("Could not write the %s mode file."
                                      % cfg["label"], ok=False, to=back)
            if run(["sudo", "systemctl", "restart", cfg["unit"]]).returncode:
                return self._redirect("Restart of %s failed." % cfg["label"],
                                      ok=False, to=back)
            time.sleep(3)
            # The mode came from the file the restart read, so it holds
            # whatever happens next; only the map is still in question.
            remember_mode(game, mode)
            if not console(game, "%s %s" % (cfg["mapcmd"], target)):
                self.log_message("MODE %s -> %s by %s, but the map change to %s "
                                 "never reached the console", game, mode, who, target)
                return self._redirect(
                    "%s restarted into %s, but the map change to %s did not reach "
                    "the console — it is on whatever map it started on."
                    % (cfg["label"], title, target), ok=False, to=back)
            self.log_message("MODE %s -> %s (%s, via restart) by %s",
                             game, mode, target, who)
            return self._redirect(
                "%s restarted into %s on %s. Everyone was disconnected — this "
                "engine only reads those settings at startup."
                % (cfg["label"], title, target), to=back)

        # A half-applied mode is worse than a refused one: some of the
        # cvars change and the page reports a mode the engine is not in.
        for c in cmds + ["%s %s" % (cfg["mapcmd"], target)]:
            if not console(game, c):
                self.log_message("MODE %s -> %s by %s FAILED at %r", game, mode, who, c)
                return self._redirect("Could not reach the %s console. The mode "
                                      "may be half applied." % cfg["label"],
                                      ok=False, to=back)
        remember_mode(game, mode)
        self.log_message("MODE %s -> %s (%s) by %s", game, mode, target, who)
        return self._redirect("%s is now %s on %s." % (cfg["label"], title, target), to=back)

    def post_map(self, form, who, game, cfg, back):
        name = field(form, "map").strip()
        if name == "random":
            st = live_state(game)
            mode = resolve_mode(game, st)
            pool = [m for m in (maps_for(game).get(mode) or maps_for(game)["all"])
                    if m != st.get("map")]
            if not pool:
                return self._redirect("No other map to switch to.", ok=False, to=back)
            name = random.choice(pool)
        if not SAFE_TOKEN.match(name):
            return self._redirect("That is not a valid map name.", ok=False, to=back)
        if name not in maps_for(game)["all"]:
            return self._redirect("%s has no map called %s." % (cfg["label"], name), ok=False, to=back)
        if not console(game, "%s %s" % (cfg["mapcmd"], name)):
            return self._console_unreachable(cfg, back)
        self.log_message("MAP %s %s %s by %s", game, cfg["mapcmd"], name, who)
        return self._redirect("%s switched to %s. %s" % (
            cfg["label"], name,
            "Players stayed connected." if cfg["mapcmd"] != "gamemap"
            else "Players reconnected."), to=back)

    def post_set(self, form, who, game, cfg, back):
        key = field(form, "key")
        value = field(form, "value").strip()
        spec = next((s for s in cfg["settings"] if s[0] == key), None)
        if spec is None:
            return self._redirect("Unknown setting.", ok=False, to=back)
        _, label, kind, extra = spec
        if kind == "int":
            if not value.isdigit() or not (extra[0] <= int(value) <= extra[1]):
                return self._redirect("%s must be between %d and %d."
                                      % (label, extra[0], extra[1]), ok=False, to=back)
        elif kind == "bool":
            if value not in ("0", "1"):
                return self._redirect("Bad value.", ok=False, to=back)
        elif kind == "choice":
            if value not in [v for v, _ in extra]:
                return self._redirect("Bad value.", ok=False, to=back)
        elif kind == "text":
            # Empty is a legal value (clears a password/MOTD); anything else
            # has to be safe to sit on a console command line, same rule as
            # chat -- SAFE_SAY already forbids the newline/semicolon/quote
            # that would turn one console write into two.
            if value and not SAFE_SAY.match(value):
                return self._redirect("%s: use plain text, no quotes or newlines."
                                      % label, ok=False, to=back)
        elif kind == "bits":
            # One switch was pressed; the cvar is all of them added up, so
            # the rest have to be preserved. Read the mask back from the
            # engine where it publishes it, and fall back to what this page
            # last applied where it does not.
            if value not in ("0", "1"):
                return self._redirect("Bad value.", ok=False, to=back)
            try:
                bit = int(field(form, "bit", "0"))
            except ValueError:
                return self._redirect("Bad value.", ok=False, to=back)
            if bit not in [b for b, _ in extra]:
                return self._redirect("Unknown rule.", ok=False, to=back)
            st_now = live_state(game)
            raw = ((st_now.get("cvars") or {}).get(key)
                   or remembered_setting(game, key)
                   or config_defaults(game).get(key) or "0")
            try:
                mask = int(raw)
            except (TypeError, ValueError):
                mask = 0
            mask = (mask | bit) if value == "1" else (mask & ~bit)
            value = str(mask)
            label = next(t for b, t in extra if b == bit)

        if key in cfg.get("restart_settings", ()):
            # CVAR_LATCH: a live `set` changes nothing until the engine's
            # next SV_InitGame, same reason the coop/dm mode toggle needs a
            # restart. Shares mode.cfg with that toggle, so merge rather
            # than overwrite -- see mode_file_merge().
            if not mode_file_merge(game, {key: value}):
                return self._redirect("Could not write the %s mode file."
                                      % cfg["label"], ok=False, to=back)
            if run(["sudo", "systemctl", "restart", cfg["unit"]]).returncode:
                return self._redirect("Restart of %s failed." % cfg["label"],
                                      ok=False, to=back)
            time.sleep(3)
            remember_setting(game, key, value)
            self.log_message("SET %s %s=%s (via restart) by %s", game, key, value, who)
            return self._redirect(
                "%s: %s set to %s. Everyone was disconnected — this engine "
                "only reads that setting at startup." % (cfg["label"], label, value),
                to=back)

        prefix = "set " if game in ("quake2", "quake3") else ""
        sent = value
        if kind == "text":
            # Quake II's `set` (Cvar_Set_f) takes exactly argc 3 or 4 and
            # reads the value as ONE token (Cmd_Argv(2)) -- unlike Quake
            # III's, which joins everything after the cvar name
            # (Cmd_ArgsFrom(2)). An unquoted multi-word value silently fails
            # on quake2 (wrong argc, prints usage, cvar untouched) while
            # looking identical to success here, and an unquoted EMPTY value
            # fails on both engines the same way -- quake2 for the same argc
            # reason, quake3 because argc==2 hits its "print current value"
            # branch instead of setting anything. Quoting fixes both cases
            # on both engines: COM_Parse-style tokenizers already strip the
            # quotes down to one token before Cvar_Set_f/Cmd_ArgsFrom ever
            # see it, so this is not a shell-style pass-through, and SAFE_SAY
            # already forbids an embedded '"' from breaking back out.
            # Verified live on the box both ways, multi-word and empty.
            sent = '"%s"' % value
        if not console(game, "%s%s %s" % (prefix, key, sent)):
            return self._console_unreachable(cfg, back)
        remember_setting(game, key, value)
        self.log_message("SET %s %s=%s by %s", game, key, value, who)
        return self._redirect("%s: %s set to %s." % (cfg["label"], label, value), to=back)

    def post_say(self, form, who, game, cfg, back):
        text = field(form, "text").strip()
        if not SAFE_SAY.match(text):
            return self._redirect("A message must be one line, under 120 "
                                  "characters, and free of quotes and semicolons.",
                                  ok=False, to=back)
        if not console(game, 'say %s' % text):
            return self._console_unreachable(cfg, back)
        self.log_message("SAY %s %r by %s", game, text[:60], who)
        return self._redirect("Sent to %s." % cfg["label"], to=back)

    def post_kick(self, form, who, game, cfg, back):
        """`kick <name>` on purpose, never a slot number.

        All four engines' kick command accepts a name (Quake:
        host_cmd.c:1999-2076, Quake II: SV_SetPlayer falls through to a name
        match, Quake III: SV_GetPlayerByHandle, Half-Life: SV_ClientByName),
        but the NUMBER each one expects is not the same number, and for
        Half-Life it is not even the number `status` prints -- `status`
        shows the connection slot, `kick #N` wants a separate, persistent
        userid that only happens to match before a reconnect (verified in
        sv_client.c). Kicking by exact name sidesteps every one of those
        four different numbering schemes at once, at the cost of nothing:
        the name has to match a name live_state() reports right now, read
        fresh, so there is no free-text injection surface here either."""
        if cfg.get("gatherer"):
            return self._redirect("%s has no console to kick from." % cfg["label"],
                                  ok=False, to=back)
        name = field(form, "name")
        st = live_state(game)
        if name not in {p.get("name") for p in (st.get("players") or [])}:
            return self._redirect("That player is not connected any more.",
                                  ok=False, to=back)
        if not console(game, "kick %s" % name):
            return self._console_unreachable(cfg, back)
        self.log_message("KICK %s %r by %s", game, name, who)
        return self._redirect("%s: kicked %s." % (cfg["label"], clean_name(game, name)), to=back)

    def post_bot(self, form, who, game, cfg, back):
        if not cfg.get("has_bots"):
            return self._redirect("%s has no bots." % cfg["label"], ok=False, to=back)
        do = field(form, "do")

        if do == "clear":
            # Stop the top-up first, or the maintainer puts them straight back.
            remember_setting(game, "keep", "0")
            if not console(game, "kick allbots"):
                return self._console_unreachable(cfg, back)
            self.log_message("BOT clear %s by %s", game, who)
            return self._redirect("Bots removed from %s." % cfg["label"], to=back)

        if do == "keep":
            count = field(form, "count", "0")
            if not count.isdigit() or not (0 <= int(count) <= 8):
                return self._redirect("Pick a number between 0 and 8.",
                                      ok=False, to=back)
            remember_setting(game, "keep", count)
            self.log_message("BOT keep %s -> %s by %s", game, count, who)
            if count == "0":
                return self._redirect("%s will no longer be topped up. Bots "
                                      "already in are left alone." % cfg["label"],
                                      to=back)
            top_up(game)
            return self._redirect("%s will be kept at %s players, filling with "
                                  "bots. It tops up every 20 seconds."
                                  % (cfg["label"], count), to=back)

        if do == "add":
            # A clicked face or Random button sends `pick`; the plain Add
            # button sends nothing, so the dropdown stands.
            name = field(form, "pick") or field(form, "name")
            skill = field(form, "skill", "3")
            team = field(form, "team")
            if skill not in [v for v, _ in SKILLS]:
                return self._redirect("Unknown skill level.", ok=False, to=back)
            if team not in ("", "red", "blue"):
                return self._redirect("Unknown team.", ok=False, to=back)
            roster = bots_for(game)
            if not roster:
                return self._redirect("No bots found in the pk3s.", ok=False, to=back)
            if name == "random":
                name = random.choice(roster)
            elif name not in roster:
                return self._redirect("%s has no bot called that."
                                      % cfg["label"], ok=False, to=back)
            cmd = "addbot %s %s" % (name, skill)
            if team:
                cmd += " %s" % team
            if not console(game, cmd):
                return self._console_unreachable(cfg, back)
            self.log_message("BOT add %s %s skill=%s team=%s by %s",
                             game, name, skill, team or "auto", who)
            return self._redirect("%s joined %s on %s."
                                  % (name, cfg["label"], dict(SKILLS)[skill]),
                                  to=back)

        return self._redirect("Unknown bot action.", ok=False, to=back)

    def post_stop(self, form, who, game, cfg, back):
        """Take a server down and leave it down.

        The record of who did it is written BEFORE the stop, so a stop that
        succeeds is never left unattributed. Writing it afterwards would mean
        a crash in between produced exactly the thing this ticket's ADR set
        out to prevent: a server that is off with nobody's name on it."""
        remember_stop(game, who)
        if run(["sudo", "systemctl", "stop", cfg["unit"]]).returncode:
            forget_stop(game)
            self.log_message("STOP FAILED %s by %s", cfg["unit"], who)
            return self._redirect("Could not stop %s." % cfg["label"],
                                  ok=False, to=back)
        self.log_message("STOP %s by %s", cfg["unit"], who)
        return self._redirect("%s stopped. It stays off until someone starts "
                              "it again." % cfg["label"], to=back)

    def post_restart(self, form, who, game, cfg, back):
        # Whatever the file says, a unit that is being started was not left
        # off by anybody. Cleared first for the same reason the stop is
        # recorded first: the page must not be able to show a running server
        # as stopped.
        was_off = unit_state(cfg["unit"]) != "active"
        forget_stop(game)
        if run(["sudo", "systemctl", "restart", cfg["unit"]]).returncode:
            return self._redirect("Restart of %s failed." % cfg["label"], ok=False, to=back)
        if was_off:
            self.log_message("START %s by %s", cfg["unit"], who)
            return self._redirect("%s started." % cfg["label"], to=back)
        self.log_message("RESTART %s by %s", cfg["unit"], who)
        return self._redirect("%s restarted. Everyone was disconnected." % cfg["label"], to=back)

    # Paths that say nothing when they succeed. The 8s poll alone is ~10,800
    # lines a day per open tab, and every page load re-fetches a dozen icons.
    _QUIET = ("/api/status", "/icon/", "/emblem/", "/shot/", "/healthz",
              "/app.css", "/app.js", "/live.js", "/sw.js", "/pwa/")

    def log_request(self, code="-", size="-"):
        """Log the requests that mean something, and the failures of the ones
        that do not.

        This service wrote 74,000 journal lines a day, more than everything
        else on the box combined, almost none of it about anything anyone did.
        That is not merely untidy: on 2026-09-02 it is what an OOM kill of
        this very service sat unnoticed inside.

        Only successful fetches of the paths above are dropped. A 403, a 404
        or a 500 on any of them still gets a line -- an icon that stopped
        resolving or a poll that started failing is exactly the kind of thing
        this log is for. Everything else, /gamedata downloads and every POST
        included, is logged as before, and the explicit audit calls
        (ALLOW, ALLOW6, DENIED, REVOKE...) go through log_message and are not
        touched by this at all."""
        try:
            c = int(code)
        except (TypeError, ValueError):
            c = 0
        if 200 <= c < 400 and self.path.split("?")[0].startswith(self._QUIET):
            return
        super().log_request(code, size)

    def log_message(self, fmt, *args):
        # journald picks this up; it is the audit trail of who did what.
        print("retro-admin: " + (fmt % args), flush=True)


class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    # Anything still open belongs to a previous run of this process, and has
    # to be closed before the sampler starts appending to it.
    play_recover()
    threading.Thread(target=warm_art, daemon=True).start()
    threading.Thread(target=maintainer, daemon=True).start()
    Server(("127.0.0.1", 8080), Handler).serve_forever()
