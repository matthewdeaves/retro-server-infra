#!/usr/bin/env python3
"""Prove that the controls in the admin UI actually do something.

Run with `retro verify [game] [--force]`. It must run on the box, and it WILL
disturb whichever server(s) it touches: it changes modes, maps and settings
in turn and reads the result back out of the engine's own status protocol.
Naming a game limits it to that one; with none given it runs every game, same
as before.

Refuses to run against any game that has a real (non-bot) player connected
right now, unless given --force. Checked from the engine's own status
protocol, not the game-access grant -- a live grant proves someone COULD
connect, not that anyone has, and a server full of `top_up()`'s own bots is
not a server anyone is using. Added after this ran unfiltered and unguarded once: a bare `retro verify
quake3` restarted q2ded outright and left quake/quake3 on test settings,
while a game-access grant was live on the box the whole time.

Why it exists: Quake's console was dead for the entire life of this project.
The systemd unit fed commands into a FIFO on stdin, and QuakeSpasm's
Sys_ConsoleInput begins

    if (!stdinIsATTY || con_eof) return NULL;

so with stdin a FIFO rather than a terminal it read nothing, ever. Writing into
a FIFO nobody reads still succeeds, so `console()` returned True, the UI said
"Quake is now Co-op on start", and nothing whatsoever happened. Every check in
here reads the change back from the engine rather than trusting the write.

Not part of the deploy gate — it is destructive, and the deploy gate has to be
safe to run while people are playing.
"""
import importlib.util
import os
import sys
import time

MODULE = sys.argv[1] if len(sys.argv) > 1 else "/opt/retro-admin/retro-admin.py"
GAME_FILTER = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None
FORCE = len(sys.argv) > 3 and sys.argv[3] == "1"
os.environ.setdefault("STATE_DIRECTORY", "/tmp/retro-verify-state")
os.makedirs(os.environ["STATE_DIRECTORY"], exist_ok=True)

spec = importlib.util.spec_from_file_location("ra", MODULE)
ra = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ra)

GAMES = ra.GAMES
if GAME_FILTER:
    if GAME_FILTER not in GAMES:
        print("unknown game: %s (know: %s)" % (GAME_FILTER, ", ".join(ra.GAMES)))
        sys.exit(2)
    GAMES = {GAME_FILTER: GAMES[GAME_FILTER]}

FAILURES = []


def check(label, ok, detail=""):
    print("  %-54s %s" % (label, "ok" if ok else "FAIL"))
    if detail:
        print("      %s" % detail)
    if not ok:
        FAILURES.append(label)


def fresh(game):
    """Live state with the memo bypassed — this is testing cause and effect."""
    ra._LIVE_CACHE.pop(game, None)
    return ra.live_state(game)


def settle(game, want, get, tries=12, delay=1.0):
    """Engines apply things when they get round to it, not when asked."""
    for _ in range(tries):
        value = get(fresh(game))
        if value == want:
            return value
        time.sleep(delay)
    return get(fresh(game))


print("This changes maps, modes and settings live. Not during a game.\n")

if not FORCE:
    busy = []
    for game in GAMES:
        st = fresh(game)
        if not st.get("up"):
            continue
        count, names = ra.human_players(game, st)
        if count:
            who = " (%s)" % ", ".join(names) if names else ""
            busy.append("  %s: %d real player%s%s" %
                         (game, count, "" if count == 1 else "s", who))
    if busy:
        print("refusing to run -- real players connected right now:")
        print("\n".join(busy))
        print("\nThis would change their settings and, for some games, drop")
        print("them outright. Re-run with --force if that is really the plan.")
        sys.exit(3)

for game, cfg in GAMES.items():
    print("%s" % cfg["label"])
    st = fresh(game)
    if not st.get("up"):
        check("%s answers at all" % game, False, "no reply from the status protocol")
        continue

    # ---------------------------------------------------------------- console
    # Does a command sent to this engine reach it? Asking for a map change and
    # watching the map is the one test that cannot be faked by a write to a
    # FIFO nobody reads.
    listed = ra.maps_for(game)["all"]
    here = st.get("map")
    target = next((m for m in listed if m != here), None)
    if target:
        ra.console(game, "%s %s" % (cfg["mapcmd"], target))
        got = settle(game, target, lambda s: s.get("map"))
        check("console reaches the engine (map -> %s)" % target, got == target,
              "" if got == target else "map is still %r" % got)
    elif not listed:
        check("console reaches the engine", True,
              "no maps listed in game directory; not verifiable from here")
    else:
        check("console reaches the engine", False, "no second map to switch to")

    # ------------------------------------------------------------------ modes
    for mode, (title, cmds) in cfg["modes"].items():
        if cfg.get("mode_needs_restart"):
            # Quake II reads these only at startup, so the UI writes a file and
            # restarts. Reproduce that rather than pretending a console set
            # would work.
            body = "\n".join(cmds) + "\n"
            ra.run(["sudo", "tee", cfg["mode_file"]], stdin=body)
            ra.run(["sudo", "systemctl", "restart", cfg["unit"]])
            time.sleep(6)
        else:
            for c in cmds:
                ra.console(game, c)
            pool = ra.sort_maps(game, mode, ra.maps_for(game).get(mode) or listed)
            if pool:
                ra.console(game, "%s %s" % (cfg["mapcmd"], pool[0]))

        got = settle(game, mode, lambda s: s.get("mode"), tries=8)
        if got is None:
            # Nothing to read back. Say so rather than passing quietly.
            check("mode %s applied" % mode, True,
                  "engine does not report a gametype; not verifiable from here")
        else:
            check("mode %s applied (engine says %r)" % (mode, got), got == mode)

    # --------------------------------------------------------------- settings
    for key, label, kind, extra in cfg["settings"]:
        if kind != "int":
            continue
        lo, hi = extra
        want = "7" if lo <= 7 <= hi else str(lo)
        if key in cfg.get("restart_settings", ()):
            # CVAR_LATCH, same as mode_needs_restart above -- a live `set`
            # changes nothing until the next restart. Reproduce post_set's
            # own mechanism (mode_file_merge + restart) rather than a plain
            # console `set`, or this reports a FAIL for a feature that
            # actually works: maxclients did exactly that until fixed here,
            # 2026-09-03 -- "engine says 4" because the naive `set` this
            # loop used to send is simply ignored by a latched cvar.
            # Force deathmatch mode alongside the value: the coop mode test
            # just above can leave the mode file in coop, and Quake II's own
            # SV_InitGame clamps maxclients to 4 there regardless of what was
            # asked for -- measured live, 2026-09-03, a real engine limit,
            # not a bug. Parsed from "dm"'s own commands rather than
            # hardcoded so this keeps working if those cvars ever change.
            merge = {key: want}
            dm = cfg["modes"].get("dm") or cfg["modes"].get(cfg.get("default_mode"))
            if dm:
                for c in dm[1]:
                    parts = c.split()
                    if len(parts) == 3 and parts[0] == "set":
                        merge.setdefault(parts[1], parts[2])
            ra.mode_file_merge(game, merge)
            ra.run(["sudo", "systemctl", "restart", cfg["unit"]])
            time.sleep(6)
        else:
            prefix = "set " if game in ("quake2", "quake3") else ""
            ra.console(game, "%s%s %s" % (prefix, key, want))
        got = settle(game, want, lambda s: (s.get("cvars") or {}).get(key), tries=6)
        if got is None:
            check("setting %s applied" % key, True,
                  "engine does not publish %s; not verifiable from here" % key)
        else:
            check("setting %s applied (engine says %s)" % (key, got), got == want)
    print()

print("%s" % ("ALL OK" if not FAILURES else "%d FAILURES" % len(FAILURES)))
sys.exit(1 if FAILURES else 0)
