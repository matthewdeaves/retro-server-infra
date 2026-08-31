#!/usr/bin/env python3
"""Drive game rendering and gatherer vs idTech mechanics locally.

Run by bin/check. No server, no network: it imports retro-admin.py and
stubs systemd and live state to verify all 5 games render correctly and
conform to their engine architectures.
"""
import importlib.util, os, shutil, sys, tempfile

MODULE = sys.argv[1] if len(sys.argv) > 1 else "admin/retro-admin.py"

sys.dont_write_bytecode = True
STATE = tempfile.mkdtemp(prefix="gathertest-")
os.environ["STATE_DIRECTORY"] = STATE
spec = importlib.util.spec_from_file_location("ra", MODULE)
ra = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ra)

# Stub systemd and live states
ra.unit_state = lambda unit: "active"
ra.unit_health = lambda unit: {"restarts": 0, "since": ra.time.time() - 3600}

fails = []
def want(label, got, expected):
    ok = got == expected
    print("  %-52s %s" % (label, "ok" if ok else "FAIL  got %r want %r"
                          % (got, expected)))
    if not ok:
        fails.append(label)

print("all five games configured and registered")
want("five games defined", len(ra.GAMES), 5)
for g in ("quake", "quake2", "quake3", "halflife", "alephone"):
    want("game %s exists in GAMES" % g, g in ra.GAMES, True)

print("\nidTech games render map pickers and mode controls")
for g in ("quake", "quake2", "quake3", "halflife"):
    ra.live_state = lambda game: {"up": True, "map": "testmap", "mode": "dm", "players": [], "cvars": {}}
    out = ra.render_game(g)
    want("%s has a map picker" % g, "select name=map" in out, True)
    want("%s has Change map button" % g, ">Change map<" in out, True)
    want("%s has Random button" % g, ">Random<" in out, True)

print("\nAleph One renders gatherer guidance rather than empty picker")
ra.live_state = lambda game: {"up": True, "map": None, "mode": None, "players": [], "cvars": {}}
a1_out = ra.render_game("alephone")
want("alephone has gather-info block", "class=gather-info" in a1_out, True)
want("alephone explains client gathering", "Marathon netgames use client-side gathering" in a1_out, True)
want("alephone mentions port", "4226" in a1_out, True)
want("alephone does not render broken select", "<select name=map" in a1_out, False)
want("alephone maps_for returns safe dict", isinstance(ra.maps_for("alephone"), dict), True)
want("alephone maps_for all is list", isinstance(ra.maps_for("alephone")["all"], list), True)

print("\nMeta HTML formats cleanly")
meta = ra.meta_html("alephone", {"up": True, "map": None, "cvars": {}})
want("alephone meta includes udp port", "udp 4226" in meta, True)

shutil.rmtree(STATE, ignore_errors=True)
print("\nFAILED: %s" % ", ".join(fails) if fails else "\nall gatherer & game render cases passed")
sys.exit(1 if fails else 0)
