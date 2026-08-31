#!/usr/bin/env python3
"""Drive the stop/start controls (#9).

Run by bin/check. No server, no network: it imports retro-admin.py and stubs
the two things that need systemd.

The ADR grants `systemctl stop` on one condition -- that a stopped server
always says who stopped it, so a server somebody parked never reads like one
that died. That condition is what these cases hold. It is not a property the
compiler or the CSS check can see, and it is the whole reason the permission
was acceptable, so it is checked rather than left to the document.
"""
import importlib.util, os, shutil, sys, tempfile

MODULE = sys.argv[1] if len(sys.argv) > 1 else "admin/retro-admin.py"

sys.dont_write_bytecode = True
STATE = tempfile.mkdtemp(prefix="powertest-")
os.environ["STATE_DIRECTORY"] = STATE
spec = importlib.util.spec_from_file_location("ra", MODULE)
ra = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ra)

# The only systemd this file needs. A server that has been up an hour and has
# never been restarted by systemd is the uninteresting baseline.
ra.unit_health = lambda unit: {"restarts": 0, "since": ra.time.time() - 3600}

fails = []
def want(label, got, expected):
    ok = got == expected
    print("  %-52s %s" % (label, "ok" if ok else "FAIL  got %r want %r"
                          % (got, expected)))
    if not ok:
        fails.append(label)

CFG = ra.GAMES["quake3"]
UNIT = CFG["unit"]

print("a parked server names whoever parked it")
ra.remember_stop("quake3", "admin@example.invalid")
out = ra.life_html("quake3", UNIT, "inactive")
want("says it was stopped", "stopped by" in out, True)
want("names the person", "admin@example.invalid" in out, True)
want("does not claim it fell over", "did not stay up" in out, False)

print("\nthe invariant the ADR actually rests on")
want("a parked server never reads as a crash",
     "did not stay up" in ra.life_html("quake3", UNIT, "inactive"), False)
want("an unclaimed stop never reads as parked",
     "stopped by" in ra.life_html("quake2", UNIT, "failed"), False)

print("\na running server ignores a stale record")
ra.remember_stop("quake", "someone@example.invalid")
out = ra.life_html("quake", UNIT, "active")
want("no stopped-by on a live server", "stopped by" in out, False)
want("it reports uptime instead", "up " in out, True)

print("\nnobody claimed it")
# Measured on the box 2026-08-23: `systemctl stop ioq3ded` leaves the unit
# FAILED, not inactive -- the engine exits 1 on SIGTERM. So systemd cannot
# tell a deliberate stop from a crash, and neither of these may pretend to.
for st in ("failed", "inactive"):
    out = ra.life_html("halflife", UNIT, st)
    want("%s says nobody here stopped it" % st,
         "nobody here stopped it" in out, True)
    want("%s does not guess at a crash" % st, "did not stay up" in out, False)

print("\nstarting clears the record")
ra.forget_stop("quake3")
want("record gone", ra.remembered_stop("quake3"), None)
want("and the page stops saying it",
     "stopped by" in ra.life_html("quake3", UNIT, "inactive"), False)

print("\nthe buttons follow the state")
live = ra.power_form("quake3", CFG, "active")
off = ra.power_form("quake3", CFG, "inactive")
want("a running server can be stopped", "action=/stop" in live, True)
want("a running server can be restarted", ">Restart<" in live, True)
want("stopping is confirmed first", "data-confirm" in live, True)
want("a stopped server offers Start", ">Start<" in off, True)
want("a stopped server offers no Stop", "action=/stop" in off, False)
want("Start is not labelled Restart", ">Restart<" in off, False)

print("\nthe route and the audit token exist")
want("/stop is routed", ra.Handler.GAME_POST_ROUTES.get("/stop"), "post_stop")
want("post_stop is implemented", hasattr(ra.Handler, "post_stop"), True)

shutil.rmtree(STATE, ignore_errors=True)
print("\nFAILED: %s" % ", ".join(fails) if fails else "\nall power cases passed")
sys.exit(1 if fails else 0)
