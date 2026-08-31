#!/usr/bin/env python3
"""Drive the health watch (#5) through scripted outages and a grant running
out. Run by bin/check. No server, no network: notify() and set_members()
are replaced with scripts.

Every case follows from the fleet's own quakespasm-CI incident, read the
same morning this was written: an absence is not an error and has to be
timed rather than waited for, a notification has to carry a clock time
rather than a state word, and a cached "last good" has to say what was good
and when. Those three are what these cases hold.
"""
import importlib.util, os, sys, tempfile, time

MODULE = sys.argv[1] if len(sys.argv) > 1 else "admin/retro-admin.py"

sys.dont_write_bytecode = True
STATE = tempfile.mkdtemp(prefix="watchtest-")
os.environ["STATE_DIRECTORY"] = STATE
spec = importlib.util.spec_from_file_location("ra", MODULE)
ra = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ra)

SENT = []
ra.notify = lambda title, body, tag="retro": (SENT.append((title, body, tag)), 1)[1]

fails = []
def want(label, got, expected):
    ok = got == expected
    print("  %-52s %s" % (label, "ok" if ok else "FAIL  got %r want %r" % (got, expected)))
    if not ok:
        fails.append(label)

T = 1755900000
UP = {"up": True}
DOWN = {"up": False}

def others_up(sick, sick_state):
    """Every game answers except the one under test, which returns whatever
    the case is currently driving. Isolates one engine's outage from the
    other three, which watch_sample checks every pass regardless."""
    return lambda g, ttl=2.0: (sick_state[0] if g == sick else UP)

# ---------------------------------------------------------------- watch_sample
print("an engine that keeps answering never fires")
ra._WATCH.clear(); SENT.clear()
ra.live_state = lambda g, ttl=2.0: UP
for i in range(10):
    ra.watch_sample(now=T + i * 20)
want("nothing sent", len(SENT), 0)

print("\na single missed pass must not fire — the control this exists for")
ra._WATCH.clear(); SENT.clear()
cur = [UP]
ra.live_state = others_up("quake2", cur)
ra.watch_sample(now=T)
cur[0] = DOWN
ra.watch_sample(now=T + 20)
want("one miss: silent", len(SENT), 0)

print("\nWATCH_MISSES consecutive misses fires exactly once, for the sick engine only")
for i in range(2, 6):
    ra.watch_sample(now=T + 20 * i)
want("fired exactly once, not once per pass after the threshold", len(SENT), 1)
title, body, tag = SENT[0]
want("names the sick game, not one of the healthy three", "Quake II" in title, True)
want("carries a clock time, not just a state word",
     any(ch.isdigit() for ch in body) and ":" in body, True)
want("says the last time it actually answered, not now",
     time.strftime("%H:%M", time.localtime(T)) in body, True)
want("does not claim it answered at the moment of the alert instead",
     time.strftime("%H:%M", time.localtime(T + 60)) in body, False)

print("\nit does not fire again while still down")
ra.watch_sample(now=T + 200)
ra.watch_sample(now=T + 400)
want("still just the one notification", len(SENT), 1)

print("\nanswering again sends exactly one recovery notice")
cur[0] = UP
ra.watch_sample(now=T + 500)
want("recovery sent", len(SENT), 2)
want("says it is back", "back" in SENT[1][0].lower(), True)
ra.watch_sample(now=T + 520)
ra.watch_sample(now=T + 540)
want("no repeat while healthy", len(SENT), 2)

print("\nan exception asking one engine counts as a miss, not as up, and does not take the others down")
ra._WATCH.clear(); SENT.clear()
def one_boom(g, ttl=2.0):
    if g == "halflife":
        raise OSError("no route to host")
    return UP
ra.live_state = one_boom
for i in range(6):
    ra.watch_sample(now=T + 20 * i)
want("the engine that cannot be asked at all still alerts", len(SENT), 1)
want("names the one that failed", "Half-Life" in SENT[0][0], True)

# ------------------------------------------------------------------ grant_watch
#
# set_members() returns EXPIRES: seconds remaining as of the moment it is
# asked, same as the real nftables read (verified against the box: "timeout":
# 43200, "expires": 11532). So a poll five seconds later has to hand back
# five seconds less, or the scripted clock is not simulating what a real
# countdown does. A stub returning a constant "remaining" while "now" moves
# invents a deadline that drifts every call, which is what the first version
# of this test did, and it manufactured its own failures.
def members_counting_down(deadline):
    return lambda now: (lambda secs: [("198.51.100.20", secs)] if secs > 0 else [])(
        deadline - now)

print("\na grant with time to spare is silent")
ra._GRANT_WARNED.clear(); SENT.clear()
deadline = T + 11532
ra.set_members = lambda name: (members_counting_down(deadline)(T)
                               if name in ("players", "admins_dyn") else [])
ra.grant_watch(now=T)
want("nothing sent, hours left", len(SENT), 0)

print("\ncrossing the warn threshold sends once per set, not once per pass")
deadline = T + 1700
for now in (T, T + 20, T + 40):
    ra.set_members = lambda name, now=now: (members_counting_down(deadline)(now)
                                            if name in ("players", "admins_dyn") else [])
    ra.grant_watch(now=now)
want("one warning for players, one for admins_dyn, not six", len(SENT), 2)
want("names which access", any("game" in s[1] for s in SENT), True)
want("names SSH separately", any("SSH" in s[1] for s in SENT), True)

print("\nrenewal re-arms a fresh warning near the new deadline")
renewed_at = T + 60
new_deadline = renewed_at + 43200
ra.set_members = lambda name: (members_counting_down(new_deadline)(renewed_at)
                               if name in ("players", "admins_dyn") else [])
ra.grant_watch(now=renewed_at)
want("the renewal itself is silent", len(SENT), 2)
near_new_deadline = new_deadline - 1700
ra.set_members = lambda name: (members_counting_down(new_deadline)(near_new_deadline)
                               if name in ("players", "admins_dyn") else [])
ra.grant_watch(now=near_new_deadline)
want("warns again as the NEW deadline nears, not the old one", len(SENT), 4)

print("\na grant that disappears (expired or revoked) is forgotten, not re-warned forever")
ra.set_members = lambda name: []
ra.grant_watch(now=near_new_deadline + 20)
want("nothing left to warn about", len(ra._GRANT_WARNED), 0)
want("no notification for an address that is simply gone", len(SENT), 4)

print("\nFAILED: %s" % ", ".join(fails) if fails else "\nall watch cases passed")
sys.exit(1 if fails else 0)
