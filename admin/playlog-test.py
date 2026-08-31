#!/usr/bin/env python3
"""Drive the play log (#8) through a scripted evening.

Run by bin/check, so it gates every commit. It needs no server, no game
content and no network: it imports retro-admin.py, replaces live_state with a
script, and drives play_sample() on a fixed clock.

It exists because the first version of this code passed every static check and
was wrong three times over, in three variants of one mistake -- a value updated
in memory and then thrown away, or derived from the wrong side of a filter:

  * a Quake III server holding three bots and nobody else reported THREE
    PLAYERS, because the bot filter emptied the roster and the code then fell
    back to st["count"], which is the length of the list before the filter.
    top_up() keeps bots in that server deliberately, so this would have
    reported a busy server every night whatever anyone did.
  * the missed-reply counter was incremented but the write was never marked,
    so it read 1, 1, 1 for ever and a session that had ended never closed.
  * the end time was only written when something else happened to change, so
    a steady two-hour game recorded a finish at the last time a player joined.

Every case below is one the recorder must get RIGHT, and the expected values
were written before the output was read. The bot case is the control: a
recorder that scores it wrong is returning the same answer for every input.
"""
import importlib.util, json, os, shutil, sys, tempfile

MODULE = sys.argv[1] if len(sys.argv) > 1 else "admin/retro-admin.py"

# Importing the module would otherwise drop admin/__pycache__ into the repo.
sys.dont_write_bytecode = True

STATE = tempfile.mkdtemp(prefix="playtest-")
os.environ["STATE_DIRECTORY"] = STATE
spec = importlib.util.spec_from_file_location("ra", MODULE)
ra = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ra)

EMPTY = {"up": True, "players": [], "count": 0}
DOWN = {"up": False, "players": [], "count": None}

def person(name, ping="48"): return {"name": name, "ping": ping, "score": "3"}
def bot(name):               return {"name": name, "ping": "0", "score": "9"}
def q3(*rows):               return {"up": True, "players": list(rows), "count": len(rows)}
def hl(n):                   return {"up": True, "players": [], "count": n}

STATE_BY_GAME = {}
ra.live_state = lambda g, ttl=2.0: STATE_BY_GAME.get(g, EMPTY)

def sample(t, **games):
    STATE_BY_GAME.clear()
    STATE_BY_GAME.update({g: EMPTY for g in ra.GAMES})
    STATE_BY_GAME.update(games)
    ra.play_sample(now=t)

def sessions():
    return ra.play_sessions(50)

fails = []
def want(label, got, expected):
    ok = got == expected
    print("  %-52s %s" % (label, "ok" if ok else "FAIL  got %r want %r" % (got, expected)))
    if not ok: fails.append(label)

T = 1755900000  # a fixed epoch; nothing here may depend on the wall clock

print("bots alone must not look like a night of play")
for i in range(6):
    sample(T + i*20, quake3=q3(bot("Sarge"), bot("Grunt"), bot("Major")))
want("no session opened by three bots", len(sessions()), 0)

print("\na person joining a server full of bots counts as one")
sample(T + 200, quake3=q3(bot("Sarge"), bot("Grunt"), person("matt")))
s = sessions()
want("one session open", len(s), 1)
want("peak is the person, not the bots", s[0]["peak"], 1)
want("only the person is named", s[0]["names"], ["matt"])

print("\na second person arrives, then both leave")
sample(T + 220, quake3=q3(bot("Sarge"), person("matt"), person("james")))
sample(T + 240, quake3=q3(bot("Sarge"), person("matt"), person("james")))
s = sessions()
want("peak rose to two", s[0]["peak"], 2)
want("both named", sorted(s[0]["names"]), ["james", "matt"])

print("\none missed reply must not split the evening")
sample(T + 260, quake3=DOWN)
want("still one session, still open", (len(sessions()), sessions()[0].get("live")), (1, True))
sample(T + 280, quake3=q3(person("matt"), person("james")))
want("recovered without splitting", len(sessions()), 1)

print("\nthey leave: two consecutive empties close it")
sample(T + 300, quake3=EMPTY)
sample(T + 320, quake3=EMPTY)
s = sessions()
want("one finished session", len(s), 1)
want("not live any more", s[0].get("live"), None)
want("ran from the first join", s[0]["a"], T + 200)
want("to the last time anyone was actually seen", s[0]["b"], T + 280)
want("peak survived the close", s[0]["peak"], 2)

print("\nHalf-Life publishes a count and no names")
sample(T + 400, halflife=hl(2))
sample(T + 420, halflife=hl(2))
sample(T + 440, halflife=EMPTY)
sample(T + 460, halflife=EMPTY)
hs = [x for x in sessions() if x["g"] == "halflife"]
want("Half-Life session recorded", len(hs), 1)
want("from the count alone", hs[0]["peak"], 2)
want("with no names, and not pretending", hs[0]["names"], [])

print("\nthe page says so rather than leaving a blank")
markup = ra.play_html()
want("Half-Life line explains the missing names",
     "no names published" in markup, True)
want("the person is on the page", "matt" in markup, True)
want("no bot reached the page", "Sarge" in markup, False)

print("\na crash mid-session keeps what was written down, invents no tail")
sample(T + 500, quake=q3(person("james")))
sample(T + 800, quake=q3(person("james")))
open_before = json.load(open(ra.PLAY_FILE))["open"]
want("the open session was on disk", "quake" in open_before, True)
ra.play_recover()
s = [x for x in sessions() if x["g"] == "quake"]
want("recovered as one finished session", len(s), 1)
want("closed at the last sample, not at now", s[0]["b"], T + 800)
want("nothing left open", json.load(open(ra.PLAY_FILE))["open"], {})

print("\nthe cap holds and drops the oldest")
d = ra._load_play()
d["done"] = [{"g": "quake2", "a": i, "b": i + 60, "peak": 1, "names": []}
             for i in range(ra.PLAY_MAX + 50)]
ra._save_play(d)
d = ra._load_play()
ra._close(d, "quake2", {"a": 9_000_000, "b": 9_000_060, "peak": 1, "names": []})
want("held at the cap", len(d["done"]), ra.PLAY_MAX)
want("the newest survived", d["done"][-1]["a"], 9_000_000)
want("the oldest went first", d["done"][0]["a"], 51)

ra._save_play(d)
size = os.path.getsize(ra.PLAY_FILE)
print("\n  %d sessions at the cap occupy %d bytes (%.0f kB) on disk"
      % (len(d["done"]), size, size / 1024.0))

shutil.rmtree(STATE, ignore_errors=True)
print("\nFAILED: %s" % ", ".join(fails) if fails else "\nall play-log cases passed")
sys.exit(1 if fails else 0)
