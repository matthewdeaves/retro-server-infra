# Overview tile icons

The four app icons from the game repos, which are much better than anything the
games themselves ship — the Ranger head with each Quake logo, and Gordon.
Rebuilt to 192px rounded squares on `#15151a`, so they read the same on a light
card and a dark one.

| File | Taken from |
|---|---|
| `quake.png` | `old-mac-quakespasm/MacOSX/newiconfinal.png` |
| `quake2.png` | `old-mac-quake2/docs/icon-source/quake2-transparent.png` |
| `quake3.png` | `old-mac-quake3/MacOSX/icon-source.png` |
| `halflife.png` | `old-mac-halflife/MacOSX/icon-source-halflife-new.png` |
| `alephone.png` | `alephone/data/icons/256x256/application-x-alephone-scea.png` |

The transparent two are trimmed to their artwork and centred; the two that are
opaque renders are cropped square from the top, which keeps Gordon's head in
frame rather than his chest.

`retro-admin.py` falls back to pulling an emblem out of the game's own pak or
pk3 if a file here is missing, so a checkout without this directory still shows
something — see `EMBLEMS` in that file.
