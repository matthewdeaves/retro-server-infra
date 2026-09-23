# systemd drop-ins

Local overrides on the unit files that ship inside each game's release
tarball. `retro deploy` installs the tarball's units and then lays these on
top; `retro dropins` does just the second half.

They are tracked here because the box is rebuildable and these are not
optional. Without them:

**`quakespasm-server`** — sets `QS_IP`, the address NetQuake advertises.
Without it Ubuntu's `127.0.1.1` goes out and nobody can connect. `retro
dropins` fills it from `RETRO_SERVER_IP`. (The pty wrapper for the console
FIFO went away with `server-v1.17`, old-mac-quakespasm#11.)

`q2ded` used to need a `stdbuf -o0 -e0` wrapper for the same reason in
reverse — yquake2 fully buffered stdout when it was a pipe, so nothing reached
journald. `server-v2.7.1` flushes for itself, so that override is gone.

**`xash-server`** — sends `log on` down the console FIFO at every start
(`ExecStartPost`). Otherwise xash journals nothing when a player joins, so
a join cannot be confirmed from the server (#27). `mp_logecho` is already 1
in the game DLL, so once the log is on, connect and "entered the game" lines
go to the console and from there into the journal.
