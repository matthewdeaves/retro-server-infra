# systemd drop-ins

Local overrides on the unit files that ship inside each game's release
tarball. `retro deploy` installs the tarball's units and then lays these on
top; `retro dropins` does just the second half.

They are tracked here because the box is rebuildable and these are not
optional. Without them:

**`quakespasm-server`** — the console does not work at all. Its unit feeds
commands into a FIFO on stdin, and `Sys_ConsoleInput` in `sys_sdl_unix.c`
opens with

```c
if (!stdinIsATTY || con_eof)
    return NULL;
```

where `stdinIsATTY` is `isatty(STDIN_FILENO)`. A FIFO is not a terminal, so the
server read nothing, ever, and printed `Terminal input not available.` on every
start to say so. Writing into a FIFO nobody reads still succeeds, so the admin
UI reported every map change, mode change and setting as applied while none of
them were. `script` puts a pseudo-terminal in between and forwards the FIFO
into it, so `isatty` is true and the commands land. `TERM` matters too — the
same check rejects `raw` and `dumb`.

The override also passes `-ip`, without which NetQuake advertises `127.0.1.1`
on Ubuntu.

`q2ded` used to need a `stdbuf -o0 -e0` wrapper for the same reason in
reverse — yquake2 fully buffered stdout when it was a pipe, so nothing reached
journald. `server-v2.7.1` flushes for itself, so that override is gone.

Quake III and Half-Life need neither: both read a non-tty stdin quite happily,
which is why this went unnoticed for so long — three of the four worked.
