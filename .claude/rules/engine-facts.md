# Engine facts that are not obvious

Verified in the engine sources under `~/Documents/old-mac-*`:

- **`map` and `changelevel` are not synonyms.** Quake and Half-Life must use
  `changelevel`; their `map` calls `CL_Disconnect()` first and drops every
  player (`Quake/host_cmd.c:850` versus `:921`). Quake III carries clients
  through `map` (`code/server/sv_init.c:535`). Quake II's `gamemap` broadcasts
  a reconnect. `bin/retro map` encodes this — use it rather than raw console.
- **Gametype cvars are `CVAR_LATCH`.** Setting `g_gametype` does nothing until
  a map change. Player limits need a full restart and drop everyone.
- **Unit names do not match runtime directories.** `q2ded.service` uses
  `/run/quake2-server/`, `xash-server.service` uses `/run/half-life-server/`.
- **Never sync `*.so` with game content.** Quake II's game DLL is plain
  `game.so` with no architecture in the name, so an x86-64 one from a local
  smoke-test tree silently replaces the aarch64 one. The engine then says
  `cannot open shared object file` about a file that is plainly there, stays
  "active", answers nothing, and burns 100% of the core. `bin/retro content`
  excludes executables for this reason.
- **Quake III needs two things the tarball does not provide**:
  `/opt/quake3-server/home` must exist or systemd fails with `226/NAMESPACE`,
  and `server.cfg` must be copied into `baseq3/` or it runs on defaults while
  looking healthy.
- **yquake2 buffers stdout** when it is a pipe. `server-v2.7.1` and later
  carry `setvbuf` on the Unix path, so the `stdbuf -o0` drop-in is gone; the
  fix was carried forward through the 8.70 rebase deliberately, because
  upstream line buffers in the Windows backend only.
- **NetQuake advertises `127.0.1.1` on Ubuntu** unless `-ip` is pinned.
- **QuakeSpasm's console needed a pty until `server-v1.17`, and no longer
  does.** `Sys_ConsoleInput` used to return immediately when
  `isatty(STDIN_FILENO)` was false, and the unit feeds it a FIFO, so every
  command was silently discarded while the UI reported success — writing into
  a FIFO nobody reads still succeeds. Fixed upstream
  (old-mac-quakespasm#11), so the `script -qfec` wrapper is **gone** and the
  drop-in is one `Environment=QS_IP=` line. `exec 3<>` in the shipped unit is
  load-bearing and must stay: it makes the server its own writer, so `read()`
  never returns 0. It is also why a console write must end with a newline —
  there is no EOF to flush a partial line on.
- **Quake II 8.70 needs a writable `HOME`.** `server-v3.0.0` rebased the engine
  onto yquake2 8.70, which wants an XDG data directory and exits if it cannot
  make one — and the unit sets `ProtectHome=true`. Fixed upstream in
  `server-v3.0.1` (old-mac-quake2#14): the shipped `q2ded.service` carries
  `StateDirectory=quake2-server`, `HOME=` and `XDG_DATA_HOME=` itself, so the
  drop-in is gone. `XDG_DATA_HOME` is the one that actually fixes it.
- **A `<select>` and a `<button>` must never share a field name.** The select
  submits on every submit and arrives first, so `parse_qs()[name][0]` returns
  the dropdown rather than the button that was clicked. Every bot face in the
  Quake III grid added the wrong bot this way. `bin/check` refuses the shape.
- **A write that succeeds proves nothing.** Read the change back out of the
  engine — `retro verify` does exactly this for every mode, map and setting.
