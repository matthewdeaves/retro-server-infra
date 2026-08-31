# Conventions

- OpenTofu, not Terraform — only because Terraform left homebrew-core.
- Two modules: `terraform/compute` (Oracle) and `terraform/cloudflare`.
  Cloudflare needs `CLOUDFLARE_API_TOKEN=$(cat ~/.cloudflare/token)` in front
  of every command.
- **The repo is the source of truth.** Anything changed on the box by hand is
  lost the next time it is rebuilt. `retro drift` compares the two and names
  every file that disagrees; it should always say no drift. systemd overrides
  live in `dropins/` and go up with `retro deploy`.
- `bin/retro` is the operational CLI. Prefer extending it over ad-hoc SSH.
- `retro deploy` resolves, downloads and checks every tarball before it stops
  anything, and puts the old files back if the new build will not stay up. It
  used to stop the unit first and look the release up second, which turned a
  deleted release or a short download into an outage. Keep that order.
- **`retro deploy <game>` installs the tag PINNED in `bin/retro`'s game
  table, never whatever is newest on GitHub.** It does not check. Deploying
  without first bumping the pin either fails loudly (asset for the old tag is
  gone) or, worse, "succeeds" by reinstalling the exact build already
  running — done live on 2026-08-28, restarted `xash-server` and dropped
  every connected player for zero version gain before the mistake was
  caught. Bump the pin (tag + asset stem, both fields) first, then deploy,
  every time.
- **A `retro deploy` that prints "rolled back" is not proof the box is
  healthy — go check.** The backup step only preserves a file that already
  existed at that exact path; a release that renames its binary or adds a
  new unit leaves nothing to restore. Bit for real on 2026-08-28 (alephone,
  `standalone_hub` → `alephone-server`): the rollback issued `systemctl
  start` and reported success without re-checking whether the process
  actually stayed up — it hadn't, the box sat crash-looping. Fixed to
  re-check `is-active` after its own restart, same as the primary path, but
  the underlying shape of the trap — "the command that grants/restores
  something exited 0" is not the same claim as "the thing it granted or
  restored is actually true" — is the same one behind the broken Extend
  button below. Re-read the live state after any deploy, not just the exit
  code.
- Deploy the web admin with `retro admin`, never by hand. It gates on
  `retro selftest`, which renders every page as an authenticated caller and
  fetches every image the HTML points at, and it rolls back if `/healthz` goes
  quiet. Compiling, parsing and "the 403 path works" have each in turn been
  mistaken here for evidence that the thing renders. They are not.
- Decoded artwork is cached to disk under the state directory and never
  re-derived. Change where an image comes from, or how it is processed, and you
  must bump `ART_REV` — otherwise the old picture survives the deploy and the
  change looks as though it silently did nothing.
- `./bin/hooks-install` once per checkout, then `bin/check` runs before every
  commit. If it fails, fix it rather than reaching for `--no-verify`; every
  check in it is there because something got through.
- No branch protection, no required review, no Dependabot.
- Verify against the running box rather than assuming a doc or a past commit
  is still true.
- **`retro drift` proves the box agrees with this repo — not that either one
  is right.** It has no way to know if a value both sides agree on is stale
  or fabricated relative to the outside world. Bit twice on 2026-08-28: the
  alephone server pin matched on both sides while naming a release that had
  never existed, and the quakespasm `QS_IP` drop-in matched on both sides
  while still naming the pre-rebuild address. Both read "same" the whole
  time. When a value depends on something outside the repo/box pair — an
  upstream release, the instance's actual current IP — check that outside
  thing directly; drift agreeing is not evidence.
- **To check what a UI change actually renders against real live state**,
  without a genuine Cloudflare Access login and without disturbing the
  running service: import the deployed module by path on the box and call
  its functions directly, the same way `selftest.py`/`verify.py` do —
  `importlib.util.spec_from_file_location` against
  `/opt/retro-admin/retro-admin.py`, then call e.g. `live_state()` or
  `page_overview()` straight from a one-off `python3 -` over SSH. Selftest's
  own synthetic checks run against whatever the box happens to hold at that
  moment, which is often an empty/idle server — not a stand-in for "populated
  with real players," which is the state that actually exercises most UI
  bugs.
