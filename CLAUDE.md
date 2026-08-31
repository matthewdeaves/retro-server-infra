# retro-server-infra

Infrastructure-as-code and a web admin UI for a set of dedicated retro game
servers (Quake, Quake II, Quake III, Half-Life, Aleph One) on Oracle Cloud's
Always Free tier. This repo is the source of truth for the live deployment —
anything changed on the box by hand is lost the next time it's rebuilt.

## Core constraints

- **Zero cost.** The whole thing must run indefinitely on Always Free. Never
  resize the instance up, never upgrade the tenancy to Pay As You Go. See
  `.claude/rules/oracle-constraints.md` before touching `cloud-init.yaml`,
  running `tofu plan`, or provisioning anything.
- **`bin/retro` is the operational CLI.** Prefer extending it over ad-hoc SSH.
  Deployments always come from a tagged release, never a working tree.
- **Security isolation** across three planes: the admin UI (Cloudflare
  Access), the game ports (nftables allowlist), and SSH (key-only, same
  allowlist mechanism). See `.claude/rules/security-model.md` before touching
  any of them.

## Read before you touch

- `.claude/rules/oracle-constraints.md` — before provisioning, editing
  `cloud-init.yaml`, running `tofu plan`, or resizing anything.
- `.claude/rules/engine-facts.md` — before touching engine CVARs, game
  content, or the systemd units.
- `.claude/rules/security-model.md` — before touching firewall rules, access
  tokens, SSH, or Cloudflare Access.
- `.claude/rules/conventions.md` — before writing operational scripts,
  deploying, or pushing (`bin/check` runs on every commit via
  `./bin/hooks-install`).

## Setup

See `README.md` for standing this up on your own Oracle/Cloudflare account.
