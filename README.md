# retro-server-infra

Infrastructure as code, and one web admin UI, for dedicated servers for five
old-Mac game ports, running on a single Oracle Cloud Always Free instance.

| Game | Repo | Server tag pinned in `bin/retro` |
|---|---|---|
| Quake | [`old-mac-quakespasm`](https://github.com/matthewdeaves/old-mac-quakespasm) | `server-v1.18` |
| Quake II | [`old-mac-quake2`](https://github.com/matthewdeaves/old-mac-quake2) | `server-v3.0.1` |
| Quake III Arena | [`old-mac-quake3`](https://github.com/matthewdeaves/old-mac-quake3) | `server-v0.6.7` |
| Half-Life | [`old-mac-half-life-1`](https://github.com/matthewdeaves/old-mac-half-life-1) | `server-v1.10.3` |
| Aleph One (Marathon) | [`alephone`](https://github.com/matthewdeaves/alephone) | `server-v1.0.0` |

**This repo builds nothing.** Those five repos build and ship server binaries
as tagged release tarballs; this repo decides where they run, who can reach
them, and how they're administered.

## The short version

- One free VM, Oracle Cloud Always Free -- 1 OCPU / 6 GB, deliberately half
  the ARM allowance, so there's no margin to eat into.
- Game servers reachable only from addresses on an nftables allowlist, not
  the open internet.
- One web admin UI behind a Cloudflare Tunnel and Cloudflare Access, so the
  box has no inbound listener for it and only your named email addresses can
  get in.
- The admin UI works through each engine's own console (a FIFO the systemd
  unit already holds open), so no rcon password is ever set or sent.
- An authenticated admin can add their own current address to the game
  allowlist from the UI, with a timeout -- the mechanism that copes with
  changing home IPs.

## Setting this up on your own Oracle account

### 1. Tools

```sh
brew install opentofu oci-cli gh jq
```
(OpenTofu, not Terraform -- they're drop-in compatible, Terraform just left
homebrew-core after its licence change.)

### 2. Oracle credentials

In the Oracle console: profile icon -> **My profile** -> **API keys** ->
**Add API key** -> **Generate API key pair** -> **Download private key** ->
**Add**. Download the key *before* clicking Add; you cannot retrieve it
afterwards.

```sh
mkdir -p ~/.oci && chmod 700 ~/.oci
mv ~/Downloads/*.pem ~/.oci/oci_api_key.pem
chmod 600 ~/.oci/oci_api_key.pem
```

Oracle then shows a configuration file preview -- paste it into
`~/.oci/config`, set `key_file` to the path above, `chmod 600` it. Check it
worked:

```sh
oci iam availability-domain list
```
A `401 NotAuthenticated` right after creating the key usually means "wait a
minute", not "wrong".

### 3. Cloudflare

You need a domain already added to Cloudflare, and a Zero Trust (Access) team
set up on the account -- Cloudflare's free tier covers both.

[dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)
-> **Create Token** -> **Custom token**, scoped to your one zone and one
account, with:

| Type | Permission | Access |
|---|---|---|
| Zone | DNS | Edit |
| Account | Cloudflare Tunnel | Edit |
| Account | Access: Apps and Policies | Edit |
| Account | Access: Organizations, Identity Providers, and Groups | Edit |

```sh
mkdir -p ~/.cloudflare && chmod 700 ~/.cloudflare
pbpaste > ~/.cloudflare/token && chmod 600 ~/.cloudflare/token
```

### 4. This repo

```sh
git clone <your fork>
cd retro-server-infra
./bin/hooks-install          # static checks before every commit
cp .env.example .env
cp terraform/compute/terraform.tfvars.example terraform/compute/terraform.tfvars
cp terraform/cloudflare/terraform.tfvars.example terraform/cloudflare/terraform.tfvars
```

Fill in `terraform/compute/terraform.tfvars` (your tenancy OCID, a budget
alert email), then:

```sh
cd terraform/compute && tofu init && tofu plan   # read it before applying
tofu apply
tofu output -raw public_ip                       # note this
```

Fill in `terraform/cloudflare/terraform.tfvars` (account/zone IDs from your
domain's Overview page, the IP from above, your admin email(s)), then:

```sh
cd ../cloudflare && tofu init && tofu apply
```

Fill in `.env` at the repo root -- `RETRO_SERVER_IP` (the same IP), your SSH
key, `RETRO_TENANCY_OCID`. `.env` and every `*.tfvars` are gitignored.

On the box, create `/etc/retro-admin/admin.env` from
`admin/retro-admin.env.example` with your real domain/team/email values (this
file is deliberately not pushed by any deploy step -- it's instance-specific,
same as `.env`).

Then push the pieces:

```sh
./bin/retro dropins    # systemd overrides, e.g. the QS_IP fix below
./bin/retro deploy all # the pinned server binaries from each game repo
./bin/retro admin      # the admin UI -- runs its own selftest first
./bin/retro drift      # confirms the box matches this checkout
```

### 5. Day to day

You do **not** need SSH for routine admin -- go to your admin hostname,
enter your email, Cloudflare sends a six-digit PIN. Once in, **Let me in**
adds your current address to the firewall for `RETRO_ALLOW_TTL` (default
12h) -- opening game ports and SSH for wherever you currently are, since the
email is the durable identity and the IP isn't.

```sh
./bin/retro status
./bin/retro map quake3 q3dm17
./bin/retro allow
./bin/retro logs quake2
```

Changed the admin UI? `./bin/retro admin` puts it on the box -- it runs
`selftest` first (renders every page, fetches every referenced image),
refuses to install anything that fails, and rolls back if `/healthz` doesn't
answer afterward. Don't `scp` it up by hand.

## Gotchas that will actually bite you

- **Never resize the instance up, never upgrade the tenancy to Pay As You
  Go.** An Always Free tenancy that's never been upgraded literally cannot
  be billed -- it refuses to provision rather than charging you. That's the
  real safety net.
- **Always read `tofu plan` before applying.** `cloud-init.yaml` is rendered
  from `user_data`, and Oracle treats any `user_data` change as requiring a
  whole new instance -- editing a firewall variable once produced `1 added,
  1 changed, 1 destroyed` and silently rebuilt the box, wiping everything on
  it. If a plan says anything is being destroyed, stop.
- **`map` and `changelevel` are not synonyms** in Quake and Half-Life --
  `map` disconnects every player first. `bin/retro map` encodes the correct
  command per engine; don't send raw console commands for map changes.
- **NetQuake advertises `127.0.1.1`** on this Ubuntu image unless `-ip` is
  pinned to the real address (`dropins/quakespasm-server.service.d/`) --
  `retro dropins` fills this in from `RETRO_SERVER_IP` automatically, but if
  the instance ever gets a new IP, update `.env` and re-run `retro dropins`.
- **`retro deploy <game>` installs whatever tag is pinned in `bin/retro`'s
  game table, not whatever is newest on GitHub.** Bump the pin first.
- **`retro drift` proves the box agrees with this repo, not that either one
  is correct.** It can't tell a value both sides agree on is stale relative
  to the outside world (an upstream release, the instance's real IP).
- **`retro verify` is destructive** -- it changes maps, modes and settings
  live to prove the admin UI's controls actually work, and refuses to run
  against a game with a real player connected. Don't run it during a game
  you care about.
- Full context on all of the above, plus the security model and engine
  quirks, lives in `.claude/rules/` for anyone (human or agent) working on
  this repo.

## Why the game traffic isn't behind Cloudflare

Cloudflare's proxy only speaks HTTP; proxying UDP needs Spectrum, an
Enterprise add-on. The game DNS record is DNS-only (grey cloud) -- only the
admin UI goes through the tunnel.
