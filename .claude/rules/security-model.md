# Security model

Three separate planes; do not blur them.

- **Admin UI** — Cloudflare Access, email one-time PIN, exactly the addresses
  in `RETRO_ADMIN_EMAILS` (.env). The box has no inbound listener;
  `cloudflared` dials out. Do not add an identity provider, a service token, or
  a second Access policy without deliberately intending to widen access.
- **Game ports** — nftables `players` set, default policy `drop`. This is not
  optional: all four engines are UDP amplifiers and Half-Life measures 101x.
  Quake II, Quake III and Half-Life each carry a per-address query limiter of
  their own now; QuakeSpasm carries none, and none of them throttle joining.
  Those are a second layer, not a replacement. An open port here makes the box
  a DDoS reflector firing under Oracle's addresses, which is also a suspension
  risk under CSA §9.3(a).
- **SSH** — nftables `admins` (static) and `admins_dyn` (email-granted,
  expiring). Key-only.

Secrets live outside the repo: `~/.oci/oci_api_key.pem`, `~/.cloudflare/token`,
and `.env` (gitignored). Terraform state holds resource attributes in cleartext
and is gitignored. Never commit game content.

**`nft add element` on a set element that already exists is a no-op — it
still exits 0, but the real kernel timeout is left completely unchanged.**
Found live on 2026-08-28, nftables v1.0.9: every "Extend for another 12h"
click on an address already in `players`/`admins_dyn` relogged `ALLOW` and
told the page it worked, while the actual countdown kept running from
whenever that address was FIRST granted — confirmed by reproducing the exact
command by hand and watching `expires` barely move. Only a genuinely new
element ever sets a timeout for real. Any code that grants or extends an
address — `post_allow`, `cmd_allow`, and anything written later that touches
`players`/`players6`/`admins_dyn` — must delete the element first (`nft
delete element ...`, treating "not present" as success, same as the existing
`nft_delete()` helper) and only then add it. Re-introducing a bare `add`
silently brings this bug back.
