# The games record MUST stay grey-cloud (proxied = false).
#
# Cloudflare's proxy only speaks HTTP. Proxying raw UDP needs Spectrum, which
# is an Enterprise add-on. Turning the orange cloud on here would not slow the
# games down, it would stop them resolving to anything that can carry a game
# protocol at all.
#
# One hostname serves every game. They are distinguished by port:
#
#   Quake            26000/UDP    Quake/net_main.c:41
#   Quake II         27910/UDP    src/common/header/common.h:181
#   Quake III        27960/UDP    code/qcommon/qcommon.h:282
#   Half-Life        27015/UDP    engine/common/netchan.h:73
#   Aleph One         4226/TCP    Source_Files/Network/network.h:51
resource "cloudflare_dns_record" "games" {
  zone_id = var.zone_id
  name    = var.games_hostname
  type    = "A"
  content = var.server_ip
  proxied = false
  ttl     = 300
  comment = "retro-server-infra: game servers. Must stay DNS-only; Cloudflare cannot proxy UDP."
}

# Quake's in-game "server address" box holds 21 characters. A long domain
# plus the default "games" label can easily not fit -- this single-letter
# label is the shortest address a subdomain of your zone can produce, so it
# fits comfortably regardless of how long your domain name is.
#
# A reserved Oracle IP would be shorter still, but that costs money and isn't
# Always Free eligible, so it's deliberately not used.
resource "cloudflare_dns_record" "games_short" {
  zone_id = var.zone_id
  name    = "g"
  type    = "A"
  content = var.server_ip
  proxied = false
  ttl     = 300
  comment = "retro-server-infra: short alias for Quake's address box. DNS-only."
}
