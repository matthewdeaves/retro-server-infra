# The front door.
#
# What this gives you, end to end:
#
#   1. Anyone visits your admin hostname
#   2. Cloudflare — not our box — asks for an email address
#   3. Only the addresses in var.admin_emails are accepted. Everyone else is
#      refused at Cloudflare's edge and never reaches the server at all.
#   4. An allowed address gets a six-digit PIN by email, valid ten minutes
#   5. Once entered, the session is remembered for 24 hours
#
# The one-time PIN identity provider is built in and already enabled on this
# account, so there is no IdP resource to create and no password anywhere.
#
# Note the box has NO inbound listener for any of this. cloudflared dials out
# to Cloudflare and the traffic comes back down that tunnel, so there is no
# admin port to find, scan, or brute force. The nftables policy stays `drop`.

resource "random_bytes" "tunnel_secret" {
  length = 32
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "main" {
  account_id    = var.account_id
  name          = "retro-games"
  tunnel_secret = random_bytes.tunnel_secret.base64
  config_src    = "cloudflare"
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "main" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.main.id

  config = {
    ingress = [
      {
        hostname = "${var.admin_hostname}.${var.zone_name}"
        service  = "http://localhost:8080"
      },
      {
        # Required catch-all. Anything not matched above gets a 404 rather
        # than reaching whatever else might be listening on the box.
        service = "http_status:404"
      },
    ]
  }
}

# Proxied (orange cloud), unlike the games record. This one IS HTTP, so
# Cloudflare can and must front it — that is what puts Access in the path.
resource "cloudflare_dns_record" "admin" {
  zone_id = var.zone_id
  name    = var.admin_hostname
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.main.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
  comment = "retro-server-infra: admin UI via tunnel. Must stay proxied or Access is bypassed."
}

resource "cloudflare_zero_trust_access_policy" "admins" {
  account_id       = var.account_id
  name             = "retro-admins"
  decision         = "allow"
  # A month, not a day. This changes how long a session lasts, never who may
  # have one — the include list is still exactly the two addresses.
  #
  # It is here for the PWA. On iOS a web app added to the Home Screen has its
  # own cookie jar, separate from Safari's, so it starts unauthenticated no
  # matter how recently you logged in through the browser. Access then bounces
  # it to <team>.cloudflareaccess.com, which is a different origin, and iOS
  # hands that to Safari and leaves the app behind on whatever page it was
  # showing. That is the "PWA breaks when you click around" symptom, and no
  # amount of client-side work fixes it: the hop is cross-origin by design.
  #
  # A longer session does not remove the hop, it makes it rare, and a week was
  # still hitting it. The trade is that a lost phone stays signed in for a
  # month — acceptable for two people's own devices behind an email one-time
  # PIN, and revocable in one click from the Cloudflare dashboard.
  session_duration = "720h"

  # The entire allowlist. Adding your brother is one more address here.
  include = [for e in var.admin_emails : { email = { email = e } }]
}

# ---------------------------------------------------------------- PWA metadata
#
# One path, /pwa/, reachable without signing in. It holds the web app manifest
# and three icons: the app's name, its description, its colours, and a Quake
# III logo. No admin function, no game data, no address, nothing about who may
# sign in. Cloudflare's own login page already shows the application name to
# anyone who visits, so the incremental disclosure here is close to nil.
#
# It exists because a browser fetches a manifest with credentials mode "omit"
# by default, so Safari asked for it without the Access cookie, Access answered
# 302 to the login, and no manifest was ever delivered. Without a manifest
# there is no scope, and iOS falls back to legacy behaviour where a Home Screen
# app hands EVERY link to a browser sheet — which is the fault being fixed.
#
# crossorigin=use-credentials on the <link> is also set and is the correct fix
# on paper. It is not relied on: Safari's handling of that attribute for
# manifests is not documented anywhere I could find, and this has already
# failed on the phone twice. This makes the manifest reachable either way.
#
# Deliberately NOT a bypass on the whole app. To undo it, delete this resource
# and its policy; the admin itself is untouched either way.
resource "cloudflare_zero_trust_access_policy" "pwa_public" {
  account_id = var.account_id
  name       = "retro-pwa-metadata-public"
  decision   = "bypass"
  include    = [{ everyone = {} }]
}

resource "cloudflare_zero_trust_access_application" "pwa" {
  account_id       = var.account_id
  name             = "Retro PWA metadata"
  domain           = "${var.admin_hostname}.${var.zone_name}/pwa"
  type             = "self_hosted"
  session_duration = "720h"
  policies = [{
    id         = cloudflare_zero_trust_access_policy.pwa_public.id
    precedence = 1
  }]
}

resource "cloudflare_zero_trust_access_application" "admin" {
  account_id       = var.account_id
  name             = "Retro game server admin"
  domain           = "${var.admin_hostname}.${var.zone_name}"
  type             = "self_hosted"

  # Both of these are about the login round-trip, not about who may complete
  # it. The include list is untouched.
  #
  # The problem they address: added to the iOS Home Screen, this runs as a web
  # app with its own cookie jar, so it starts with no Access session. Every
  # link then 302s to <team>.cloudflareaccess.com, which is a different origin,
  # and iOS answers that by throwing a browser sheet over the app — the one
  # with "Done" in the corner — leaving the app on the page it started on.
  #
  # Coming back from that login is a cross-site navigation, and a cookie
  # without SameSite=None is not stored on one. Left at the default, the app
  # can be sent round the login repeatedly and never end up holding a session,
  # which is exactly the reported behaviour. Requires Secure, which it is.
  same_site_cookie_attribute = "none"

  # And one fewer hop through that sheet: the interstitial is a page whose only
  # content is a button that continues the redirect.
  skip_interstitial = true
  # A month, not a day. This changes how long a session lasts, never who may
  # have one — the include list is still exactly the two addresses.
  #
  # It is here for the PWA. On iOS a web app added to the Home Screen has its
  # own cookie jar, separate from Safari's, so it starts unauthenticated no
  # matter how recently you logged in through the browser. Access then bounces
  # it to <team>.cloudflareaccess.com, which is a different origin, and iOS
  # hands that to Safari and leaves the app behind on whatever page it was
  # showing. That is the "PWA breaks when you click around" symptom, and no
  # amount of client-side work fixes it: the hop is cross-origin by design.
  #
  # A longer session does not remove the hop, it makes it rare, and a week was
  # still hitting it. The trade is that a lost phone stays signed in for a
  # month — acceptable for two people's own devices behind an email one-time
  # PIN, and revocable in one click from the Cloudflare dashboard.
  session_duration = "720h"

  policies = [{
    id         = cloudflare_zero_trust_access_policy.admins.id
    precedence = 1
  }]
}

output "admin_url" {
  value = "https://${var.admin_hostname}.${var.zone_name}"
}

output "tunnel_id" {
  value = cloudflare_zero_trust_tunnel_cloudflared.main.id
}

# The connector token is not an attribute of the tunnel resource in provider
# v5; it comes from its own data source.
data "cloudflare_zero_trust_tunnel_cloudflared_token" "main" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.main.id
}

output "tunnel_token" {
  description = "Passed to cloudflared on the server. Sensitive."
  value       = data.cloudflare_zero_trust_tunnel_cloudflared_token.main.token
  sensitive   = true
}
