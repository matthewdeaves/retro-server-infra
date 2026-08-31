variable "account_id" {
  description = "Not secret. From the domain Overview page, right sidebar."
  type        = string
}

variable "zone_id" {
  description = "Not secret. Same page as account_id."
  type        = string
}

variable "zone_name" {
  description = "Your domain, already added to Cloudflare."
  type        = string
}

variable "server_ip" {
  description = "From `cd ../compute && tofu output -raw public_ip`."
  type        = string
}

variable "games_hostname" {
  description = "The one name players point their clients at. All four games live here; the UDP port picks the game."
  type        = string
  default     = "games"
}

variable "admin_hostname" {
  type    = string
  default = "admin"
}

variable "admin_emails" {
  description = "The only addresses that may reach the admin UI. Each gets a one-time PIN by email."
  type        = list(string)
}
