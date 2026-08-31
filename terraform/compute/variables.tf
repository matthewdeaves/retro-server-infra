variable "oci_profile" {
  description = "Profile name in ~/.oci/config."
  type        = string
  default     = "DEFAULT"
}

variable "region" {
  description = <<-EOT
    Must be the tenancy's home region. Always Free resources only exist there,
    and the home region cannot be changed after signup.
  EOT
  type        = string
  default     = "uk-london-1"
}

variable "tenancy_ocid" {
  description = "Tenancy OCID. Also serves as the root compartment."
  type        = string
}

variable "compartment_ocid" {
  description = "Compartment to build in. Defaults to the tenancy root."
  type        = string
  default     = null
}

variable "ssh_public_key" {
  description = "Public key installed for the ubuntu user. Path, not contents."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

# ---------------------------------------------------------------- shape
#
# Always Free gives one of two things, and which one you get depends on
# whether London has ARM capacity on the day. The ARM allocation was halved
# during 2026 to 1,500 OCPU-hours / 9,000 GB-hours per month, which for an
# Always Free tenancy means 2 OCPUs and 12 GB — not the 4/24 most guides still
# quote. Do not raise these without checking the billing page first.

variable "shape" {
  description = "VM.Standard.A1.Flex (ARM) or VM.Standard.E2.1.Micro (AMD)."
  type        = string
  default     = "VM.Standard.A1.Flex"

  validation {
    condition     = contains(["VM.Standard.A1.Flex", "VM.Standard.E2.1.Micro"], var.shape)
    error_message = "Only the two Always Free shapes are supported here."
  }
}

variable "ocpus" {
  description = <<-EOT
    Ignored for the micro shape, which is fixed at 1 OCPU / 1 GB. The ARM
    Always Free allowance is 2 OCPU / 12 GB total; this defaults to HALF of
    it (1 OCPU) on purpose -- the full amount leaves no margin (99.2% of the
    monthly cap) and Oracle treats any resize as tearing down and rebuilding
    the instance. Raise this only after checking the billing page, and expect
    to lose the box's state when you do.
  EOT
  type        = number
  default     = 1
}

variable "memory_gb" {
  description = "Ignored for the micro shape. See ocpus above."
  type        = number
  default     = 6
}

variable "boot_volume_gb" {
  description = "Always Free allows 200 GB total block storage across the tenancy."
  type        = number
  default     = 50
}

# ---------------------------------------------------------------- access
#
# SSH is genuinely restricted at the cloud layer. The game ports are not,
# because the per-source allowlist is enforced by nftables on the host where
# the admin UI can add and expire entries at runtime.

variable "ssh_ingress_cidrs" {
  description = <<-EOT
    Addresses allowed to reach TCP 22 at the Oracle layer.

    This is deliberately 0.0.0.0/0 and the real filtering happens in nftables
    on the host, which is NOT a relaxation. The reason is that both admins are
    on residential connections that renumber, and pinning SSH to a fixed
    address here means every ISP renumber locks you out of your own tooling
    until you edit Terraform and re-apply.

    Moving enforcement to the host lets an admin who has authenticated to
    Cloudflare Access by email re-open SSH for wherever they are, with a
    timeout. The email is the durable identity; the address is not.

    What actually guards port 22:
      - nftables chain policy is `drop`, and only @admins (static) and
        @admins_dyn (email-granted, expiring) are accepted
      - sshd is key-only: PasswordAuthentication no, PermitRootLogin no
  EOT
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "game_udp_ports" {
  description = "Verified from engine source."
  type        = map(number)
  default = {
    quake     = 26000 # Quake/net_main.c:41
    quake2    = 27910 # src/common/header/common.h:181
    quake3    = 27960 # code/qcommon/qcommon.h:282
    halflife  = 27015 # engine/common/netchan.h:73
    alephone  = 4226  # Source_Files/Network/network.h:51
  }
}

variable "instance_name" {
  type    = string
  default = "retro-games"
}
