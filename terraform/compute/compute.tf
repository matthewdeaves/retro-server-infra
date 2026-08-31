locals {
  is_flex = var.shape == "VM.Standard.A1.Flex"

  # The micro shape is x86 and fixed at 1 OCPU / 1 GB. That is genuinely
  # enough here — these are 1996-1999 servers carrying eight players — but it
  # changes the architecture, so the deploy step has to pick the matching
  # release tarball rather than assuming aarch64.
  arch = local.is_flex ? "aarch64" : "x86_64"
}

data "oci_core_images" "ubuntu" {
  compartment_id           = local.compartment_id
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "24.04"
  shape                    = var.shape
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

resource "oci_core_instance" "games" {
  compartment_id      = local.compartment_id
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  display_name        = var.instance_name
  shape               = var.shape

  # Only flex shapes accept a shape_config. Setting one on the micro shape is
  # an error rather than a no-op.
  dynamic "shape_config" {
    for_each = local.is_flex ? [1] : []
    content {
      ocpus         = var.ocpus
      memory_in_gbs = var.memory_gb
    }
  }

  source_details {
    source_type             = "image"
    source_id               = data.oci_core_images.ubuntu.images[0].id
    boot_volume_size_in_gbs = var.boot_volume_gb
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.public.id
    assign_public_ip = true
    hostname_label   = var.instance_name
  }

  metadata = {
    ssh_authorized_keys = file(pathexpand(var.ssh_public_key))
    user_data           = base64encode(templatefile("${path.module}/cloud-init.yaml", {
      game_udp_ports = values(var.game_udp_ports)
      ssh_cidrs      = var.ssh_ingress_cidrs
    }))
  }

  lifecycle {
    # The image is refreshed by Canonical regularly. Without this, a routine
    # `tofu plan` proposes destroying and rebuilding the server because a newer
    # image exists.
    #
    # `metadata` matters even more, and this was learned the hard way on
    # 2026-08-21. user_data is rendered from cloud-init.yaml, which takes
    # ssh_ingress_cidrs as a template variable. Editing that firewall variable
    # therefore rewrote user_data, and OCI treats a user_data change as
    # requiring a NEW INSTANCE. `tofu apply` reported "1 added, 1 changed,
    # 1 destroyed" and quietly rebuilt the box: new IP, and 1.15 GB of game
    # content gone.
    #
    # cloud-init only ever runs on first boot, so tracking changes to it buys
    # nothing and costs the whole server. If cloud-init genuinely needs to
    # change, do it deliberately with `tofu taint`, not as a side effect of
    # editing a firewall list.
    ignore_changes = [source_details[0].source_id, metadata]
  }
}
