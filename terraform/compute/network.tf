locals {
  compartment_id = coalesce(var.compartment_ocid, var.tenancy_ocid)
}

data "oci_identity_availability_domains" "ads" {
  compartment_id = var.tenancy_ocid
}

resource "oci_core_vcn" "main" {
  compartment_id = local.compartment_id
  display_name   = "${var.instance_name}-vcn"
  cidr_blocks    = ["10.10.0.0/16"]
  dns_label      = "retrogames"
}

resource "oci_core_internet_gateway" "main" {
  compartment_id = local.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "${var.instance_name}-igw"
  enabled        = true
}

resource "oci_core_route_table" "public" {
  compartment_id = local.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "${var.instance_name}-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.main.id
  }
}

# The security list is the coarse layer. It decides which protocols and ports
# exist at all; it does NOT decide who may play.
#
# The game ports are open to the world here on purpose. The per-source
# allowlist lives in nftables on the host, because it
# has to be mutable at runtime — an authenticated admin adds their own address
# with a timeout from the web UI. Encoding that here instead would mean a
# `tofu apply` every time an admin's address changes.
#
# SSH is different. It is genuinely restricted here, because it never needs to
# change at short notice.
resource "oci_core_security_list" "public" {
  compartment_id = local.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "${var.instance_name}-sl"

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
  }

  dynamic "ingress_security_rules" {
    for_each = toset(var.ssh_ingress_cidrs)
    content {
      source      = ingress_security_rules.value
      protocol    = "6" # TCP
      description = "SSH"
      tcp_options {
        min = 22
        max = 22
      }
    }
  }

  dynamic "ingress_security_rules" {
    for_each = var.game_udp_ports
    content {
      source      = "0.0.0.0/0"
      protocol    = "17" # UDP
      description = "${ingress_security_rules.key} — filtered per source by nftables on the host"
      udp_options {
        min = ingress_security_rules.value
        max = ingress_security_rules.value
      }
    }
  }

  dynamic "ingress_security_rules" {
    for_each = { alephone = 4226 }
    content {
      source      = "0.0.0.0/0"
      protocol    = "6" # TCP
      description = "${ingress_security_rules.key} — filtered per source by nftables on the host"
      tcp_options {
        min = ingress_security_rules.value
        max = ingress_security_rules.value
      }
    }
  }

  # Path MTU discovery breaks silently without this, and a game protocol that
  # sends large snapshots is exactly where you would notice.
  ingress_security_rules {
    source      = "0.0.0.0/0"
    protocol    = "1" # ICMP
    description = "Fragmentation needed / destination unreachable"
    icmp_options {
      type = 3
      code = 4
    }
  }

  ingress_security_rules {
    source      = "10.10.0.0/16"
    protocol    = "1"
    description = "ICMP within the VCN"
    icmp_options {
      type = 3
    }
  }
}

resource "oci_core_subnet" "public" {
  compartment_id             = local.compartment_id
  vcn_id                     = oci_core_vcn.main.id
  display_name               = "${var.instance_name}-subnet"
  cidr_block                 = "10.10.1.0/24"
  route_table_id             = oci_core_route_table.public.id
  security_list_ids          = [oci_core_security_list.public.id]
  dns_label                  = "public"
  prohibit_public_ip_on_vnic = false
}
