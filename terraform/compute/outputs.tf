output "public_ip" {
  description = "Point the grey-cloud DNS records here."
  value       = oci_core_instance.games.public_ip
}

output "ssh" {
  value = "ssh ubuntu@${oci_core_instance.games.public_ip}"
}

output "arch" {
  description = "Which release tarball the deploy step should fetch."
  value       = local.arch
}

output "shape" {
  value = oci_core_instance.games.shape
}
