# Oracle Cloud & Cost Constraints

## The one absolute constraint

**This must cost nothing. Ever.** Not "cheap" — zero.

- The instance is **1 OCPU / 6 GB on purpose**, which is half the Always Free
  allowance. 2 OCPU / 12 GB works out at 99.2% of the monthly cap and leaves no
  margin. **Never resize it up.**
- **Never upgrade the tenancy to Pay As You Go.** An Always Free tenancy that
  has not been upgraded cannot be billed at all — it refuses to provision
  rather than charging. That property is the actual protection here.
- Before adding any Oracle resource, confirm it is Always Free eligible. If
  that cannot be confirmed, do not add it. A reserved public IP was rejected on
  exactly these grounds even though it was convenient.
- A budget alert fires at the first penny. It should never fire.
- Data transfer **in** is free; **out** has a 10 TB/month allowance that four
  1990s game servers cannot plausibly approach.

## The trap that already destroyed the server once

`user_data` is rendered from `cloud-init.yaml`, which takes firewall variables
as template inputs. **OCI treats any user_data change as requiring a new
instance.** On 2026-08-21 editing `ssh_ingress_cidrs` produced
`1 added, 1 changed, 1 destroyed`, silently rebuilt the box, and destroyed
1.15 GB of game content along with a working deployment.

`oci_core_instance.games` now carries `ignore_changes = [..., metadata]`.

**Always read a `tofu plan` before applying.** If it says anything is being
destroyed, stop. cloud-init runs on first boot only, so tracking changes to it
buys nothing and can cost the whole server. If it genuinely must change, use
`tofu taint` deliberately and re-run the full deploy afterwards.
