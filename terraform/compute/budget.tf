# Cost tripwire.
#
# Everything in this repo is sized to sit inside Oracle's Always Free
# allowance, and an Always Free tenancy that has never been upgraded to Pay As
# You Go cannot be billed — it refuses to provision rather than charging you.
# This is the belt to that pair of braces: if anything ever does accrue cost,
# an email arrives the same day rather than a surprise arriving in a month.
#
# Budgets themselves are free.

variable "budget_alert_email" {
  description = "Where the spend alert goes."
  type        = string
}

resource "oci_budget_budget" "zero" {
  compartment_id = var.tenancy_ocid
  target_type    = "COMPARTMENT"
  targets        = [var.tenancy_ocid]

  # The smallest budget OCI accepts. The point is not the number, it is that
  # the alert below fires at 1% of it.
  amount       = 1
  reset_period = "MONTHLY"

  display_name = "always-free-tripwire"
  description  = "Fires if this tenancy ever accrues real cost. It should never fire."
}

resource "oci_budget_alert_rule" "any_spend" {
  budget_id      = oci_budget_budget.zero.id
  type           = "ACTUAL"
  threshold      = 1
  threshold_type = "PERCENTAGE"

  display_name = "any-actual-spend"
  message      = "retro-server-infra: the Oracle tenancy has accrued cost. It is supposed to be entirely Always Free. Check the billing page."
  recipients   = var.budget_alert_email
}
