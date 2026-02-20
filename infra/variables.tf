# infra/variables.tf
# ===================
# Input variables for the self-healing layer.
# Set these when running terraform apply.

variable "aws_region" {
  description = "AWS region to deploy the Lambda and EventBridge rule into"
  type        = string
  default     = "us-east-1"
}

variable "slack_webhook_url" {
  description = "Slack Incoming Webhook URL for violation alerts"
  type        = string
  sensitive   = true   # prevents the URL from appearing in terraform plan output
}

# ══════════════════════════════════════════════════════════════════════════════
# DRIFT DETECTION — append these to infra/variables.tf
# ══════════════════════════════════════════════════════════════════════════════

variable "auditor_account_id" {
  description = "AWS Account ID of the Auditor (Account A)"
  type        = string
  default     = "222892837737"
}
