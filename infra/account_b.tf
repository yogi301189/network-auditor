# infra/account_b.tf
# ====================
# Deploys the EventBridge forwarding rule in Account B.
# This rule captures Security Group changes and forwards them
# to Account A's central Event Bus for processing.
#
# Deploy separately using Account B credentials:
#   cd infra/
#   terraform workspace new account-b
#   terraform apply -var="deploy_account_b=true" -var="aws_account_b_region=us-east-1"
#
# OR apply manually via AWS Console in Account B (see instructions below)

# ── PROVIDER FOR ACCOUNT B ────────────────────────────────────────────────────
# This provider assumes the NetworkAuditorTargetRole in Account B
# so Terraform can deploy resources there from Account A's credentials.

provider "aws" {
  alias  = "account_b"
  region = var.aws_region

  assume_role {
    role_arn     = "arn:aws:iam::278119224464:role/NetworkAuditorTargetRole"
    session_name = "TerraformNetworkAuditor"
  }
}


# ── EVENTBRIDGE FORWARDING RULE IN ACCOUNT B ─────────────────────────────────
# Watches for Security Group changes in Account B and forwards
# them to Account A's central Event Bus automatically.

resource "aws_cloudwatch_event_rule" "account_b_sg_forward" {
  provider    = aws.account_b
  name        = "NetworkAuditorForwardSGChanges"
  description = "Forwards Security Group changes to Account A central Event Bus"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "AuthorizeSecurityGroupIngress",
        "ModifySecurityGroupRules",
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "account_b_forward_to_central" {
  provider  = aws.account_b
  rule      = aws_cloudwatch_event_rule.account_b_sg_forward.name
  arn       = aws_cloudwatch_event_bus.central.arn  # Account A's central bus

  # Role that gives Account B's EventBridge permission to put events
  # into Account A's Event Bus
  role_arn  = aws_iam_role.account_b_eventbridge_role.arn
}


# ── IAM ROLE IN ACCOUNT B FOR EVENTBRIDGE ────────────────────────────────────
# EventBridge in Account B needs a role to call events:PutEvents
# on Account A's Event Bus — cross-account API calls require explicit permission.

resource "aws_iam_role" "account_b_eventbridge_role" {
  provider    = aws.account_b
  name        = "NetworkAuditorEventBridgeForwardRole"
  description = "Allows Account B EventBridge to forward events to Account A"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "account_b_eventbridge_policy" {
  provider = aws.account_b
  name     = "NetworkAuditorEventBridgeForwardPolicy"
  role     = aws_iam_role.account_b_eventbridge_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["events:PutEvents"]
      Resource = aws_cloudwatch_event_bus.central.arn  # Account A's bus ARN
    }]
  })
}
