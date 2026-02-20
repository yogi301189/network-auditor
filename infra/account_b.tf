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

# ══════════════════════════════════════════════════════════════════════════════
# DRIFT DETECTION — ACCOUNT B / TARGET (278119224464)
# Append this block to the bottom of infra/account_b.tf
# ══════════════════════════════════════════════════════════════════════════════


# ── IAM ROLE — REMEDIATION ────────────────────────────────────────────────────
# The Auditor Lambda assumes this role to fix drift in Account B.
# Scoped to exactly what each Golden Rule remediation needs.
# Trust: only the Auditor account Lambda role can assume this.

resource "aws_iam_role" "drift_remediation_role" {
  provider    = aws.account_b
  name        = "NetworkAuditorDriftRemediationRole"
  description = "Assumed by Auditor Lambda to auto-remediate drift in Account B"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${var.auditor_account_id}:role/NetworkAuditorLambdaRole"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "drift_remediation_policy" {
  provider = aws.account_b
  name     = "NetworkAuditorDriftRemediationPolicy"
  role     = aws_iam_role.drift_remediation_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecurityGroupRemediation"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupIngress",
        ]
        Resource = "*"
      },
      {
        Sid    = "S3Remediation"
        Effect = "Allow"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:GetBucketPublicAccessBlock",
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudTrailRemediation"
        Effect = "Allow"
        Action = [
          "cloudtrail:StartLogging",
          "cloudtrail:GetTrailStatus",
        ]
        Resource = "*"
      },
      {
        Sid    = "RDSRemediation"
        Effect = "Allow"
        Action = [
          "rds:ModifyDBInstance",
          "rds:DescribeDBInstances",
        ]
        Resource = "*"
      }
    ]
  })
}


# ── AWS CONFIG — RECORDER ─────────────────────────────────────────────────────
# Records configuration state of key resource types in Account B.
# This is what AWS Config uses to detect drift — no Terraform state needed.

resource "aws_iam_role" "config_role" {
  provider    = aws.account_b
  name        = "NetworkAuditorConfigRole"
  description = "Service role for AWS Config in Account B"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_role_managed" {
  provider   = aws.account_b
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# S3 bucket for Config delivery channel (Config audit history — not Terraform state)
resource "aws_s3_bucket" "config_logs" {
  provider      = aws.account_b
  bucket        = "network-auditor-config-logs-278119224464"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "config_logs_policy" {
  provider = aws.account_b
  bucket   = aws_s3_bucket.config_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSConfigBucketPermissionsCheck"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.config_logs.arn
      },
      {
        Sid       = "AWSConfigBucketDelivery"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.config_logs.arn}/AWSLogs/278119224464/Config/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

resource "aws_config_configuration_recorder" "account_b" {
  provider = aws.account_b
  name     = "NetworkAuditorConfigRecorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = false
    include_global_resource_types = false

    # Only the resource types covered by your 8 Golden Rules
    resource_types = [
      "AWS::EC2::SecurityGroup",
      "AWS::S3::Bucket",
      "AWS::IAM::User",
      "AWS::CloudTrail::Trail",
      "AWS::RDS::DBInstance",
    ]
  }
}

resource "aws_config_delivery_channel" "account_b" {
  provider       = aws.account_b
  name           = "NetworkAuditorConfigChannel"
  s3_bucket_name = aws_s3_bucket.config_logs.bucket

  depends_on = [aws_config_configuration_recorder.account_b]
}

resource "aws_config_configuration_recorder_status" "account_b" {
  provider   = aws.account_b
  name       = aws_config_configuration_recorder.account_b.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.account_b]
}


# ── AWS CONFIG RULES — ALL 8 GOLDEN RULES ─────────────────────────────────────

# Golden Rule 1: No SSH open to world
resource "aws_config_config_rule" "restricted_ssh" {
  provider = aws.account_b
  name     = "golden-rule-restricted-ssh"

  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }

  input_parameters = jsonencode({ blockedPort1 = "22" })
  depends_on       = [aws_config_configuration_recorder_status.account_b]
}

# Golden Rule 2: No RDP open to world
resource "aws_config_config_rule" "restricted_rdp" {
  provider = aws.account_b
  name     = "golden-rule-restricted-rdp"

  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }

  input_parameters = jsonencode({ blockedPort1 = "3389" })
  depends_on       = [aws_config_configuration_recorder_status.account_b]
}

# Golden Rule 3: S3 not publicly readable
resource "aws_config_config_rule" "s3_no_public_read" {
  provider = aws.account_b
  name     = "golden-rule-s3-no-public-read"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.account_b]
}

# Golden Rule 4: S3 not publicly writable
resource "aws_config_config_rule" "s3_no_public_write" {
  provider = aws.account_b
  name     = "golden-rule-s3-no-public-write"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.account_b]
}

# Golden Rule 5: MFA enabled (alert only — cannot auto-remediate)
resource "aws_config_config_rule" "mfa_enabled" {
  provider = aws.account_b
  name     = "golden-rule-mfa-enabled"

  source {
    owner             = "AWS"
    source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder_status.account_b]
}

# Golden Rule 6: CloudTrail enabled
resource "aws_config_config_rule" "cloudtrail_enabled" {
  provider = aws.account_b
  name     = "golden-rule-cloudtrail-enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.account_b]
}

# Golden Rule 7: Root has no access keys (alert only — too sensitive to auto-touch)
resource "aws_config_config_rule" "root_no_access_keys" {
  provider = aws.account_b
  name     = "golden-rule-root-no-access-keys"

  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }

  depends_on = [aws_config_configuration_recorder_status.account_b]
}

# Golden Rule 8: RDS not publicly accessible
resource "aws_config_config_rule" "rds_not_public" {
  provider = aws.account_b
  name     = "golden-rule-rds-not-public"

  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
  }

  depends_on = [aws_config_configuration_recorder_status.account_b]
}


# ── EVENTBRIDGE — FORWARD CONFIG DRIFT TO AUDITOR CENTRAL BUS ────────────────
# Config fires NON_COMPLIANT → EventBridge picks it up in Account B
# → forwards to Account A's existing NetworkAuditorCentral bus
# → existing central bus rule routes to drift Lambda

resource "aws_cloudwatch_event_rule" "account_b_drift_forward" {
  provider    = aws.account_b
  name        = "NetworkAuditorForwardDriftEvents"
  description = "Forwards Config NON_COMPLIANT events to Auditor central bus"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      configRuleName = [
        "golden-rule-restricted-ssh",
        "golden-rule-restricted-rdp",
        "golden-rule-s3-no-public-read",
        "golden-rule-s3-no-public-write",
        "golden-rule-mfa-enabled",
        "golden-rule-cloudtrail-enabled",
        "golden-rule-root-no-access-keys",
        "golden-rule-rds-not-public",
      ]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "account_b_drift_to_central" {
  provider  = aws.account_b
  rule      = aws_cloudwatch_event_rule.account_b_drift_forward.name
  arn       = aws_cloudwatch_event_bus.central.arn   # Account A's existing central bus
  role_arn  = aws_iam_role.account_b_eventbridge_role.arn  # Already exists in account_b.tf
}


# ── AUTHORIZE CONFIG AGGREGATION ──────────────────────────────────────────────
# Grants the Auditor account permission to pull Config compliance
# data from Account B into the aggregator defined in main.tf.

resource "aws_config_aggregate_authorization" "to_auditor" {
  provider   = aws.account_b
  account_id = var.auditor_account_id
  region     = var.aws_region
}
