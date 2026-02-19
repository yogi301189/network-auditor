# infra/main.tf
# ==============
# Deploys the self-healing layer:
#   - Lambda function (the detector)
#   - EventBridge rule (the trigger)
#   - IAM Role + Policy (least-privilege permissions)
#
# Deploy with:
#   cd infra/
#   terraform init
#   terraform plan
#   terraform apply

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}


# ── PACKAGE THE LAMBDA ────────────────────────────────────────────────────────
# Terraform zips the handler.py file automatically.
# Every time handler.py changes, Terraform detects it and redeploys.

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/handler.py"
  output_path = "${path.module}/lambda/handler.zip"
}


# ── IAM ROLE FOR LAMBDA ───────────────────────────────────────────────────────
# Lambda needs a role to execute. This role has two policies:
#   1. AWSLambdaBasicExecutionRole — allows Lambda to write logs to CloudWatch
#   2. Our custom policy            — allows reading Security Group details

resource "aws_iam_role" "lambda_role" {
  name        = "NetworkAuditorLambdaRole"
  description = "Role for the real-time Security Group violation detector"

  # Trust policy: only Lambda can assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Attach the AWS managed policy for basic Lambda execution (CloudWatch Logs)
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Our custom read-only policy — Lambda only needs to describe Security Groups
resource "aws_iam_role_policy" "lambda_ec2_read" {
  name = "NetworkAuditorLambdaEC2Read"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSecurityGroupRules",
        "ec2:RevokeSecurityGroupIngress",
      ]
      Resource = "*"
    }]
  })
}


# ── LAMBDA FUNCTION ───────────────────────────────────────────────────────────

resource "aws_lambda_function" "sg_detector" {
  function_name = "NetworkAuditorSGDetector"
  description   = "Detects Security Group violations in real time and alerts Slack"

  # The zipped handler from above
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  # handler = "filename.function_name"
  handler = "handler.lambda_handler"
  runtime = "python3.12"
  timeout = 30    # seconds — plenty of time for an EC2 API call + Slack post

  role = aws_iam_role.lambda_role.arn

  # Inject the Slack webhook URL as an environment variable
  # The function reads it with: os.environ.get("SLACK_WEBHOOK_URL")
  environment {
    variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
    }
  }
}

# CloudWatch Log Group — stores all Lambda execution logs
# Explicit resource means Terraform manages the retention period
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.sg_detector.function_name}"
  retention_in_days = 30
}


# ── EVENTBRIDGE RULE ──────────────────────────────────────────────────────────
# Watches for Security Group inbound rule changes across the entire account.
# Fires within seconds of the API call being made.

resource "aws_cloudwatch_event_rule" "sg_changes" {
  name        = "NetworkAuditorSGChanges"
  description = "Fires when Security Group inbound rules are added or modified"

  # Event pattern: match CloudTrail API calls for SG rule changes
  # AuthorizeSecurityGroupIngress = adding a new inbound rule
  # ModifySecurityGroupRules      = editing an existing inbound rule
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

# Connect the EventBridge rule to the Lambda function
resource "aws_cloudwatch_event_target" "sg_changes_to_lambda" {
  rule = aws_cloudwatch_event_rule.sg_changes.name
  arn  = aws_lambda_function.sg_detector.arn
}

# Give EventBridge permission to invoke the Lambda
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sg_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sg_changes.arn
}


# ── CLOUDWATCH PERMISSIONS FOR LAMBDA ────────────────────────────────────────
# Allow Lambda to publish custom metrics to CloudWatch

resource "aws_iam_role_policy" "lambda_cloudwatch_metrics" {
  name = "NetworkAuditorLambdaCloudWatchMetrics"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["cloudwatch:PutMetricData"]
      Resource = "*"
    }]
  })
}


# ── CLOUDWATCH DASHBOARD ──────────────────────────────────────────────────────

resource "aws_cloudwatch_dashboard" "network_auditor" {
  dashboard_name = "NetworkAuditor"

  dashboard_body = jsonencode({
    widgets = [

      # ── Widget 1: Violations Over Time (top left) ──
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title   = "🔴 Violations Detected Over Time"
          view    = "timeSeries"
          stacked = false
          period  = 86400   # 1 day buckets
          stat    = "Sum"
          metrics = [[
            "NetworkAuditor",
            "ViolationDetected",
            { label = "Violations", color = "#d13212" }
          ]]
          yAxis = { left = { min = 0 } }
        }
      },

      # ── Widget 2: Remediation Success vs Failure (top right) ──
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title   = "✅ Remediation Outcomes"
          view    = "timeSeries"
          stacked = true
          period  = 86400
          stat    = "Sum"
          metrics = [
            ["NetworkAuditor", "RemediationSuccess", { label = "Auto-Fixed",     color = "#1d8102" }],
            ["NetworkAuditor", "RemediationFailed",  { label = "Manual Required", color = "#ff7f0e" }],
          ]
          yAxis = { left = { min = 0 } }
        }
      },

      # ── Widget 3: Total violations (single number — bottom left) ──
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 6
        height = 3
        properties = {
          title   = "Total Violations (30 days)"
          view    = "singleValue"
          period  = 2592000   # 30 days
          stat    = "Sum"
          metrics = [["NetworkAuditor", "ViolationDetected"]]
        }
      },

      # ── Widget 4: Total auto-remediated (single number) ──
      {
        type   = "metric"
        x      = 6
        y      = 6
        width  = 6
        height = 3
        properties = {
          title   = "Auto-Remediated (30 days)"
          view    = "singleValue"
          period  = 2592000
          stat    = "Sum"
          metrics = [["NetworkAuditor", "RemediationSuccess"]]
        }
      },

      # ── Widget 5: Lambda execution logs (bottom right) ──
      {
        type   = "log"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          title   = "📋 Recent Violation Log"
          view    = "table"
          period  = 86400
          query   = "SOURCE '/aws/lambda/NetworkAuditorSGDetector' | fields @timestamp, @message | filter @message like /VIOLATION/ | sort @timestamp desc | limit 20"
          region  = var.aws_region
        }
      },
    ]
  })
}


# ── OUTPUTS ───────────────────────────────────────────────────────────────────

output "lambda_function_name" {
  value       = aws_lambda_function.sg_detector.function_name
  description = "Name of the deployed Lambda function"
}

output "lambda_function_arn" {
  value       = aws_lambda_function.sg_detector.arn
  description = "ARN of the deployed Lambda function"
}

output "eventbridge_rule_name" {
  value       = aws_cloudwatch_event_rule.sg_changes.name
  description = "Name of the EventBridge rule watching for SG changes"
}

output "dashboard_url" {
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.network_auditor.dashboard_name}"
  description = "Direct URL to the CloudWatch dashboard"
}
