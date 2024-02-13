data "aws_partition" "current" {}
data "aws_region" "current" {}

variable "memory" {
  description = "Memory to allocate to Lambda function"
  type        = string
  default     = 128
}

variable "event_state" {
  description = "Whether Cloudwatch event schedule is enabled or disabled"
  type        = string
  default     = "ENABLED"
}

variable "alarm_notification_arn" {
  description = "Enter the Amazon SNS Notification ARN for alarm notifications, leave blank to disable notifications."
  type        = string
}

variable "alarm_identifier_prefix" {
  description = "Enter the prefix that should be added to the beginning of each alarm created by the solution, (e.g. AutoAlarm-i-00e4f327736cb077f-CPUUtilization-GreaterThanThreshold-80-5m)"
  type        = string
  default     = "AutoAlarm"
}

resource "aws_lambda_function" "lambda_function" {
  function_name    = "CloudWatchAutoAlarms"
  handler          = "cw_auto_alarms.lambda_handler"
  runtime          = "python3.8"
  role             = aws_iam_role.cloud_watch_auto_alarm_lambda_role.arn
  memory_size      = var.memory
  timeout          = 600
  filename         = "cw-lambda-alerts.zip"
  source_code_hash = data.archive_file.lambda-file-zip.output_base64sha256
  environment {
    variables = {
      ALARM_TAG                              = "Create_Auto_Alarms"
      CREATE_DEFAULT_ALARMS                  = true
      CLOUDWATCH_NAMESPACE                   = "CWAgent"
      ALARM_CPU_HIGH_THRESHOLD               = 75
      ALARM_DEFAULT_ANOMALY_THRESHOLD        = 2
      ALARM_CPU_CREDIT_BALANCE_LOW_THRESHOLD = 100
      ALARM_MEMORY_HIGH_THRESHOLD            = 75
      ALARM_DISK_PERCENT_LOW_THRESHOLD       = 20
      ALARM_IDENTIFIER_PREFIX                = var.alarm_identifier_prefix
      CLOUDWATCH_APPEND_DIMENSIONS           = "InstanceId, ImageId, InstanceType"
      ALARM_LAMBDA_ERROR_THRESHOLD           = 0
      ALARM_LAMBDA_THROTTLE_THRESHOLD        = 0
      DEFAULT_ALARM_SNS_TOPIC_ARN            = var.alarm_notification_arn
    }
  }
}

data "archive_file" "lambda-file-zip" {
  type        = "zip"
  source_dir  = "./src"
  output_path = "cw-lambda-alerts.zip"
}

data "aws_iam_policy_document" "lambda-assume-role-policy-document" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      identifiers = ["lambda.amazonaws.com"]
      type        = "Service"
    }
  }
}

data "aws_iam_policy_document" "lambda-policy-document" {
  statement {
    effect = "Allow"
    actions = [
      "cloudwatch:PutMetricData"
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:DescribeLogGroups",
      "logs:PutLogEvents"

    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:*"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:*:log-stream:*"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeImages"
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "cloudwatch:DescribeAlarms",
      "cloudwatch:DeleteAlarms",
      "cloudwatch:PutMetricAlarm"
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:cloudwatch:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:alarm:${var.alarm_identifier_prefix}-*"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "cloudwatch:DescribeAlarms"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "cloud_watch_auto_alarm_lambda_role" {
  path               = "/"
  name               = "cloudwatch-auto-alarm-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda-assume-role-policy-document.json
}

resource "aws_iam_role_policy_attachment" "lambda-policy-attachment" {
  policy_arn = aws_iam_policy.lambda-policy.arn
  role       = aws_iam_role.cloud_watch_auto_alarm_lambda_role.name
}

resource "aws_iam_policy" "lambda-policy" {
  name   = "cloudwatch-auto-alarm-lambda-policy"
  policy = data.aws_iam_policy_document.lambda-policy-document.json
  path   = "/"
}



resource "aws_lambda_permission" "lambda_invoke_permission_cloudwatch_events_ec2" {
  function_name = aws_lambda_function.lambda_function.arn
  action        = "lambda:InvokeFunction"
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cloud_watch_auto_alarm_cloudwatch_event_ec2.arn
}

resource "aws_cloudwatch_event_rule" "cloud_watch_auto_alarm_cloudwatch_event_ec2" {
  name          = "Initiate-CloudWatchAutoAlarmsEC2"
  description   = "Creates CloudWatch alarms on instance start via Lambda CloudWatchAutoAlarms and deletes them on instance termination."
  event_pattern = " { \"source\": [ \"aws.ec2\" ], \"detail-type\": [ \"EC2 Instance State-change Notification\" ], \"detail\": { \"state\": [ \"running\", \"terminated\" ] } }"
  state         = var.event_state
}

resource "aws_cloudwatch_event_rule" "cloud_watch_auto_alarm_cloudwatch_event_lambda" {
  name          = "Initiate-CloudWatchAutoAlarmsLambda"
  description   = "Creates and deletes CloudWatch alarms for lambda functions with the CloudWatchAutoAlarms activation tag"
  event_pattern = " { \"source\": [ \"aws.lambda\" ], \"detail-type\": [ \"AWS API Call via CloudTrail\" ], \"detail\": { \"eventSource\": [ \"lambda.amazonaws.com\" ], \"eventName\": [ \"TagResource20170331v2\", \"DeleteFunction20150331\" ] } } "
  state         = var.event_state
}

resource "aws_cloudwatch_event_rule" "cloud_watch_auto_alarm_cloudwatch_event_rds_create" {
  name          = "Initiate-CloudWatchAutoAlarmsRDSCreate"
  description   = "Creates CloudWatch alarms for RDS instances with CloudWatchAutoAlarms activation tag"
  event_pattern = " { \"detail-type\": [\"AWS API Call via CloudTrail\"], \"detail\": { \"eventSource\": [\"rds.amazonaws.com\"], \"eventName\": [\"AddTagsToResource\"] } } "
  state         = var.event_state
}

resource "aws_cloudwatch_event_rule" "cloud_watch_auto_alarm_cloudwatch_event_rds_delete" {
  name          = "Initiate-CloudWatchAutoAlarmsRDSDelete"
  description   = "Deletes CloudWatch alarms for corresponding RDS instance is deleted"
  event_pattern = " { \"source\": [\"aws.rds\"], \"detail\": { \"EventCategories\": [\"creation\", \"deletion\"] } } "
  state         = var.event_state
}

resource "aws_lambda_permission" "lambda_invoke_permission_cloudwatch_events_lambda" {
  function_name = aws_lambda_function.lambda_function.arn
  action        = "lambda:InvokeFunction"
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cloud_watch_auto_alarm_cloudwatch_event_lambda.arn
}

resource "aws_lambda_permission" "lambda_invoke_permission_cloudwatch_events_rds_create" {
  function_name = aws_lambda_function.lambda_function.arn
  action        = "lambda:InvokeFunction"
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cloud_watch_auto_alarm_cloudwatch_event_rds_create.arn
}

resource "aws_lambda_permission" "lambda_invoke_permission_cloudwatch_events_rds_delete" {
  function_name = aws_lambda_function.lambda_function.arn
  action        = "lambda:InvokeFunction"
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cloud_watch_auto_alarm_cloudwatch_event_rds_delete.arn
}

