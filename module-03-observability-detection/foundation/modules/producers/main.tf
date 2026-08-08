###############################################################################
# modules/producers :: main.tf
#
# WHO WRITES THE LOG.
#
# Chapter 10 spends its time on the second half of the chain -- filter, alarm,
# topic, human. This module builds the first half, and it builds it three times
# because AWS answers "how does output become a log event" three different ways.
# Students need all three, because the failure mode is different in each:
#
#   LAMBDA     the service captures stdout automatically, into /aws/lambda/<fn>.
#              Nothing to install. The failure is that you never DECLARED the
#              group, so AWS made one for you with retention "Never expire" and
#              no encryption, and your filters are on a different group entirely.
#
#   EC2        nothing is automatic. A file on a disk is not a log event. You
#              install the CloudWatch agent, you give the instance an IAM role,
#              and you write an agent config that says which file goes to which
#              group. Miss any of the three and the evidence dies with the box.
#
#   CONTAINER  the task definition's logConfiguration decides. With the awslogs
#              driver, stdout goes to CloudWatch. Without it, stdout goes to the
#              container runtime and is gone when the task stops -- and a task
#              with no log driver is still a perfectly healthy task, so nothing
#              anywhere turns red.
#
# All three emit the SAME JSON audit line, so the same two metric filters count
# all three. That is the lesson underneath the lesson: detection is written
# against a log CONTRACT, not against a compute type.
###############################################################################

locals {
  on       = var.log_delivery_enabled ? 1 : 0
  lam      = var.lambda_producer ? 1 : 0
  ec2      = var.ec2_producer ? 1 : 0
  ctr      = var.container_producer ? 1 : 0

  # A declared group is only encrypted/retained in the hardened profile. In the
  # weak profile we do not declare it at all, which is the actual default most
  # accounts live with.
  lam_on = var.lambda_producer && var.log_delivery_enabled ? 1 : 0
  ec2_on = var.ec2_producer && var.log_delivery_enabled ? 1 : 0
  ctr_on = var.container_producer && var.log_delivery_enabled ? 1 : 0

  lambda_name        = "${var.name_prefix}-emitter"
  lambda_log_group   = "/aws/lambda/${var.name_prefix}-emitter"
  ecs_log_group      = "/${var.name_prefix}/ecs"
}

# ===========================================================================
# PRODUCER 1 :: LAMBDA  -- the service writes the log for you
# ===========================================================================

data "archive_file" "emitter" {
  count       = local.lam
  type        = "zip"
  source_dir  = "${path.module}/lambda_src"
  output_path = "${path.module}/.build/emitter.zip"
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  count              = local.lam
  name               = "${var.name_prefix}-emitter-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = { Project = var.project }
}

# The three permissions that turn stdout into a log event. Scoped to this
# function's own group -- a Lambda that can write to every log group in the
# account is a Lambda that can also overwrite your evidence.
data "aws_iam_policy_document" "lambda_logs" {
  statement {
    actions = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [
      "arn:aws:logs:${var.region}:*:log-group:${local.lambda_log_group}",
      "arn:aws:logs:${var.region}:*:log-group:${local.lambda_log_group}:*",
    ]
  }
}

resource "aws_iam_role_policy" "lambda_logs" {
  count  = local.lam
  name   = "${var.name_prefix}-emitter-logs"
  role   = aws_iam_role.lambda[0].id
  policy = data.aws_iam_policy_document.lambda_logs.json
}

# HARDENED ONLY. Declaring the group is the whole lesson: same logs, but now
# retention and encryption are decisions you made instead of defaults you
# inherited. In the weak profile this resource does not exist, Lambda creates
# the group itself on first invoke, and it never expires.
resource "aws_cloudwatch_log_group" "lambda" {
  count             = local.lam_on
  name              = local.lambda_log_group
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = { Project = var.project, Producer = "lambda" }
}

resource "aws_lambda_function" "emitter" {
  count            = local.lam
  function_name    = local.lambda_name
  role             = aws_iam_role.lambda[0].arn
  handler          = "index.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.emitter[0].output_path
  source_code_hash = data.archive_file.emitter[0].output_base64sha256
  timeout          = 30
  tags             = { Project = var.project, Producer = "lambda" }

  environment {
    variables = { HWZ_BURST = "all" }
  }

  # Without this the first invocation races the log group into existence and
  # you get the service default even in the hardened profile.
  depends_on = [aws_cloudwatch_log_group.lambda]
}

# ===========================================================================
# PRODUCER 2 :: EC2  -- nothing is automatic
# ===========================================================================

data "aws_ami" "al2023" {
  count       = local.ec2
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ec2" {
  count              = local.ec2
  name               = "${var.name_prefix}-producer-ec2-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = { Project = var.project }
}

resource "aws_iam_instance_profile" "ec2" {
  count = local.ec2
  name  = "${var.name_prefix}-producer-ec2-profile"
  role  = aws_iam_role.ec2[0].name
}

# HARDENED ONLY. This is the permission half of the EC2 answer. In the weak
# profile the agent is not installed AND the role cannot write, so students see
# both halves fail together the way they do in a real neglected account.
data "aws_iam_policy_document" "ec2_logs" {
  statement {
    actions = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = [
      "arn:aws:logs:${var.region}:*:log-group:${var.app_log_group_name}",
      "arn:aws:logs:${var.region}:*:log-group:${var.app_log_group_name}:*",
    ]
  }
}

resource "aws_iam_role_policy" "ec2_logs" {
  count  = local.ec2_on
  name   = "${var.name_prefix}-producer-ec2-logs"
  role   = aws_iam_role.ec2[0].id
  policy = data.aws_iam_policy_document.ec2_logs.json
}

# Egress only. Nothing needs to reach this box; it needs to reach CloudWatch.
resource "aws_security_group" "ec2" {
  count       = local.ec2
  name        = "${var.name_prefix}-producer-ec2-sg"
  description = "Log producer instance: no inbound, HTTPS egress to AWS APIs only."
  vpc_id      = var.vpc_id

  egress {
    description = "HTTPS to AWS service endpoints (CloudWatch Logs)."
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Project = var.project, Producer = "ec2" }
}

resource "aws_instance" "producer" {
  count                       = local.ec2
  ami                         = data.aws_ami.al2023[0].id
  instance_type               = var.instance_type
  subnet_id                   = var.public_subnet_ids[0]
  vpc_security_group_ids      = [aws_security_group.ec2[0].id]
  iam_instance_profile        = aws_iam_instance_profile.ec2[0].name
  associate_public_ip_address = true

  # IMDSv2 required. An instance that hands out role credentials to anything
  # that can make an unauthenticated GET is a credential vending machine.
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted   = true
    volume_size = 8
  }

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    log_group    = var.app_log_group_name
    ship_logs    = var.log_delivery_enabled
    project      = var.project
  })

  tags = { Name = "${var.name_prefix}-producer", Project = var.project, Producer = "ec2" }
}

# ===========================================================================
# PRODUCER 3 :: CONTAINER  -- the log driver decides
# ===========================================================================

resource "aws_ecs_cluster" "this" {
  count = local.ctr
  name  = "${var.name_prefix}-producers"
  tags  = { Project = var.project }
}

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_exec" {
  count              = local.ctr
  name               = "${var.name_prefix}-producer-ecs-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
  tags               = { Project = var.project }
}

# The execution role is what the ECS AGENT uses to pull the image and to open
# the log stream -- not what your code uses. Confusing the execution role with
# the task role is the most common Fargate mistake there is.
resource "aws_iam_role_policy_attachment" "ecs_exec" {
  count      = local.ctr
  role       = aws_iam_role.ecs_exec[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_cloudwatch_log_group" "ecs" {
  count             = local.ctr_on
  name              = local.ecs_log_group
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = { Project = var.project, Producer = "container" }
}

resource "aws_ecs_task_definition" "producer" {
  count                    = local.ctr
  family                   = "${var.name_prefix}-producer"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_exec[0].arn
  tags                     = { Project = var.project, Producer = "container" }

  container_definitions = jsonencode([
    merge(
      {
        name      = "emitter"
        image     = "public.ecr.aws/docker/library/python:3.12-slim"
        essential = true
        command = [
          "python", "-c",
          join("", [
            "import json,uuid\n",
            "def l(s,d,p):\n",
            "    return {'audit':True,'producer':'container','request_id':str(uuid.uuid4()),",
            "'route':'/v1/complete','principal':p,'status':s,'detail':d}\n",
            "ev=[l(200,'ok','user_carol') for _ in range(8)]\n",
            "ev+=[l(403 if i%3==2 else 401,'Invalid token','attacker_mallory') for i in range(6)]\n",
            "ev+=[l(429,'Rate cap exceeded','attacker_mallory') for _ in range(2)]\n",
            "[print(json.dumps(e),flush=True) for e in ev]\n",
          ])
        ]
      },
      # THE ENTIRE DIFFERENCE. With this block, stdout becomes CloudWatch log
      # events. Without it, the task runs, exits 0, reports healthy, and its
      # output is gone. Nothing anywhere turns red.
      var.log_delivery_enabled ? {
        logConfiguration = {
          logDriver = "awslogs"
          options = {
            "awslogs-group"         = local.ecs_log_group
            "awslogs-region"        = var.region
            "awslogs-stream-prefix" = "emitter"
          }
        }
      } : {}
    )
  ])

  depends_on = [aws_cloudwatch_log_group.ecs]
}
