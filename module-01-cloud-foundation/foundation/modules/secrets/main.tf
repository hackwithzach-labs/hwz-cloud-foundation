###############################################################################
# modules/secrets
# A Secrets Manager secret your pillars read credentials from. That is ALL this
# module does. There is deliberately NO rotation Lambda here.
#
# The old course referenced aws_lambda_function.rotator that was never defined,
# so the whole plan failed. Rotation is a real topic, but it is an APPLICATION
# concern taught at the pillar level with a Lambda you actually build, not a
# dangling reference in the foundation. Foundation stays clean and deployable.
###############################################################################

resource "aws_secretsmanager_secret" "this" {
  name        = "${var.name_prefix}-app-secret"
  description = "Placeholder application credentials for the pillar builds"
  kms_key_id  = var.kms_key_arn != "" ? var.kms_key_arn : null

  # Lab convenience, mirrors force_destroy on the buckets. Secrets Manager
  # normally SCHEDULES a delete with a 7-30 day recovery window and RESERVES the
  # name for that whole window -- so a teardown-then-redeploy fails with "a
  # secret with this name is already scheduled for deletion". Zero means purge
  # on destroy so the deploy -> destroy -> redeploy loop this course runs stays
  # clean. In production you WANT a recovery window; here you want a repeatable lab.
  recovery_window_in_days = 0
}

# Best practice: never hardcode a secret value, not even a placeholder. We
# generate a random password at apply time. It lives in state (which .gitignore
# blocks) and in Secrets Manager, never in the source you commit.
resource "random_password" "app" {
  length           = 24
  special          = true
  override_special = "!#$%*-_=+"
}

resource "aws_secretsmanager_secret_version" "this" {
  secret_id = aws_secretsmanager_secret.this.id
  secret_string = jsonencode({
    username = "app"
    password = random_password.app.result
  })
}
