# The composed foundation names every resource "${project}-${environment}".
# Modules 4, 5 and 6 never declared this because they never actually composed
# the foundation; now that they do, they need it, and it must match the value
# modules 1-3 use or the pillar deploys under a different name prefix and
# hwz-detect scopes past it.
variable "environment" {
  description = "Environment suffix, e.g. lab. Must match the value used in modules 1-3."
  type        = string
  default     = "lab"
}
