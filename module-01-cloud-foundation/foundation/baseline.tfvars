###############################################################################
# baseline.tfvars  ::  THE WEAK STACK  (insecure ON PURPOSE)
#
# Apply with:  terraform apply -var-file=baseline.tfvars
#
# Every flag below is set to the value a rushed contractor or a first-week
# engineer would leave it at. Nothing here is broken. It DEPLOYS CLEAN. It is
# just wide open. That is the difference between "weak by policy" and "broken
# by omission". You will scan this, understand every hole, then harden it.
###############################################################################

project     = "hwz"
environment = "lab"
region      = "us-east-1"

# --- everything below is the weak setting ---
ssh_ingress_cidr               = "0.0.0.0/0" # the whole internet
vpc_flow_logs                  = false       # no network visibility
s3_block_public_access         = false       # bucket can be made public
s3_default_encryption          = false       # objects stored in the clear
s3_enforce_tls                 = false       # plaintext requests allowed
s3_versioning                  = false       # no recovery from overwrite/delete
kms_strict_key_policy          = false       # broad key policy
kms_allow_cloudtrail           = false       # (trail is not using KMS yet)
iam_deny_destructive           = false       # role can delete anything
cloudtrail_multi_region        = false       # only one region recorded
cloudtrail_log_file_validation = false       # logs can be tampered undetected
cloudtrail_data_events         = false       # object read/write not recorded
cloudtrail_use_kms             = false       # trail logs unencrypted
iam_scope_workload = false
