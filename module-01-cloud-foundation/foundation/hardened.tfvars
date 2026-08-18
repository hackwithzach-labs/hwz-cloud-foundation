###############################################################################
# hardened.tfvars  ::  THE HARDENED STACK
#
# Apply with:  terraform apply -var-file=hardened.tfvars
#
# Same code. Same modules. Every flag flipped to its strong value. Run a plan
# against the baseline state and read the diff: that diff IS the security
# lesson. Then apply, re-scan, and watch the findings drop to zero.
###############################################################################

project     = "hwz"
environment = "lab"
region      = "us-east-1"

# Lock the endpoint SG to the VPC itself. Nothing from the open internet.
ssh_ingress_cidr               = "10.20.0.0/16"
vpc_flow_logs                  = true
s3_block_public_access         = true
s3_default_encryption          = true
s3_enforce_tls                 = true
s3_versioning                  = true
kms_strict_key_policy          = true
kms_allow_cloudtrail           = true
iam_deny_destructive           = true
cloudtrail_multi_region        = true
cloudtrail_log_file_validation = true
cloudtrail_data_events         = true
cloudtrail_use_kms             = true
iam_scope_workload = true
