output "posture_file" {
  description = "Path the attack and the visual lab read to learn what you deployed."
  value       = local_file.posture.filename
}

output "vpc_id" {
  description = "The composed Chapter 8 VPC every pillar sits in."
  value       = module.foundation.vpc_id
}

output "next_step" {
  description = "What to run once apply finishes."
  value       = "python3 ../attack/end_to_end.py --ticket ../attack/tickets/poisoned.pdf --posture ${local_file.posture.filename}"
}
