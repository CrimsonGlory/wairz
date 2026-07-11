variable "name" {
  description = "Name prefix for storage resources."
  type        = string
}

variable "vpc_id" {
  description = "VPC the EFS mount targets live in."
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR allowed to reach EFS over NFS."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnets to place EFS mount targets in (one per AZ)."
  type        = list(string)
}

variable "efs_throughput_mode" {
  description = "EFS throughput mode: bursting (free, default) or elastic (pay-per-use, better for heavy Ghidra project I/O bursts)."
  type        = string
  default     = "bursting"
}

variable "posix_uid" {
  description = "POSIX uid the access points present (the backend container's 'wairz' user)."
  type        = number
  default     = 1000
}

variable "posix_gid" {
  description = "POSIX gid the access points present."
  type        = number
  default     = 1000
}
