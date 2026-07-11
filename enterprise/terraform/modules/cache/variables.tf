variable "name" {
  description = "Name prefix for cache resources."
  type        = string
}

variable "vpc_id" {
  description = "VPC the cache lives in."
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR allowed to reach Redis."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnets for the cache subnet group."
  type        = list(string)
}

variable "node_type" {
  description = "ElastiCache node type. cache.t4g.micro is the cheap default."
  type        = string
  default     = "cache.t4g.micro"
}

variable "num_cache_clusters" {
  description = "Number of nodes (>1 enables automatic failover / HA)."
  type        = number
  default     = 1
}

variable "engine_version" {
  description = "Redis engine version."
  type        = string
  default     = "7.1"
}
