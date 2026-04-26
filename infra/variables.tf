variable "aws_region" {
  type    = string
  default = "ap-northeast-2"
}

variable "name_prefix" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "associate_public_ip_address" {
  type    = bool
  default = true
}

variable "cloudflare_ipv4_cidrs" {
  type = list(string)
}

variable "db_allowed_cidrs" {
  type    = list(string)
  default = []
}

variable "key_name" {
  type    = string
  default = null
}

variable "tailscale_auth_key" {
  type      = string
  sensitive = true
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "team_members" {
  description = "IAM 사용자로 추가할 팀원 목록"
  type        = list(string)
  default     = []
}