variable "aws_region" {
  type    = string
  default = "ap-northeast-2"
}

variable "name_prefix" {
  type    = string
  default = "aegis-3"
}

variable "vpc_id" {
  description = "null이면 기본 VPC 자동 사용"
  type        = string
  default     = null
}

variable "subnet_id" {
  description = "null이면 기본 VPC 의 기본 서브넷 자동 사용"
  type        = string
  default     = null
}

variable "availability_zone" {
  description = "subnet_id 를 지정하지 않았을 때 기본 서브넷을 고를 가용영역"
  type        = string
  default     = "ap-northeast-2a"
}

variable "instance_type" {
  type    = string
  default = "t3.small"
}

variable "associate_public_ip_address" {
  type    = bool
  default = true
}

variable "cloudflare_ipv4_cidrs" {
  description = "null이면 https://www.cloudflare.com/ips-v4 에서 자동 조회"
  type        = list(string)
  default     = null
}

variable "db_allowed_cidrs" {
  type    = list(string)
  default = []
}

variable "key_name" {
  description = "null이면 SSH 키페어를 새로 생성"
  type        = string
  default     = null
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