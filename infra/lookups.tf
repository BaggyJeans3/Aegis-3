# 계정마다 달라지는 값은 tfvars 에 적지 않아도 되도록 자동 조회/생성한다.
# tfvars 에 값을 직접 주면 그 값이 우선한다.

# ------------------------------------------------------------
# VPC / 서브넷: 지정 안 하면 해당 리전(기본 서울)의 기본 VPC 와
# var.availability_zone(기본 ap-northeast-2a)의 기본 서브넷 사용
# ------------------------------------------------------------
data "aws_vpc" "default" {
  count   = var.vpc_id == null ? 1 : 0
  default = true
}

data "aws_subnets" "default" {
  count = var.subnet_id == null ? 1 : 0

  filter {
    name   = "vpc-id"
    values = [local.vpc_id]
  }

  filter {
    name   = "default-for-az"
    values = ["true"]
  }

  filter {
    name   = "availability-zone"
    values = [var.availability_zone]
  }
}

# ------------------------------------------------------------
# Cloudflare IPv4 대역: 지정 안 하면 Cloudflare 공식 목록을 받아온다
# ------------------------------------------------------------
data "http" "cloudflare_ipv4" {
  count = var.cloudflare_ipv4_cidrs == null ? 1 : 0
  url   = "https://www.cloudflare.com/ips-v4"
}

# ------------------------------------------------------------
# SSH 키페어: key_name 을 지정 안 하면 새로 생성.
# 개인키는 `terraform output -raw ssh_private_key` 로 꺼내 GitHub 시크릿 EC2_SSH_KEY 에 등록.
# (개인키가 tfstate 에 저장되므로 tfstate 는 절대 커밋하지 말 것 — .gitignore 처리됨)
# ------------------------------------------------------------
resource "tls_private_key" "ssh" {
  count     = var.key_name == null ? 1 : 0
  algorithm = "ED25519"
}

resource "aws_key_pair" "generated" {
  count      = var.key_name == null ? 1 : 0
  key_name   = "${var.name_prefix}-key"
  public_key = tls_private_key.ssh[0].public_key_openssh
  tags       = local.common_tags
}

locals {
  vpc_id    = var.vpc_id != null ? var.vpc_id : data.aws_vpc.default[0].id
  subnet_id = var.subnet_id != null ? var.subnet_id : one(data.aws_subnets.default[0].ids)

  cloudflare_ipv4_cidrs = var.cloudflare_ipv4_cidrs != null ? var.cloudflare_ipv4_cidrs : [
    for cidr in split("\n", trimspace(data.http.cloudflare_ipv4[0].response_body)) : trimspace(cidr)
  ]

  key_name = var.key_name != null ? var.key_name : aws_key_pair.generated[0].key_name
}
