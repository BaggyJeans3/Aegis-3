resource "aws_security_group" "ec2_sg" {
  name        = "${var.name_prefix}-sg"
  description = "Security group for ${var.name_prefix} EC2 (Cloudflare Only & Tailscale Auth)"
  vpc_id      = var.vpc_id

  revoke_rules_on_delete = true

  # ==========================================
  # [ INGRESS: 인바운드 트래픽 ]
  # SSH(22번 포트) 규칙 완전히 삭제됨!
  # ==========================================

  ingress {
    description = "HTTP strictly from Cloudflare"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.cloudflare_ipv4_cidrs
  }

  ingress {
    description = "HTTPS strictly from Cloudflare"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.cloudflare_ipv4_cidrs
  }

  # ==========================================
  # [ EGRESS: 아웃바운드 트래픽 ]
  # ==========================================

  egress {
    description = "HTTP outbound"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTPS outbound (Also used for Tailscale DERP relays)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS TCP outbound"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS UDP outbound"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # --- Tailscale 동작을 위한 필수 UDP Outbound 추가 ---
  egress {
    description = "Tailscale STUN (UDP hole punching)"
    from_port   = 3478
    to_port     = 3478
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Tailscale P2P Direct Connection"
    from_port   = 41641
    to_port     = 41641
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  dynamic "egress" {
    for_each = length(var.db_allowed_cidrs) == 0 ? [] : local.db_ports
    content {
      description = "DB outbound ${egress.value}"
      from_port   = egress.value
      to_port     = egress.value
      protocol    = "tcp"
      cidr_blocks = var.db_allowed_cidrs
    }
  }

  tags = local.common_tags
}