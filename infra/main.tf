provider "aws" {
  region = var.aws_region
}

# Ubuntu 24.04 LTS (Noble) 최신 AMI 가져오기
data "aws_ssm_parameter" "ubuntu_2404_amd64" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

locals {
  common_tags = merge(
    {
      Name = var.name_prefix
    },
    var.tags
  )

  db_ports = [5432, 3306, 27017, 6379]
}

resource "aws_instance" "ec2" {
  ami                         = data.aws_ssm_parameter.ubuntu_2404_amd64.value
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.ec2_sg.id]
  associate_public_ip_address = var.associate_public_ip_address
  key_name                    = var.key_name

  # IAM 인스턴스 프로파일 연결 추가
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  # Tailscale 자동 설치 스크립트 주입
  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    tailscale_auth_key = var.tailscale_auth_key
  })

  tags = local.common_tags
}

# 탄력적 IP (Elastic IP) 생성 및 EC2 연결
resource "aws_eip" "ec2_eip" {
  instance = aws_instance.ec2.id
  domain   = "vpc"

  tags = merge(
    local.common_tags,
    {
      Name = "${var.name_prefix}-eip"
    }
  )
}