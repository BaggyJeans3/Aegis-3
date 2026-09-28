output "ec2_public_ip" {
  description = "EC2 인스턴스의 고정 공인 IP (Elastic IP)"
  value       = aws_eip.ec2_eip.public_ip
}
output "ssh_private_key" {
  description = "자동 생성된 SSH 개인키 (GitHub 시크릿 EC2_SSH_KEY 에 등록). key_name 을 직접 지정했으면 null"
  value       = var.key_name == null ? tls_private_key.ssh[0].private_key_openssh : null
  sensitive   = true
}
