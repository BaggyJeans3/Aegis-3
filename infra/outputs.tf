output "ec2_public_ip" {
  description = "EC2 인스턴스의 고정 공인 IP (Elastic IP)"
  value       = aws_eip.ec2_eip.public_ip
}