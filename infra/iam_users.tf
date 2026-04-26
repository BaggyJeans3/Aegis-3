# 1. 팀원 계정 생성
resource "aws_iam_user" "team" {
  for_each = toset(var.team_members)
  name     = each.key
  tags     = local.common_tags
}

# 2. 팀원들이 소속될 그룹 생성
resource "aws_iam_group" "baggyjeans_group" {
  name = "${var.name_prefix}-dev-group"
}

# 3. 그룹에 팀원들 추가
resource "aws_iam_user_group_membership" "membership" {
  for_each = toset(var.team_members)
  user     = aws_iam_user.team[each.key].name
  groups   = [aws_iam_group.baggyjeans_group.name] 
}

# 4. 그룹에 권한 부여 
resource "aws_iam_group_policy_attachment" "baggyjeans_pwr_user" {
  group      = aws_iam_group.baggyjeans_group.name 
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}