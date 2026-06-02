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

# 5. 본인 액세스 키 관리(Self-service) 정책
#    PowerUserAccess는 IAM 권한을 제외하므로, 팀원이 자기 액세스 키를
#    생성/삭제/조회/교체할 수 있도록 별도 정책을 만들어 그룹에 부여한다.
#    Resource를 ${aws:username} 으로 제한해 "본인 키만" 다루게 한다.
data "aws_iam_policy_document" "manage_own_access_keys" {
  statement {
    sid    = "AllowManageOwnAccessKeys"
    effect = "Allow"
    actions = [
      "iam:CreateAccessKey",
      "iam:DeleteAccessKey",
      "iam:ListAccessKeys",
      "iam:UpdateAccessKey",
      "iam:GetUser",
    ]
    resources = ["arn:aws:iam::*:user/$${aws:username}"]
  }
}

resource "aws_iam_policy" "manage_own_access_keys" {
  name        = "${var.name_prefix}-ManageOwnAccessKeys"
  description = "Allow IAM users to manage (rotate) their own access keys only"
  policy      = data.aws_iam_policy_document.manage_own_access_keys.json
  tags        = local.common_tags
}

resource "aws_iam_group_policy_attachment" "manage_own_access_keys" {
  group      = aws_iam_group.baggyjeans_group.name
  policy_arn = aws_iam_policy.manage_own_access_keys.arn
}