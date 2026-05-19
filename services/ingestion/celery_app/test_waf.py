# test_waf.py
from tasks import process_security_log

print("🚀 Coraza WAF 테스트 페이로드 전송 중...")

# 1. SQL Injection 테스트
print("- SQLi 페이로드 전송")
process_security_log.delay(log_data="1' OR '1'='1")

# 2. XSS 테스트
print("- XSS 페이로드 전송")
process_security_log.delay(log_data="<script>alert('hacked')</script>")

print("✅ 전송 완료! Celery Worker 터미널 로그를 확인하세요.")