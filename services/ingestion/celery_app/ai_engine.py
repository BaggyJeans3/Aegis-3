from google import genai
from google.genai import types
import re
import json
import os

def _get_client():
    """
    매 호출마다 새 Client 를 생성한다.
    Celery prefork pool 의 child worker 에서 module-level 캐시된 grpc client 를 재사용하면
    fork-after-init 이슈로 첫 RPC 호출이 silently 실패할 수 있어, 캐싱하지 않는다.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY 환경 변수가 설정되어 있지 않습니다.")
    return genai.Client(api_key=api_key)


def generate_waf_rule_with_feedback(attack_log: dict, max_retries: int = 3) -> dict:
    """
    AI를 호출하여 공격 로그를 분석하고 WAF 룰(정규식)을 생성합니다.
    문법 오류 시 피드백 루프를 통해 재시도합니다.
    """
    client = _get_client()
    chat = client.chats.create(
        model="gemini-2.5-flash",
        config=types.GenerateContentConfig(response_mime_type="application/json"),
    )

    # 초기 프롬프트
    prompt = f"""
    당신은 웹 보안(WAF) 전문가입니다. 다음 해킹 공격 로그를 분석하고,
    이를 차단할 수 있는 PCRE 정규식(Regex)과 Coraza WAF 룰을 생성하세요.

    [공격 로그]
    {json.dumps(attack_log, indent=2, ensure_ascii=False)}

    [출력 JSON 포맷]
    {{
        "rule_name": "SQL_Injection_Block",
        "description": "분석 결과 요약",
        "regex": "정규식 패턴",
        "confidence_score": 90
    }}
    """

    for attempt in range(max_retries):
        try:
            print(f"--- [시도 {attempt + 1}/{max_retries}] AI 룰 생성 중 ---")
            response = chat.send_message(prompt)
            result = json.loads(response.text)

            # 1. JSON 구조 검증 (필요한 키가 다 있는지)
            if "regex" not in result:
                raise ValueError("JSON 응답에 'regex' 키가 없습니다.")

            generated_regex = result["regex"]

            # 2. 정규식 문법 사전 테스트 (Try-Except의 핵심)
            # re.compile을 통해 정규식 문법이 유효한지 파이썬 내부에서 검사합니다.
            re.compile(generated_regex)

            print("✅ 정규식 문법 검증 성공!")
            return result  # 성공 시 최종 결과 반환

        except json.JSONDecodeError as e:
            # JSON 파싱 에러 발생 시 피드백
            error_msg = f"JSON 파싱 에러가 발생했습니다: {str(e)}. 반드시 올바른 JSON 형식으로만 응답하세요."
            prompt = error_msg

        except re.error as e:
            # 정규식 문법 에러 발생 시 피드백
            error_msg = f"당신이 생성한 정규식 '{generated_regex}'에 문법 오류가 있습니다: {str(e)}. 이 오류를 수정하여 다시 정규식을 작성하세요."
            print(f"⚠️ 정규식 오류 발생. 피드백 전송: {error_msg}")
            prompt = error_msg

        except Exception as e:
            error_msg = f"알 수 없는 에러: {str(e)}. 다시 시도하세요."
            prompt = error_msg

    # 최대 재시도 횟수를 초과한 경우
    print("❌ 최대 재시도 횟수 초과. AI 룰 생성 실패.")
    return None


# --- 테스트 실행 코드 ---
if __name__ == "__main__":
    # 테스트용 가짜 공격 로그 (Risk Score 85점 상황 가정)
    sample_log = {
        "ip": "192.168.1.100",
        "endpoint": "/api/users?id=1' OR '1'='1",
        "method": "GET",
        "user_agent": "sqlmap/1.5",
        "risk_score": 85,
    }

    final_rule = generate_waf_rule_with_feedback(sample_log)
    if final_rule:
        print("\n[최종 적용 가능한 WAF 룰]")
        print(json.dumps(final_rule, indent=2, ensure_ascii=False))