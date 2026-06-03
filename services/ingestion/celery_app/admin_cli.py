#!/usr/bin/env python
"""
[Aegis-3 SOAR] 운영자 CLI 도구

사용법:
    docker exec aegis-soar-worker python -m admin_cli unblock <IP>
    docker exec aegis-soar-worker python -m admin_cli list_suspects
    docker exec aegis-soar-worker python -m admin_cli stats

unblock 명령은 Redis blacklist에서 IP를 제거하고,
오탐지 의심 카운터를 자동으로 증가시킨다 (record_false_positive 호출).
"""

import sys
from celery_app import redis_client
from tasks import record_false_positive, get_suspect_fp_ips


def unblock(ip: str) -> None:
    """blacklist에서 IP 해제 + 오탐지 카운터 자동 증가."""
    if not ip:
        print("❌ IP 인자가 필요합니다.")
        sys.exit(1)

    blacklist_key = f"aegis:blacklist:{ip}"

    # 1. Blacklist 존재 여부 확인
    exists = redis_client.exists(blacklist_key)
    if not exists:
        print(f"ℹ️ IP {ip}은(는) blacklist에 없습니다.")
        return

    # 2. Blacklist에서 제거
    deleted = redis_client.delete(blacklist_key)
    print(f"✅ Blacklist 해제: {blacklist_key} (삭제: {deleted})")

    # 3. 오탐지 의심 카운터 자동 증가
    result = record_false_positive(ip)
    if result.get("ok"):
        print(f"📊 오탐지 카운터: {result['fp_count']}/{result['threshold']}")
        if result.get("is_suspect"):
            print(f"⚠️  IP {ip} 의심 IP 목록에 자동 등록됨")
    else:
        print(f"⚠️ 카운터 기록 실패: {result.get('reason')}")


def list_suspects() -> None:
    """오탐지 의심 IP 목록 조회."""
    suspects = get_suspect_fp_ips()
    if not suspects:
        print("ℹ️ 의심 IP가 없습니다.")
        return

    print(f"⚠️  오탐지 의심 IP 목록 ({len(suspects)}개):")
    for ip in suspects:
        fp_count = redis_client.get(f"aegis:false_positive:{ip}") or "0"
        print(f"  - {ip} (해제 횟수: {fp_count})")


def stats() -> None:
    """오탐지·차단 통계 조회."""
    keys_to_show = [
        ("aegis:stats:proxy_blocked", "Proxy 1차 차단 횟수"),
        ("aegis:stats:llm_skipped", "LLM 호출 skip 횟수 (blacklist)"),
        ("aegis:stats:cluster_skipped", "LLM 호출 skip 횟수 (cluster)"),
        ("aegis:stats:false_positive_total", "오탐지 의심 누적"),
    ]
    print("📈 Aegis-3 SOAR 통계:")
    for key, label in keys_to_show:
        value = redis_client.get(key) or "0"
        print(f"  - {label}: {value}")


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "unblock":
        if len(sys.argv) < 3:
            print("Usage: python -m admin_cli unblock <IP>")
            sys.exit(1)
        unblock(sys.argv[2])

    elif cmd == "list_suspects":
        list_suspects()

    elif cmd == "stats":
        stats()

    else:
        print(f"❌ 알 수 없는 명령: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
