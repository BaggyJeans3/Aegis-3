FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask gunicorn

COPY . .

EXPOSE 5000

# [변경] Flask 개발 서버 → gunicorn.
# ⚠ -w(프로세스 수)는 반드시 1: detector 상태(IP/세션별 60초·10분 누적)가 프로세스 메모리에 있어서
#   프로세스를 늘리면 요청이 나뉘어 R-SCAN/R-RATE 등이 임계값에 도달하지 못한다(미탐).
#   동시 처리는 --threads 로 늘린다(상태 접근은 state.STATE_LOCK 으로 보호).
# 롤백이 필요하면: CMD ["python", "-m", "soar.risk_score_engine.app"]
CMD ["gunicorn", "-w", "1", "--threads", "8", "-b", "0.0.0.0:5000", "--access-logfile", "-", "soar.risk_score_engine.app:app"]
