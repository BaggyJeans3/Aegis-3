FROM python:3.11-slim

# 작업 디렉토리 설정
WORKDIR /app

# 시스템 패키지 업데이트 및 필요한 빌드 도구 설치 (필요시)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 패키지 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir pymongo

# 애플리케이션 코드 복사
COPY . .

# FastAPI 기본 포트 노출 (docker-compose에서 매핑됨)
EXPOSE 8000