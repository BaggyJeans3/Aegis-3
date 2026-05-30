FROM python:3.11-slim

WORKDIR /code

# asyncpg 런타임 의존성: libpq5 (psycopg/asyncpg가 동적 링크하는 PostgreSQL 클라이언트 라이브러리)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./app ./app

EXPOSE 8001

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
