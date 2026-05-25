FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask

COPY . .

EXPOSE 5000

CMD ["python", "-m", "soar.risk_score_engine.app"]