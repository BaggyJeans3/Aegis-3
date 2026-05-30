# Aegis 포털 백엔드 — PC 로컬 실행 가이드

EC2를 건드리지 않고, 본인 PC에서 FastAPI 백엔드를 돌립니다.

## 구조

```
Vite 프론트(브라우저)
   ↓ fetch http://localhost:8001
FastAPI (PC에서 실행)
   ↓ mongodb://localhost:27017
SSH 터널 ──────────→ EC2 mongo-bridge → MongoDB
```

---

## 0. 폴더 배치

이 폴더(`aegis-portal-backend`)를 PC 아무 곳에나 둡니다.
구조는 아래와 같아야 합니다.

```
aegis-portal-backend/
├── .env            ← 직접 생성 (아래 1번)
├── .env.example
├── requirements.txt
├── Dockerfile      ← 나중에 EC2 배포용. PC 실행에는 안 씀
└── app/
    ├── __init__.py
    ├── main.py
    ├── database.py
    └── seed_data.py
```

---

## 1. .env 파일 만들기

`.env.example` 를 복사해서 `.env` 로 이름을 바꾸고,
`MONGO_PASSWORD` 값만 실제 값으로 채웁니다.

PowerShell:
```powershell
Copy-Item .env.example .env
notepad .env
```

`.env` 내용:
```
MONGO_HOST=localhost
MONGO_PORT=27017
MONGO_USER=aegis_user
MONGO_PASSWORD=<실제_MONGO_PASSWORD_값>
MONGO_DB_NAME=aegis_logs
```

---

## 2. 파이썬 패키지 설치

`aegis-portal-backend` 폴더에서 PowerShell 실행:

```powershell
# 가상환경 생성 (권장)
python -m venv venv
.\venv\Scripts\Activate.ps1

# 패키지 설치
pip install -r requirements.txt
```

> 만약 `Activate.ps1` 실행이 권한 오류로 막히면:
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> ```
> 를 먼저 실행한 뒤 다시 Activate.

---

## 3. 사전 준비 확인 (EC2 쪽)

FastAPI를 켜기 전에 아래 2가지가 살아있어야 합니다.

1. **mongo-bridge 컨테이너** — EC2에서 `sudo docker ps | grep mongo-bridge`
   로 `Up` 확인. 없으면 다시 실행:
   ```bash
   sudo docker run -d --rm --name mongo-bridge --network aegis-3_aegis-net -p 27017:27017 alpine/socat tcp-listen:27017,fork,reuseaddr tcp-connect:aegis-mongodb:27017
   ```

2. **SSH 터널** — PC의 별도 터미널에서 실행하고 그 창을 계속 켜둠:
   ```
   ssh -i <키파일> -L 27017:localhost:27017 ubuntu@<EC2_IP>
   ```

---

## 4. FastAPI 실행

`venv` 가 활성화된 상태에서, `aegis-portal-backend` 폴더에서:

```powershell
uvicorn app.main:app --reload --port 8001
```

성공하면 `Application startup complete` 가 보입니다.
(이때 MongoDB 접속까지 시도하므로, 3번이 안 돼 있으면 여기서 에러가 납니다.)

---

## 5. 동작 확인 & 더미 로그 삽입

브라우저나 새 터미널에서:

```powershell
# 헬스 체크
curl http://localhost:8001/api/health

# 더미 로그 200건 삽입 (최초 1회)
curl -X POST "http://localhost:8001/api/seed?count=200"

# 로그 조회 확인
curl "http://localhost:8001/api/logs?page_size=2"
```

`/api/seed` 를 호출하면 그때 MongoDB에 `aegis_logs.traffic_logs`
컬렉션이 생기면서 더미 데이터가 채워집니다.

API 문서는 브라우저에서 http://localhost:8001/docs 로 확인 가능합니다.

---

## 정리: 매번 테스트할 때 켜는 순서

1. EC2: mongo-bridge `Up` 확인
2. PC 터미널 A: SSH 터널 실행 (창 유지)
3. PC 터미널 B: `venv` 활성화 → `uvicorn app.main:app --reload --port 8001`
4. Vite 프론트: `npm run dev`

끝나면 그냥 각 창을 닫으면 됩니다. EC2에는 영구 변경이 없습니다.
(원하면 EC2에서 `sudo docker stop mongo-bridge` 로 임시 컨테이너 제거)
