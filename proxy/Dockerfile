FROM node:20-alpine
WORKDIR /app

# 캐시 효율을 위해 package 파일들만 먼저 복사
COPY package.json package-lock.json ./

# npm ci 사용 (package-lock.json 기반으로 정확하게 설치)
RUN npm ci 

COPY . .
EXPOSE 3000
CMD ["node", "app.js"]