FROM nginx:1.25.0-alpine

# 필요한 기본 폴더만 생성
RUN mkdir -p /usr/local/nginx/modules/

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]