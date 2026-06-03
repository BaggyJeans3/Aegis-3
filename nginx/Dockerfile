FROM golang:1.25-bookworm AS libcoraza-builder

ARG LIBCORAZA_VERSION=v1.4.0

RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends \
    build-essential \
    autoconf \
    automake \
    libtool \
    pkg-config \
    wget \
    ca-certificates \
    git \
    curl \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src

RUN wget -O libcoraza.tar.gz "https://github.com/corazawaf/libcoraza/archive/refs/tags/${LIBCORAZA_VERSION}.tar.gz" \
    && tar -xzf libcoraza.tar.gz \
    && cd "libcoraza-${LIBCORAZA_VERSION#v}" \
    && touch ChangeLog \
    && (./build.sh || true) \
    && ./configure \
    && make \
    && mkdir -p /usr/local/include/coraza /usr/local/lib \
    && cp libcoraza.so libcoraza.a /usr/local/lib/ \
    && cp coraza/coraza.h /usr/local/include/coraza/


FROM nginx:1.25-bookworm AS coraza-nginx-builder

ARG NGINX_VERSION=1.25.5
ARG CORAZA_NGINX_VERSION=v0.11.0

COPY --from=libcoraza-builder /usr/local/include/coraza /usr/local/include/coraza
COPY --from=libcoraza-builder /usr/local/lib/libcoraza.so /usr/local/lib/libcoraza.so
COPY --from=libcoraza-builder /usr/local/lib/libcoraza.a /usr/local/lib/libcoraza.a

RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends \
    build-essential \
    libpcre3-dev \
    zlib1g-dev \
    libssl-dev \
    wget \
    ca-certificates \
    curl \
    git \
    make \
    && rm -rf /var/lib/apt/lists/* \
    && ldconfig

WORKDIR /usr/src

RUN wget -O coraza-nginx.tar.gz "https://github.com/corazawaf/coraza-nginx/archive/refs/tags/${CORAZA_NGINX_VERSION}.tar.gz" \
    && tar -xzf coraza-nginx.tar.gz \
    && curl -fsSL "http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" | tar zxC /usr/src -f - \
    && cd "/usr/src/nginx-${NGINX_VERSION}" \
    && ./configure --with-compat --add-dynamic-module="/usr/src/coraza-nginx-${CORAZA_NGINX_VERSION#v}" \
    && make modules \
    && mkdir -p /usr/lib/nginx/modules \
    && cp objs/ngx_http_coraza_module.so /usr/lib/nginx/modules/


# === [신규] 응답 본문 정규식 치환 모듈 빌드 ===
# ngx_http_substitutions_filter_module (yaoweibin/ngx_http_substitutions_filter_module):
#   기본 sub_filter는 리터럴 문자열만 지원하므로, 정규식 기반 응답 본문 치환을 위해 필요.
#   용도: 개인정보(전화번호/주민번호/카드번호/이메일) 마스킹 미들웨어.
# 공식 release tag가 없어 master HEAD 기준으로 빌드한다. 빌드 재현성 확보가 필요해지면
# SUBS_FILTER_REF 를 특정 commit 해시로 고정하면 된다.
# NOTE: 이 모듈은 Coraza response body 필터와 같은 nginx pass 에 함께 있으면 4KB 초과
# 응답에서 "zero size buf in writer" 충돌을 일으킨다. 이 충돌은 모듈 패치가 아니라
# nginx.conf 의 2-pass 분리(프론트=coraza, 내부=subs)로 회피한다. 따라서 모듈 자체는
# 패치 없이 사용한다.
FROM nginx:1.25-bookworm AS subs-filter-builder

ARG NGINX_VERSION=1.25.5
ARG SUBS_FILTER_REF=master

# 런타임 nginx 1.25 공식 이미지는 PCRE2로 빌드돼 있다. 모듈도 반드시 PCRE2로
# 빌드해야 ngx_regex 래퍼가 pcre2_* / 실제 ngx_regex_exec 함수 호출로 전개되어
# 런타임 nginx 바이너리가 심볼을 제공한다. libpcre3-dev(PCRE1)로 빌드하면
# pcre_fullinfo 등 PCRE1 심볼이 .so에 박혀 dlopen 시 undefined symbol로 죽는다.
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends \
    build-essential \
    libpcre2-dev \
    zlib1g-dev \
    libssl-dev \
    wget \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src

RUN wget -O subs-filter.tar.gz "https://github.com/yaoweibin/ngx_http_substitutions_filter_module/archive/${SUBS_FILTER_REF}.tar.gz" \
    && tar -xzf subs-filter.tar.gz \
    && mv ngx_http_substitutions_filter_module-* /usr/src/subs-filter \
    && curl -fsSL "http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" | tar zxC /usr/src -f - \
    && cd "/usr/src/nginx-${NGINX_VERSION}" \
    && ./configure --with-compat --add-dynamic-module=/usr/src/subs-filter \
    && make modules \
    && mkdir -p /usr/lib/nginx/modules \
    && cp objs/ngx_http_subs_filter_module.so /usr/lib/nginx/modules/


FROM nginx:1.25-bookworm

COPY --from=coraza-nginx-builder /usr/lib/nginx/modules/ngx_http_coraza_module.so /usr/lib/nginx/modules/ngx_http_coraza_module.so
COPY --from=libcoraza-builder /usr/local/lib/libcoraza.so /usr/local/lib/libcoraza.so
# 응답 본문 정규식 치환 모듈 (개인정보 마스킹용)
COPY --from=subs-filter-builder /usr/lib/nginx/modules/ngx_http_subs_filter_module.so /usr/lib/nginx/modules/ngx_http_subs_filter_module.so

# Node.js + npm: 룰 주입 사이드카(Express) 구동용
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/* \
    && ldconfig \
    && mkdir -p /var/log/coraza /etc/nginx/crs /etc/nginx/rules

COPY nginx.conf /etc/nginx/nginx.conf
COPY coraza.conf /etc/nginx/coraza.conf
COPY crs-setup.conf /etc/nginx/crs-setup.conf
COPY crs /etc/nginx/crs
COPY rules /etc/nginx/rules
# Baseline copy used by entrypoint to sync static rules into the
# nginx_dynamic_rules volume on every start (volume preserves dynamic.conf
# but stale static rules would otherwise never refresh).
COPY rules /opt/aegis-rules-baseline

# Sidecar (룰 주입 API)
WORKDIR /opt/sidecar
COPY package.json ./package.json
RUN npm install --omit=dev
COPY sidecar.js ./sidecar.js

# 엔트리포인트: nginx + 사이드카 동시 기동
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 80 4000

CMD ["/usr/local/bin/entrypoint.sh"]