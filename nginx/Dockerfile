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


FROM nginx:1.25-bookworm

COPY --from=coraza-nginx-builder /usr/lib/nginx/modules/ngx_http_coraza_module.so /usr/lib/nginx/modules/ngx_http_coraza_module.so
COPY --from=libcoraza-builder /usr/local/lib/libcoraza.so /usr/local/lib/libcoraza.so

RUN ldconfig \
    && mkdir -p /var/log/coraza /etc/nginx/crs /etc/nginx/rules

COPY nginx.conf /etc/nginx/nginx.conf
COPY coraza.conf /etc/nginx/coraza.conf
COPY crs-setup.conf /etc/nginx/crs-setup.conf
COPY crs /etc/nginx/crs
COPY rules /etc/nginx/rules

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
