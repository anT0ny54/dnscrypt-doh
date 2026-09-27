# syntax=docker/dockerfile:1.7

FROM alpine:3.24.1 AS build
ARG TARGETARCH
ARG GO_VERSION=1.23.2
ARG DNSCRYPT_VERSION=2.1.5

RUN apk add --no-cache ca-certificates wget tar

WORKDIR /build

# Install exactly Go 1.23.2; Alpine 3.24 itself ships a newer Go toolchain,
# so the build stage pins a reproducible compiler explicitly.
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) GO_ARCH=amd64; GO_SHA=542d3c1705f1c6a1c5a80d5dc62e2e45171af291e755d591c5e6531ef63b454e ;; \
      arm64) GO_ARCH=arm64; GO_SHA=f626cdd92fc21a88b31c1251f419c17782933a42903db87a174ce74eeecc66a9 ;; \
      *) echo "Unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz; \
    echo "${GO_SHA}  /tmp/go.tar.gz" | sha256sum -c -; \
    tar -C /usr/local -xzf /tmp/go.tar.gz; \
    rm /tmp/go.tar.gz
ENV PATH=/usr/local/go/bin:$PATH
ENV CGO_ENABLED=0

# Pin dnscrypt-proxy 2.1.5 and build a small static binary.
RUN set -eux; \
    wget -q "https://github.com/DNSCrypt/dnscrypt-proxy/archive/refs/tags/${DNSCRYPT_VERSION}.tar.gz" -O /tmp/dnscrypt.tar.gz; \
    mkdir -p /build/dnscrypt; \
    tar -xzf /tmp/dnscrypt.tar.gz -C /build/dnscrypt --strip-components=1; \
    rm /tmp/dnscrypt.tar.gz; \
    cd /build/dnscrypt; \
    go build -mod=vendor -trimpath -ldflags='-s -w' -o /out/dnscrypt-proxy ./dnscrypt-proxy; \
    /out/dnscrypt-proxy -version; \
    /out/dnscrypt-proxy -config /dev/null -version >/dev/null

COPY main.go main_test.go go.mod /build/gateway/
RUN set -eux; \
    cd /build/gateway; \
    go test ./...; \
    go vet ./...; \
    go build -trimpath -ldflags='-s -w' -o /out/doh-gateway .; \
    /out/doh-gateway >/tmp/gateway-check.log 2>&1 & pid=$!; \
    sleep 1; \
    kill "$pid" 2>/dev/null || true; \
    wait "$pid" 2>/dev/null || true

FROM alpine:3.24.1 AS runtime

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S doh && adduser -S -D -H -G doh doh

COPY --from=build /out/dnscrypt-proxy /usr/local/bin/dnscrypt-proxy
COPY --from=build /out/doh-gateway /usr/local/bin/doh-gateway
# dnscrypt-proxy's local DoH server uses the bundled localhost TLS certificate.
COPY --from=build /build/dnscrypt/localhost.pem /etc/localhost.pem
COPY dnscrypt-proxy.toml /etc/dnscrypt-proxy.toml
COPY entrypoint.sh /entrypoint.sh

RUN chmod 0755 /usr/local/bin/dnscrypt-proxy /usr/local/bin/doh-gateway /entrypoint.sh && \
    chmod 0600 /etc/localhost.pem && \
    chown doh:doh /usr/local/bin/dnscrypt-proxy /usr/local/bin/doh-gateway /etc/localhost.pem /etc/dnscrypt-proxy.toml /entrypoint.sh

ENV GOMAXPROCS=1 \
    GOGC=75 \
    GOMEMLIMIT=192MiB \
    PORT=8080 \
    DOH_PATH=/dns-query \
    RATE_LIMIT=99 \
    RATE_WINDOW_SECONDS=60 \
    MAX_DNS_MESSAGE_BYTES=65535 \
    MAX_CONCURRENCY=128 \
    MAX_CLIENT_IPS=250000 \
    TRUST_PROXY_HEADERS=true

EXPOSE 8080

USER doh

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O - http://127.0.0.1:${PORT}/health >/dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
