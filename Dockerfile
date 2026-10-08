FROM alpine:3.24.2 AS build
ARG TARGETARCH
RUN apk add --no-cache ca-certificates wget tar openssl
WORKDIR /build
RUN mkdir -p /out
RUN set -eux; GO_VERSION=1.27.1; case "${TARGETARCH}" in amd64) GO_ARCH=amd64; GO_SHA=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445;; arm64) GO_ARCH=arm64; GO_SHA=3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec;; *) echo "Unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1;; esac; wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz; echo "${GO_SHA}  /tmp/go.tar.gz" | sha256sum -c -; tar -C /usr/local -xzf /tmp/go.tar.gz; rm /tmp/go.tar.gz
ENV PATH=/usr/local/go/bin:$PATH CGO_ENABLED=0
RUN set -eux; DNSCRYPT_VERSION=2.1.18; DNSCRYPT_SHA256=9b810d862ba07c383cc0b8f9f7f1f2ca8f74a02f849d818c4c4d37cc21a7dfa6; wget -q "https://github.com/DNSCrypt/dnscrypt-proxy/archive/refs/tags/${DNSCRYPT_VERSION}.tar.gz" -O /tmp/dnscrypt.tar.gz; echo "${DNSCRYPT_SHA256}  /tmp/dnscrypt.tar.gz" | sha256sum -c -; mkdir -p /build/dnscrypt; tar -xzf /tmp/dnscrypt.tar.gz -C /build/dnscrypt --strip-components=1; rm /tmp/dnscrypt.tar.gz; cd /build/dnscrypt; go build -mod=vendor -trimpath -ldflags='-s -w' -o /out/dnscrypt-proxy ./dnscrypt-proxy; /out/dnscrypt-proxy -version
COPY main.go main_test.go go.mod /build/gateway/
RUN set -eux; cd /build/gateway; go test ./...; go vet ./...; go build -trimpath -ldflags='-s -w' -o /out/doh-gateway .
RUN set -eux; openssl req -x509 -nodes -newkey rsa:2048 -days 5000 -sha256 -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' -keyout /out/localhost.pem -out /out/localhost.pem
FROM alpine:3.24.2 AS runtime
RUN apk add --no-cache ca-certificates tzdata tini && addgroup -S doh && adduser -S -D -H -G doh doh
COPY --from=build /out/dnscrypt-proxy /usr/local/bin/dnscrypt-proxy
COPY --from=build /out/doh-gateway /usr/local/bin/doh-gateway
COPY --from=build /out/localhost.pem /etc/localhost.pem
COPY dnscrypt-proxy.toml /etc/dnscrypt-proxy.toml
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /usr/local/bin/dnscrypt-proxy /usr/local/bin/doh-gateway /entrypoint.sh && chmod 0600 /etc/localhost.pem && chown doh:doh /etc/localhost.pem
ENV GOMAXPROCS=1 GOGC=75 GOMEMLIMIT=192MiB PORT=8080 DOH_PATH=/dns-query RATE_LIMIT=99 RATE_WINDOW_SECONDS=60 MAX_DNS_MESSAGE_BYTES=4096 MAX_CONCURRENCY=8 MAX_CLIENT_IPS=10000 TRUST_PROXY_HEADERS=true
EXPOSE 8080
USER doh
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 CMD wget -q -O - http://127.0.0.1:${PORT}/health >/dev/null || exit 1
ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
