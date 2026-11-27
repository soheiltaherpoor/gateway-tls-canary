FROM golang:1.24 AS build
WORKDIR /src
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/gateway-tls-canary ./cmd/gateway-tls-canary

FROM scratch
# The CA bundle is what the chain_valid metric verifies against.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/gateway-tls-canary /gateway-tls-canary
USER 65534:65534
EXPOSE 9195
ENTRYPOINT ["/gateway-tls-canary"]
# Mount your config at /config.json and set "listen": ":9195" in it,
# otherwise the default 127.0.0.1:9195 is unreachable from outside the container.
CMD ["serve", "-config", "/config.json"]
