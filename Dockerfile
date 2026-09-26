# Multi-arch build: `docker buildx build --platform linux/arm64,linux/amd64 .`
# The Go toolchain always runs natively and cross-compiles, so building the
# arm64 image on an amd64 machine needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1-alpine AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/submarine-server ./cmd/submarine-server \
 && mkdir -p /out/data

FROM scratch
# CA roots so SMTP over TLS can verify the mail server.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/submarine-server /submarine-server
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENV DB_PATH=/data/submarine.db \
    LISTEN_ADDR=:8080
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD ["/submarine-server", "healthcheck"]
ENTRYPOINT ["/submarine-server"]
CMD ["serve"]
