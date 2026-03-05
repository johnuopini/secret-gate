FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder

ARG TARGETARCH
ARG TARGETOS=linux

WORKDIR /app
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum* ./
RUN go mod download
COPY . .

# Build server for target architecture
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-s -w" -o /server ./cmd/server

# Build client for all supported platforms (for download endpoint)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /client-linux-amd64 ./cmd/client
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o /client-linux-arm64 ./cmd/client
RUN CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o /client-darwin-amd64 ./cmd/client
RUN CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o /client-darwin-arm64 ./cmd/client

FROM alpine:3.23
WORKDIR /app
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /server /app/server
COPY --from=builder /client-linux-amd64 /app/clients/client-linux-amd64
COPY --from=builder /client-linux-arm64 /app/clients/client-linux-arm64
COPY --from=builder /client-darwin-amd64 /app/clients/client-darwin-amd64
COPY --from=builder /client-darwin-arm64 /app/clients/client-darwin-arm64

RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup && \
    chown -R appuser:appgroup /app

USER appuser
EXPOSE 8080
ENV PORT=8080
CMD ["/app/server"]
