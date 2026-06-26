FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/nostr-shigner .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata su-exec && adduser -D -u 1000 nostr-shigner
COPY --from=builder /out/nostr-shigner /usr/local/bin/nostr-shigner
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV HOME=/data
ENV PORT=3000
WORKDIR /data
RUN mkdir -p /data && chown -R nostr-shigner:nostr-shigner /data

# start as root so the entrypoint can fix /data ownership, then drop to nostr-shigner.
# do not set `user:` in compose, or this fix is bypassed.
ENTRYPOINT ["docker-entrypoint.sh"]
EXPOSE 3000
CMD ["nostr-shigner", "web"]
