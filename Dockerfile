FROM golang:1.23-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=1.0.0-docker
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" -o /out/pulse-agent ./cmd/pulse-agent

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 pulse
COPY --from=build /out/pulse-agent /usr/local/bin/pulse-agent

# Pre-create the identity directory so a mounted named volume inherits the
# unprivileged user's ownership instead of being created root-owned.
RUN mkdir -p /home/pulse/.pulse-agent && chown -R pulse:pulse /home/pulse

# The agent has no business running as root — and doesn't need to.
USER pulse
WORKDIR /home/pulse

ENTRYPOINT ["/usr/local/bin/pulse-agent"]
