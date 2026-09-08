.PHONY: build test vet fmt icons dist clean

VERSION ?= dev
SERVER  ?=
GO_LDFLAGS = -s -w -X main.Version=$(VERSION)$(if $(SERVER), -X main.DefaultServer=$(SERVER))

build:             ## собрать под текущую платформу
	CGO_ENABLED=0 go build -trimpath -ldflags "$(GO_LDFLAGS)" -o pulse-agent ./cmd/pulse-agent

test:
	go test -race ./...

vet:
	go vet ./...
	GOOS=windows go vet ./...

fmt:
	gofmt -w .

icons:             ## пересобрать .ico из SVG (нужен docker)
	docker run --rm -v "$(PWD)/assets/icons":/w -w /w debian:bookworm-slim bash -c '\
		apt-get update -qq >/dev/null && apt-get install -yqq librsvg2-bin imagemagick >/dev/null 2>&1; \
		for state in active paused attention; do \
			for s in 16 20 24 32; do rsvg-convert -w $$s -h $$s tray-$$state.svg -o /tmp/t-$$state-$$s.png; done; \
			convert /tmp/t-$$state-16.png /tmp/t-$$state-20.png /tmp/t-$$state-24.png /tmp/t-$$state-32.png tray-$$state.ico; \
		done; \
		for s in 16 32 48 64 128 256; do rsvg-convert -w $$s -h $$s app.svg -o /tmp/a-$$s.png; done; \
		convert /tmp/a-16.png /tmp/a-32.png /tmp/a-48.png /tmp/a-64.png /tmp/a-128.png /tmp/a-256.png app.ico; \
		chown -R $(shell id -u):$(shell id -g) .'

dist:              ## собрать все платформы локально (как в релизе)
	@mkdir -p dist
	@for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do \
		goos=$${target%/*}; goarch=$${target#*/}; ext=""; flags="$(GO_LDFLAGS)"; \
		if [ "$$goos" = "windows" ]; then ext=".exe"; flags="$$flags -H windowsgui"; fi; \
		CGO_ENABLED=0 GOOS=$$goos GOARCH=$$goarch go build -trimpath -ldflags "$$flags" \
			-o dist/pulse-agent-$$goos-$$goarch$$ext ./cmd/pulse-agent || exit 1; \
		echo "собрано dist/pulse-agent-$$goos-$$goarch$$ext"; \
	done
	@cp assets/icons/*.ico dist/
	@cd dist && shasum -a 256 * > SHA256SUMS.txt

clean:
	rm -rf dist pulse-agent pulse-agent.exe
