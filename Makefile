VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN := minstrel-launchpad

# os/arch[/variant]: NAS boxes, Raspberry Pis, routers (OpenWrt on ARM and
# MIPS, OPNsense/pfSense on FreeBSD), and desktops that run a media server.
TARGETS := \
	linux/amd64 linux/arm64 linux/arm/7 linux/arm/6 linux/mipsle linux/mips linux/riscv64 \
	freebsd/amd64 freebsd/arm64 \
	darwin/amd64 darwin/arm64 \
	windows/amd64 windows/arm64

.PHONY: build test vet dist docker clean

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) .

test:
	go test ./...

vet:
	go vet ./...

dist:
	@mkdir -p dist
	@for t in $(TARGETS); do \
		os=$${t%%/*}; rest=$${t#*/}; arch=$${rest%%/*}; variant=$${rest#$$arch}; variant=$${variant#/}; \
		name=$(BIN)-$(VERSION)-$$os-$$arch$${variant:+v$$variant}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "$$name"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch GOARM=$$variant GOMIPS=softfloat \
			go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$$name$$ext . || exit 1; \
	done

docker:
	docker build --build-arg VERSION=$(VERSION) -t minstrel-launchpad:$(VERSION) .

clean:
	rm -rf dist $(BIN)
