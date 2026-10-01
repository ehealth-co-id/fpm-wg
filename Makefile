BINARY  := fpm-wg
PKG     := ./cmd/fpm-wg
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build cross test vet fmt install clean

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

# Build for an explicit GOOS/GOARCH into ./$(BINARY) (used by the release CI).
cross:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

install: build
	install -Dm0755 bin/$(BINARY) /usr/local/bin/$(BINARY)

clean:
	rm -rf bin $(BINARY)
