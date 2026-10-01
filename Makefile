BINARY  := fpm-wg
PKG     := ./cmd/fpm-wg
LDFLAGS := -s -w

.PHONY: all build test vet fmt install clean

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

install: build
	install -Dm0755 bin/$(BINARY) /usr/local/bin/$(BINARY)

clean:
	rm -rf bin
