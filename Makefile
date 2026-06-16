BINARY := dragnet
PKG    := ./cmd/dragnet
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build windows linux clean run tidy vet

all: windows

build:
	go build -o $(BINARY) $(PKG)

windows:
	GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BINARY).exe $(PKG)

linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BINARY) $(PKG)

run: build
	./$(BINARY) -target 127.0.0.1 -ports top -no-tui

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -f $(BINARY) $(BINARY).exe dragnet-*.json dragnet-*.html
