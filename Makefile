.PHONY: test build docker fmt

VERSION ?= dev

fmt:
	gofmt -w .

test:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)
	go vet ./...
	go test -race -count=1 ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/gateway-tls-canary ./cmd/gateway-tls-canary

docker:
	docker build --build-arg VERSION=$(VERSION) -t gateway-tls-canary .
