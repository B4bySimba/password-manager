.PHONY: test race vet fmt build demo bench check clean

check: fmt vet test race

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	@test -z "$$(gofmt -l . )" || (echo "gofmt needed:"; gofmt -l .; exit 1)

build:
	go build -o vault ./cmd/vault

demo:
	go run ./examples/demo

bench:
	go test -bench . -benchmem ./internal/crypto ./internal/pwgen

clean:
	rm -f vault
