.PHONY: dev build test lint fmt tidy clean

BIN := bin/tildrad

dev:
	go run ./cmd/tildrad

build:
	go build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/tildrad

test:
	go test -race -count=1 ./...

# The crypto-adjacent packages get the vet treatment plus staticcheck when it
# is installed; CI installs it, local dev doesn't have to.
lint:
	go vet ./...
	@command -v staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed, skipping"

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

clean:
	rm -rf bin
