.PHONY: dev build release reproduce test test-postgres postgres-up postgres-down lint fmt tidy clean

BIN := bin/tildrad
PG_CONTAINER := tildra-pg
PG_PORT ?= 55440
PG_URL := postgres://tildra:tildra@127.0.0.1:$(PG_PORT)/tildra?sslmode=disable

dev:
	go run ./cmd/tildrad

build:
	go build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/tildrad
	go build -trimpath -ldflags="-s -w" -o bin/tildra-auditor ./cmd/tildra-auditor

# The exact flags a published binary is built with. Anyone can run this and
# compare hashes against a release — see docs/REPRODUCIBLE_BUILDS.md. `build`
# above is for development and is deliberately not the same command; use this
# one for anything anybody else will run.
release:
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
		-o $(BIN) ./cmd/tildrad
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
		-o bin/tildra-auditor ./cmd/tildra-auditor

# Build twice from two different source paths and fail unless the bytes match.
reproduce:
	./scripts/reproduce.sh

test:
	go test -race -count=1 ./...

# Bring up a throwaway Postgres and run the conformance suite against it.
# Without this the Postgres half of the suite skips, and the two store
# implementations are free to drift.
postgres-up:
	@docker start $(PG_CONTAINER) 2>/dev/null || \
		docker run -d --name $(PG_CONTAINER) \
			-e POSTGRES_USER=tildra -e POSTGRES_PASSWORD=tildra -e POSTGRES_DB=tildra \
			-p $(PG_PORT):5432 postgres:16-alpine
	@printf 'waiting for postgres'
	@until docker exec -e PGPASSWORD=tildra $(PG_CONTAINER) \
		psql -h 127.0.0.1 -U tildra -d tildra -c 'select 1' >/dev/null 2>&1; \
		do printf '.'; sleep 1; done; echo ' ready'

postgres-down:
	@docker rm -f $(PG_CONTAINER) >/dev/null 2>&1 || true

test-postgres: postgres-up
	TILDRA_TEST_DATABASE_URL='$(PG_URL)' go test -count=1 ./internal/store/...

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
