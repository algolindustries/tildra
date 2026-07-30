module github.com/tildra/tildra/server

go 1.25.0

// Pinned exactly, not as a floor. A newer patch release produces a
// different binary, which is the difference between a reproducible build and
// a build that happens to match today. See docs/REPRODUCIBLE_BUILDS.md.
toolchain go1.25.3

require (
	github.com/coder/websocket v1.8.12
	github.com/jackc/pgx/v5 v5.10.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)
