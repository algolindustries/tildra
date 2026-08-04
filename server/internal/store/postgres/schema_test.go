package postgres_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// docs/PROTOCOL.md §8 is a table of what the operator can see. Nothing checked
// it, so a column could be added and the table would go on saying what used to
// be true — which is how `devices.name` came to be a user-supplied string
// stored in the clear with no row describing it.
//
// This is that table, as columns, listed in schema order and compared sorted.
// A schema change fails here until §8 is changed with it. The note on each
// group is what §8 has to be able to say; if you cannot write one, the column
// is the problem rather than this list.
var expectedColumns = map[string][]string{
	// Routing. An account is a key and an optional public handle.
	"accounts": {"id", "handle", "created_at"},
	// `name` is chosen by the user and stored in the clear. It is for their own
	// device list, and the operator can read it — §8 says so.
	"devices": {"account_id", "device_id", "name", "identity_key", "created_at", "last_seen"},
	// Public halves only. The secrets never leave the device.
	"signed_prekeys": {
		"account_id", "device_id", "identity_key",
		"ec_id", "ec_public", "ec_signature",
		"pq_id", "pq_public", "pq_signature", "updated_at",
	},
	"one_time_prekeys": {"account_id", "device_id", "kind", "key_id", "public_key", "created_at"},
	// A mailbox is registered by the device that will read it, so the server
	// knows which device drains which address. What it does not learn is who
	// wrote to it — see envelopes.
	"mailboxes": {"id", "account_id", "device_id", "expires_at"},
	// No sender column, and there must never be one: that is sealed sender.
	"envelopes": {"id", "mailbox", "ciphertext", "server_ts"},
	"backups":   {"account_id", "blob", "updated_at"},
	// The token itself is never stored, only a hash of it.
	"auth_tokens": {"token_hash", "account_id", "device_id", "expires_at"},
	// No owner column, and there must never be one: an account-to-blob mapping
	// would recreate the metadata sealed sender exists to remove.
	"attachments": {"id", "ciphertext", "size_bytes", "created_at", "expires_at"},
	// Opaque to the server; it is a routing token for the push provider.
	"push_tokens": {"account_id", "device_id", "platform", "token", "updated_at"},
	// Public on purpose. The whole value of the log is that anyone can read it.
	"transparency_log": {"idx", "handle", "account_id", "identity_key", "recorded_at"},
	// Transient, five minutes, and holds public key material plus a sealed blob.
	"provisioning": {"id", "identity_key", "ephemeral_key", "approval", "created_at", "expires_at"},
	// `account_id` is here for "the first account to claim an id keeps it", and
	// it means the operator can link a recovery fetch to an account even though
	// the fetch is unauthenticated. §1.1 and §8 both say so.
	"recovery_blobs": {"lookup_id", "account_id", "blob", "updated_at"},
}

// Words that must never appear as a column name. §8's second row is "Phone
// number / email — never collected", and the cheapest way for that to stop
// being true is a column somebody adds without reading the table.
var forbiddenColumnWords = []string{"phone", "email", "msisdn", "sender", "owner", "uploader"}

var (
	tableRe  = regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\((.*?)\n\)\s*;`)
	columnRe = regexp.MustCompile(`^(\w+)\s`)
)

func TestSchemaMatchesWhatTheProtocolSaysIsStored(t *testing.T) {
	found := readSchema(t)

	for table, want := range expectedColumns {
		got, ok := found[table]
		if !ok {
			t.Errorf("table %q is in the expected set and not in the migrations", table)
			continue
		}
		want = append([]string(nil), want...)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("table %q has columns %v, expected %v\n"+
				"A column is a change to what the operator can see. Update docs/PROTOCOL.md §8 "+
				"and this list together, or do not add it.", table, got, want)
		}
	}

	for table := range found {
		if _, ok := expectedColumns[table]; !ok {
			t.Errorf("table %q is in the migrations and nowhere in docs/PROTOCOL.md §8's accounting", table)
		}
	}
}

func TestNoColumnCollectsWhatTildraSaysItDoesNot(t *testing.T) {
	for table, columns := range readSchema(t) {
		for _, column := range columns {
			for _, word := range forbiddenColumnWords {
				if strings.Contains(column, word) {
					t.Errorf("%s.%s: §8 says this is not collected", table, column)
				}
			}
		}
	}
}

// readSchema parses the migration files rather than a live database, so it runs
// everywhere `go test` does. The files are what ships; a database is only ever
// what they produced.
func readSchema(t *testing.T) map[string][]string {
	t.Helper()

	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}

	tables := map[string][]string{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		body, err := os.ReadFile(filepath.Join("migrations", entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		for _, match := range tableRe.FindAllStringSubmatch(string(body), -1) {
			name := match[1]
			if _, seen := tables[name]; seen {
				t.Errorf("table %q is created in more than one migration", name)
			}
			tables[name] = columnsOf(match[2])
		}
	}

	if len(tables) == 0 {
		t.Fatal("parsed no tables out of the migrations; the parser is broken, not the schema")
	}
	return tables
}

// columnsOf pulls the column names out of a CREATE TABLE body, skipping the
// table-level constraints that share its comma-separated shape.
func columnsOf(body string) []string {
	var columns []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "--") {
			continue
		}
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "PRIMARY KEY") ||
			strings.HasPrefix(upper, "FOREIGN KEY") ||
			strings.HasPrefix(upper, "UNIQUE") ||
			strings.HasPrefix(upper, "CHECK") ||
			strings.HasPrefix(upper, "CONSTRAINT") {
			continue
		}
		if m := columnRe.FindStringSubmatch(line); m != nil {
			columns = append(columns, m[1])
		}
	}
	sort.Strings(columns)
	return columns
}
