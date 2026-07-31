package storetest

import (
	"os"
	"reflect"
	"regexp"
	"testing"

	"github.com/tildra/tildra/server/internal/store"
)

// The rule this file exists to enforce is already written down, in
// `docs/STATUS.md`: "If you add a method to `store.Store`, add it to the suite
// too, or Postgres and memory are free to drift."
//
// Nothing enforced it. Four methods had slipped through — the whole
// device-linking provisioning channel, which is the one operation where a
// difference between the two implementations hands somebody else a seat at the
// table. They were added when this test was written; the test is what stops
// the next four.
//
// It checks that the suite *names* every method, which is necessary and not
// sufficient: it cannot tell a thorough case from a token one. What it does
// catch is the failure that actually happened, which is a method nobody
// remembered at all.

// allowed lists methods deliberately outside the suite, with the reason.
//
// Adding to this map is a decision, not a formality — the same shape as the
// client's `check:reachable` allowlist, and for the same reason: an exception
// nobody has to justify stops being an exception.
var allowed = map[string]string{
	"Close": "both factories close the store in t.Cleanup, so it is exercised by " +
		"every run; asserting it here as well would close the pgx pool twice",
}

func TestEveryStoreMethodIsInTheConformanceSuite(t *testing.T) {
	src, err := os.ReadFile("storetest.go")
	if err != nil {
		t.Fatalf("read the suite: %v", err)
	}

	iface := reflect.TypeOf((*store.Store)(nil)).Elem()
	if iface.NumMethod() < 30 {
		t.Fatalf("only %d methods on store.Store; this test is looking at the wrong type",
			iface.NumMethod())
	}

	var missing []string
	for i := 0; i < iface.NumMethod(); i++ {
		name := iface.Method(i).Name
		if _, ok := allowed[name]; ok {
			continue
		}
		// A call, not a mention: `s.Method(` rather than the name in a comment.
		if !regexp.MustCompile(`\.` + name + `\(`).Match(src) {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		t.Fatalf("these store.Store methods are not exercised by the conformance suite, "+
			"so the two implementations are free to drift on them: %v", missing)
	}
}

func TestTheAllowlistOnlyNamesRealMethods(t *testing.T) {
	// An allowance for a method that no longer exists is an allowance nobody
	// will notice is stale.
	iface := reflect.TypeOf((*store.Store)(nil)).Elem()
	for name, reason := range allowed {
		if _, ok := iface.MethodByName(name); !ok {
			t.Errorf("the allowlist names %q, which is not on store.Store", name)
		}
		if reason == "" {
			t.Errorf("%q is allowed without a reason", name)
		}
	}
}

func TestEverySuiteCaseIsRegistered(t *testing.T) {
	// The guard above scans for calls, so a case that exists but was never
	// added to the runner would satisfy it while never executing — a method
	// covered on paper and untested in fact.
	src, err := os.ReadFile("storetest.go")
	if err != nil {
		t.Fatalf("read the suite: %v", err)
	}

	defined := regexp.MustCompile(`(?m)^func (test[A-Za-z0-9]+)\(t \*testing\.T, s store\.Store\)`).
		FindAllStringSubmatch(string(src), -1)
	if len(defined) < 15 {
		t.Fatalf("found only %d suite cases; the pattern is wrong", len(defined))
	}

	for _, m := range defined {
		name := m[1]
		if !regexp.MustCompile(`\{"[A-Za-z0-9]+", ` + name + `\}`).Match(src) {
			t.Errorf("%s is defined but never registered in Run, so it never runs", name)
		}
	}
}
