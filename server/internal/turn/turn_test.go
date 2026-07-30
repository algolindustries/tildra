package turn

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{
		Secret: "a-shared-secret",
		URLs:   []string{"turn:turn.example:3478?transport=udp", "turns:turn.example:5349"},
		TTL:    time.Hour,
	}
}

var epoch = time.Unix(1_770_000_000, 0)

func TestIssueMatchesTheCoturnRestConvention(t *testing.T) {
	// Computed here the way coturn does it, independently of Issue. If this
	// only checked Issue against Verify, both could be wrong together and the
	// relay would reject every credential the server hands out.
	c := testConfig()
	cred, err := c.Issue(epoch)
	if err != nil {
		t.Fatal(err)
	}

	mac := hmac.New(sha1.New, []byte(c.Secret))
	mac.Write([]byte(cred.Username))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if cred.Password != want {
		t.Fatalf("password = %q, coturn would compute %q", cred.Password, want)
	}
}

func TestUsernameIsExpiryColonName(t *testing.T) {
	cred, err := testConfig().Issue(epoch)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.SplitN(cred.Username, ":", 2)
	if len(parts) != 2 {
		t.Fatalf("username %q is not <expiry>:<name>", cred.Username)
	}
	expiry, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		t.Fatalf("expiry %q is not a number", parts[0])
	}
	if want := epoch.Add(time.Hour).Unix(); expiry != want {
		t.Fatalf("expiry = %d, want %d", expiry, want)
	}
	if expiry != cred.ExpiresAt {
		t.Fatalf("ExpiresAt %d disagrees with the username %d", cred.ExpiresAt, expiry)
	}
	if parts[1] == "" {
		t.Fatal("name is empty")
	}
}

func TestCredentialCarriesNothingAboutWhoAskedForIt(t *testing.T) {
	// The whole point of not using an account id: a TURN log must not say
	// which account relayed media. Two issuances a moment apart must not be
	// linkable to each other either.
	c := testConfig()
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		cred, err := c.Issue(epoch)
		if err != nil {
			t.Fatal(err)
		}
		name := strings.SplitN(cred.Username, ":", 2)[1]
		if seen[name] {
			t.Fatalf("name %q was issued twice", name)
		}
		seen[name] = true
	}
}

func TestVerifyAcceptsWhatIssueProduces(t *testing.T) {
	c := testConfig()
	cred, err := c.Issue(epoch)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Verify(cred.Username, cred.Password, epoch) {
		t.Fatal("a freshly issued credential did not verify")
	}
	if !c.Verify(cred.Username, cred.Password, epoch.Add(59*time.Minute)) {
		t.Fatal("credential rejected while still inside its window")
	}
}

func TestVerifyRejectsAnExpiredCredential(t *testing.T) {
	c := testConfig()
	cred, err := c.Issue(epoch)
	if err != nil {
		t.Fatal(err)
	}
	if c.Verify(cred.Username, cred.Password, epoch.Add(time.Hour+time.Second)) {
		t.Fatal("an expired credential verified")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	c := testConfig()
	cred, err := c.Issue(epoch)
	if err != nil {
		t.Fatal(err)
	}

	// Extending the expiry without the secret is the obvious attack: the
	// timestamp is inside the MAC precisely so it cannot be moved.
	longer := strconv.FormatInt(cred.ExpiresAt+86400, 10) +
		":" + strings.SplitN(cred.Username, ":", 2)[1]
	if c.Verify(longer, cred.Password, epoch) {
		t.Fatal("a credential with a moved expiry verified")
	}

	if c.Verify(cred.Username, cred.Password+"x", epoch) {
		t.Fatal("a modified password verified")
	}

	other := testConfig()
	other.Secret = "a-different-secret"
	if other.Verify(cred.Username, cred.Password, epoch) {
		t.Fatal("a credential verified against the wrong secret")
	}
}

func TestVerifyRejectsMalformedUsernames(t *testing.T) {
	c := testConfig()
	for _, bad := range []string{"", "no-colon", "notanumber:name", ":name"} {
		if c.Verify(bad, "whatever", epoch) {
			t.Fatalf("username %q verified", bad)
		}
	}
}

func TestUnconfiguredRefusesRatherThanIssuingSomethingUseless(t *testing.T) {
	for _, c := range []Config{
		{},
		{Secret: "s"},
		{URLs: []string{"turn:x"}},
		{Secret: "s", URLs: nil},
	} {
		if c.Configured() {
			t.Fatalf("%+v reported itself configured", c)
		}
		if _, err := c.Issue(epoch); err != ErrNotConfigured {
			t.Fatalf("%+v: err = %v, want ErrNotConfigured", c, err)
		}
	}
}

func TestTTLDefaultsWhenUnset(t *testing.T) {
	c := testConfig()
	c.TTL = 0
	cred, err := c.Issue(epoch)
	if err != nil {
		t.Fatal(err)
	}
	if want := epoch.Add(DefaultTTL).Unix(); cred.ExpiresAt != want {
		t.Fatalf("ExpiresAt = %d, want the default TTL %d", cred.ExpiresAt, want)
	}
}

func TestParseURLs(t *testing.T) {
	cases := map[string][]string{
		"":                              nil,
		"   ":                           nil,
		"turn:a:3478":                   {"turn:a:3478"},
		"turn:a:3478, turns:b:5349":     {"turn:a:3478", "turns:b:5349"},
		"turn:a:3478,,  ,turns:b:5349 ": {"turn:a:3478", "turns:b:5349"},
	}
	for raw, want := range cases {
		got := ParseURLs(raw)
		if len(got) != len(want) {
			t.Fatalf("ParseURLs(%q) = %v, want %v", raw, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("ParseURLs(%q) = %v, want %v", raw, got, want)
			}
		}
	}
}
