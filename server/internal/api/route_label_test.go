package api

import "testing"

func TestRouteLabelKeepsTheEndpointAndDropsTheIdentifier(t *testing.T) {
	cases := map[string]string{
		"/healthz":                         "/healthz",
		"/v1/messages":                     "/v1/messages",
		"/v1/keys":                         "/v1/keys",
		"/v1/keys/ACCOUNT01/DEVICE01":      "/v1/keys/{}/{}",
		"/v1/devices/ACCOUNT01":            "/v1/devices/{}",
		"/v1/handles/ayse":                 "/v1/handles/{}",
		"/v1/attachments/att-123":          "/v1/attachments/{}",
		"/v1/provisioning/prov-1/approval": "/v1/provisioning/{}/{}",
		"/v1/recovery/0123456789abcdef":    "/v1/recovery/{}",
		"/v1/transparency/head":            "/v1/transparency/head",
		"/v1/transparency/consistency":     "/v1/transparency/consistency",
		"/v1/turn":                         "/v1/turn",
		"/v1/auth/challenge":               "/v1/auth/challenge",
	}
	for path, want := range cases {
		if got := routeLabel(path); got != want {
			t.Errorf("routeLabel(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestRouteLabelRefusesAnythingItDoesNotServe(t *testing.T) {
	// An unmatched path is text a stranger chose. Echoing it into the log
	// turns the log into something they can write to.
	for _, path := range []string{
		"/etc/passwd",
		"/v1/nosuchthing/ACCOUNT01",
		"/../../secret",
		"/",
		"",
		"/v1",
		"/v1/keysx/ACCOUNT01",
	} {
		if got := routeLabel(path); got != "(unrecognised)" {
			t.Errorf("routeLabel(%q) = %q, want (unrecognised)", path, got)
		}
	}
}

func TestRouteLabelNeverGrowsBeyondItsPrefix(t *testing.T) {
	// Whatever the path carries, the label is the prefix plus a placeholder
	// per segment — never any of the segments themselves.
	label := routeLabel("/v1/keys/SECRETACCOUNT/SECRETDEVICE/extra")
	if label != "/v1/keys/{}/{}/{}" {
		t.Fatalf("label = %q", label)
	}
}
