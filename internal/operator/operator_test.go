package operator

import (
	"strings"
	"testing"
)

func TestUsername_ValidationAndNormalization(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		normalized  string
		expectValid bool
	}{
		{"standard lowercase", "admin", "admin", true},
		{"uppercase normalized to lowercase", "ADMIN", "admin", true},
		{"mixed case with dot and dash", "Admin.User-1", "admin.user-1", true},
		{"underscore allowed", "user_name", "user_name", true},
		{"leading digit allowed", "012", "012", true},
		{"digits and letters", "a1b", "a1b", true},
		{"maximum length 64 characters allowed", strings.Repeat("a", 64), strings.Repeat("a", 64), true},
		{"too short with 1 character rejected", "a", "a", false},
		{"too short with 2 characters rejected", "ab", "ab", false},
		{"too long with 65 characters rejected", strings.Repeat("a", 65), strings.Repeat("a", 65), false},
		{"leading dot rejected", ".admin", ".admin", false},
		{"leading dash rejected", "-admin", "-admin", false},
		{"leading underscore rejected", "_admin", "_admin", false},
		{"at sign character rejected", "admin@stackpilot", "admin@stackpilot", false},
		{"whitespace rejected", "admin space", "admin space", false},
		{"slash character rejected", "admin/root", "admin/root", false},
		{"exclamation mark rejected", "admin!123", "admin!123", false},
		{"colon character rejected", "admin:1", "admin:1", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			norm := NormalizeUsername(tc.input)
			if norm != tc.normalized {
				t.Errorf("NormalizeUsername(%q): expected %q, got %q", tc.input, tc.normalized, norm)
			}

			err := ValidateUsername(norm)
			if tc.expectValid && err != nil {
				t.Errorf("ValidateUsername(%q): unexpected error: %v", norm, err)
			}
			if !tc.expectValid && err == nil {
				t.Errorf("ValidateUsername(%q): expected error, got nil", norm)
			}
		})
	}
}

func TestAuditActions_Constants(t *testing.T) {
	expectedActions := map[AuditAction]string{
		ActionOperatorCreated:   "operator.created",
		ActionOperatorLogin:     "operator.login",
		ActionOperatorLogout:    "operator.logout",
		ActionOperatorAuditRead: "operator.audit.read",
	}

	for act, str := range expectedActions {
		if string(act) != str {
			t.Errorf("action %q mismatch, expected %q", act, str)
		}
	}

	expectedOutcomes := map[AuditOutcome]string{
		OutcomeSuccess: "success",
		OutcomeFailure: "failure",
		OutcomeDenied:  "denied",
	}

	for out, str := range expectedOutcomes {
		if string(out) != str {
			t.Errorf("outcome %q mismatch, expected %q", out, str)
		}
	}
}
