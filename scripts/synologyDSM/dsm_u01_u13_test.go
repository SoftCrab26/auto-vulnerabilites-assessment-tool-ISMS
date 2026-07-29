package main

import (
	"strings"
	"testing"
)

type dsmU01U13TestCase struct {
	name string
	got  CheckResult
	want Status
}

func TestDSMU01U13Evaluators(t *testing.T) {
	tests := []dsmU01U13TestCase{
		{
			name: "U01 disables active SSH root login",
			got: evalU01(U01Input{
				SSHConfig: "PermitRootLogin no\nMatch User backup\nPermitRootLogin yes\n",
				Source:    "/etc/ssh/sshd_config",
				SSHActive: true,
			}),
			want: Good,
		},
		{
			name: "U01 missing critical evidence",
			got:  evalU01(U01Input{}),
			want: Error,
		},
		{
			name: "U02 clear PAM complexity",
			got: evalU02(U02Input{Evidence: []FileResult{{
				Path: "/etc/pam.d/common-password",
				Content: "password requisite pam_pwquality.so minlen=12 " +
					"ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1\n",
			}}}),
			want: Good,
		},
		{
			name: "U02 DSM UI policy requires review",
			got: evalU02(U02Input{Evidence: []FileResult{{
				Path: "/etc/synoinfo.conf", Content: "support_auto_block=\"yes\"\n",
			}}}),
			want: Manual,
		},
		{
			name: "U03 compliant lockout threshold",
			got: evalU03(U03Input{Evidence: []FileResult{{
				Path:    "/etc/pam.d/common-auth",
				Content: "auth required pam_faillock.so deny=5 unlock_time=600\n",
			}}}),
			want: Good,
		},
		{
			name: "U04 secure file metadata",
			got: evalU04(U04Input{Files: []U04FileEvidence{
				{Path: "/etc/passwd", Mode: 0o644, UID: 0, GID: 0, Found: true},
				{Path: "/etc/shadow", Mode: 0o600, UID: 0, GID: 0, Found: true},
			}}),
			want: Good,
		},
		{
			name: "U05 finds non-root UID zero",
			got: evalU05(U05Input{
				Source: "/etc/passwd",
				Passwd: "root:x:0:0:root:/root:/bin/sh\nbackdoor:x:0:0::/:/bin/sh\n",
			}),
			want: Vulnerable,
		},
		{
			name: "U06 accepts DSM administrators restriction",
			got: evalU06(U06Input{
				PAMSource:   "/etc/pam.d/su",
				SuPAM:       "auth required pam_wheel.so use_uid group=administrators\n",
				GroupSource: "/etc/group",
				Group:       "administrators:x:101:admin\n",
			}),
			want: Good,
		},
		{
			name: "U07 flags obvious sample account",
			got: evalU07(U07Input{
				Source: "/etc/passwd",
				Passwd: "sample:x:1025:100::/var/services/homes/sample:/bin/sh\n",
			}),
			want: Vulnerable,
		},
		{
			name: "U08 membership requires authorization review",
			got: evalU08(U08Input{
				Source: "/etc/group",
				Group:  "administrators:x:101:admin,ops\n",
			}),
			want: Manual,
		},
		{
			name: "U08 clearly unauthorized sample administrator",
			got: evalU08(U08Input{
				Source: "/etc/group",
				Group:  "administrators:x:101:admin,test\n",
			}),
			want: Vulnerable,
		},
		{
			name: "U09 inventory requires operational review",
			got: evalU09(U09Input{
				GroupSource:  "/etc/group",
				Group:        "administrators:x:101:admin\nunused:x:999:\n",
				PasswdSource: "/etc/passwd",
				Passwd:       "admin:x:1024:101::/var/services/homes/admin:/bin/sh\n",
			}),
			want: Manual,
		},
		{
			name: "U10 finds duplicate UIDs",
			got: evalU10(U10Input{
				Source: "/etc/passwd",
				Passwd: "alice:x:1026:100::/:/bin/sh\nbob:x:1026:100::/:/bin/sh\n",
			}),
			want: Vulnerable,
		},
		{
			name: "U11 flags interactive system account",
			got: evalU11(U11Input{
				Source: "/etc/passwd",
				Passwd: "daemon:x:2:2::/:/bin/sh\n",
			}),
			want: Vulnerable,
		},
		{
			name: "U12 accepts protected short TMOUT",
			got: evalU12(U12Input{Evidence: []FileResult{{
				Path: "/etc/profile", Content: "TMOUT=600\nreadonly TMOUT\nexport TMOUT\n",
			}}}),
			want: Good,
		},
		{
			name: "U12 ambiguous DSM timeout policy",
			got: evalU12(U12Input{Evidence: []FileResult{{
				Path: "/etc/profile", Content: "PATH=/bin:/usr/bin\n",
			}}}),
			want: Manual,
		},
		{
			name: "U13 weak active hash",
			got: evalU13(U13Input{
				Source: "/etc/shadow",
				Shadow: "legacy:$1$salt$secret:19000:0:99999:7:::\n",
			}),
			want: Vulnerable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got.Status != test.want {
				t.Fatalf("status = %v, want %v; result=%+v", test.got.Status, test.want, test.got)
			}
		})
	}
}

func TestDSMU13SanitizesShadowEvidence(t *testing.T) {
	const secretHash = "$6$private-salt$highly-secret-hash-body"
	result := evalU13(U13Input{
		Source: "/etc/shadow",
		Shadow: "admin:" + secretHash + ":19000:0:99999:7:::\n" +
			"disabled:!" + secretHash + ":19000:0:99999:7:::\n",
	})
	if result.Status != Good {
		t.Fatalf("status = %v, want %v; result=%+v", result.Status, Good, result)
	}
	output := dsmU01U13TestResultText(result)
	for _, forbidden := range []string{secretHash, "private-salt", "highly-secret-hash-body"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("sensitive hash material %q leaked in result: %q", forbidden, output)
		}
	}
	for _, expected := range []string{"admin=SHA512 lock=unlocked", "disabled=SHA512 lock=locked"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("sanitized classification %q missing from result: %q", expected, output)
		}
	}
}

func dsmU01U13TestResultText(result CheckResult) string {
	return strings.Join([]string{
		result.RawConfig,
		result.ProcessedConfig,
		result.VulnerableConfig,
		result.ErrMsg,
	}, "\n")
}
