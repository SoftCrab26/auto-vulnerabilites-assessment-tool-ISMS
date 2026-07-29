package main

import "testing"

func TestParseDSMMetadata(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		synoinfo  string
		hardware  string
		wantDSM   bool
		supported bool
	}{
		{
			name: "DSM 6.2 fixture",
			version: `majorversion="6"
minorversion="2"
productversion="6.2.4"
buildnumber="25556"
smallfixnumber="8"`,
			synoinfo:  `unique="synology_x86_224+"`,
			hardware:  "DS224+\n",
			wantDSM:   true,
			supported: true,
		},
		{
			name: "DSM 7 is unsupported",
			version: `majorversion="7"
minorversion="2"
productversion="7.2.1"
buildnumber="69057"`,
			wantDSM:   true,
			supported: false,
		},
		{
			name:      "missing metadata",
			wantDSM:   false,
			supported: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata := parseDSMMetadata(test.version, test.synoinfo, test.hardware)
			if metadata.IsDSM != test.wantDSM {
				t.Fatalf("IsDSM = %t, want %t", metadata.IsDSM, test.wantDSM)
			}
			if metadata.IsSupported != test.supported {
				t.Fatalf("IsSupported = %t, want %t", metadata.IsSupported, test.supported)
			}
		})
	}
}

func TestParseDSMMetadataFields(t *testing.T) {
	metadata := parseDSMMetadata(
		"majorversion='6'\nminorversion=2\nproductversion=\"6.2.4\"\nbuildnumber=25556\nsmallfixnumber=8",
		"arch=\"x86_64\"\nupnpmodelname=\"DiskStation\"",
		"DS918+\n",
	)

	if metadata.Version != "6.2.4" || metadata.BuildNumber != "25556" || metadata.SmallFixNumber != "8" {
		t.Fatalf("unexpected version metadata: %+v", metadata)
	}
	if metadata.Model != "DS918+" || metadata.Architecture != "x86_64" {
		t.Fatalf("unexpected hardware metadata: %+v", metadata)
	}
}
