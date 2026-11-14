package letsencrypt

import "testing"

func TestDefaultOptionsUseStagingDirectory(t *testing.T) {
	opts := resolveOptions()
	if opts.ACMEDirectoryURL != DefaultACMEStagingDirectoryURL {
		t.Fatalf("unexpected default ACME directory: got=%q want=%q", opts.ACMEDirectoryURL, DefaultACMEStagingDirectoryURL)
	}
}

func TestWithACMEProductionOverridesDirectory(t *testing.T) {
	opts := resolveOptions(WithACMEProduction())
	if opts.ACMEDirectoryURL != DefaultACMEProductionDirectoryURL {
		t.Fatalf("unexpected ACME directory: got=%q want=%q", opts.ACMEDirectoryURL, DefaultACMEProductionDirectoryURL)
	}
}
