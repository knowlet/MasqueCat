package tailcat

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoImplicitDERPMapService(t *testing.T) {
	if DefaultDERPMapURL != "" {
		t.Fatalf("DefaultDERPMapURL must be empty, got %q", DefaultDERPMapURL)
	}
	_, err := FetchDERPMap(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no DERP map URL configured") {
		t.Fatalf("FetchDERPMap without an explicit URL = %v; want explicit-source error", err)
	}

	ci := &ConnInfo{RegionID: 1}
	err = ci.Expand(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no DERP map source configured") {
		t.Fatalf("ConnInfo.Expand without an explicit map source = %v; want explicit-source error", err)
	}
}

// TestNoLegacyServiceDomainHardcodes prevents the old hosted infrastructure
// from being reintroduced as a runtime/configuration default. Source-level Go
// imports of the upstream networking module are intentionally excluded here;
// eliminating that compile-time module is a separate engine migration.
func TestNoLegacyServiceDomainHardcodes(t *testing.T) {
	forbidden := []string{
		"tailcat" + ".dev",
	}

	root := "."
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if path == "upstream_defaults_test.go" {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".go", ".md", ".yaml", ".yml", ".json", ".nix", ".toml":
		default:
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(b)
		for _, needle := range forbidden {
			if strings.Contains(text, needle) {
				return errors.New(path + " contains forbidden hosted-service domain " + needle)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
