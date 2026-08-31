package tailcat

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
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

// TestNoLegacyServiceDomainHardcodes prevents hosted upstream infrastructure
// from being reintroduced as a runtime/configuration default. Go import specs
// for the reused upstream networking module are intentionally excluded here;
// eliminating that compile-time module is a separate engine migration.
func TestNoLegacyServiceDomainHardcodes(t *testing.T) {
	hostedDomain := "tailcat" + ".dev"
	upstreamModuleDomain := "tailscale" + ".com"

	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
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
		case ".md", ".yaml", ".yml", ".json", ".nix", ".toml":
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(b), hostedDomain) {
				return errors.New(path + " contains forbidden hosted-service domain " + hostedDomain)
			}
		case ".go":
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			imports := map[*ast.BasicLit]bool{}
			for _, imp := range f.Imports {
				imports[imp.Path] = true
			}
			var violation error
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING || imports[lit] {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				switch {
				case strings.Contains(s, hostedDomain):
					violation = errors.New(path + " contains forbidden hosted-service domain " + hostedDomain)
					return false
				case strings.Contains(s, upstreamModuleDomain):
					violation = errors.New(path + " contains upstream domain in a non-import runtime string")
					return false
				}
				return true
			})
			if violation != nil {
				return violation
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
