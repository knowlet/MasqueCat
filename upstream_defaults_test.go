package tailcat

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
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

// TestNoLegacyServiceDomainHardcodes guards only the runtime surfaces that can
// supply DERP-map defaults. It deliberately does not ban ordinary mentions of
// the upstream Go module and does not scan documentation or test fixtures.
func TestNoLegacyServiceDomainHardcodes(t *testing.T) {
	hostedDomain := "tailcat" + ".dev"
	var violations []string

	isRuntimeSurface := func(path string) bool {
		path = filepath.ToSlash(path)
		switch path {
		case "tailcat.go", "pickregion.go", "pickregion_js.go":
			return true
		}
		return strings.HasPrefix(path, "cmd/") ||
			strings.HasPrefix(path, "web/") ||
			strings.HasPrefix(path, "webdemo/")
	}

	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".github", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !isRuntimeSurface(path) || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		switch strings.ToLower(filepath.Ext(path)) {
		case ".js", ".html", ".json", ".yaml", ".yml", ".toml", ".nix":
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(b), hostedDomain) {
				violations = append(violations, path+" contains forbidden hosted-service domain "+hostedDomain)
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
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING || imports[lit] {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err == nil && strings.Contains(s, hostedDomain) {
					pos := fset.Position(lit.Pos())
					violations = append(violations, pos.String()+" contains forbidden hosted-service domain "+hostedDomain)
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		sort.Strings(violations)
		t.Fatalf("hosted-service runtime defaults found:\n%s", strings.Join(violations, "\n"))
	}
}
