// Package openapitest validates serialized output against the repository's
// OpenAPI component schemas. It is test support, not runtime validation.
package openapitest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
)

var schemas = sync.OnceValues(loadSchemas)

// Validate checks a JSON-serializable value. Pass json.RawMessage for wire JSON
// so unknown fields are checked before decoding into a Go response struct.
func Validate(t testing.TB, name string, value any) {
	t.Helper()
	if err := Check(name, value); err != nil {
		t.Fatal(err)
	}
}

// Check is Validate's error-returning form, used to prove invalid output fails.
func Check(name string, value any) error {
	all, err := schemas()
	if err != nil {
		return fmt.Errorf("OpenAPI %s: %w", name, err)
	}
	schema, ok := all[name]
	if !ok {
		return fmt.Errorf("OpenAPI %s: unknown component schema", name)
	}
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("OpenAPI %s: marshal output: %w", name, err)
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("OpenAPI %s: decode output: %w", name, err)
	}
	if err := schema.Validate(decoded); err != nil {
		return fmt.Errorf("OpenAPI %s: %w", name, err)
	}
	return nil
}

func loadSchemas() (map[string]*jsonschema.Resolved, error) {
	// Go tests run from their package directory. Walk upward rather than relying
	// on compiler source paths, which can be removed by -trimpath.
	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	var data []byte
	for {
		data, err = os.ReadFile(filepath.Join(dir, "openapi.json"))
		if err == nil {
			break
		}
		if !os.IsNotExist(err) || filepath.Dir(dir) == dir {
			return nil, fmt.Errorf("locate openapi.json: %w", err)
		}
		dir = filepath.Dir(dir)
	}
	var document struct {
		Components struct {
			Schemas map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse openapi.json: %w", err)
	}
	if len(document.Components.Schemas) == 0 {
		return nil, fmt.Errorf("openapi.json has no component schemas")
	}
	// JSON Schema's resolver understands $defs, not OpenAPI's components.
	// Relocate only reference keywords; do not rewrite descriptions or values.
	relocateReferences(document.Components.Schemas)
	data, err = json.Marshal(document.Components.Schemas)
	if err != nil {
		return nil, err
	}
	var definitions map[string]*jsonschema.Schema
	if err := json.Unmarshal(data, &definitions); err != nil {
		return nil, fmt.Errorf("parse component schemas: %w", err)
	}
	resolved := make(map[string]*jsonschema.Resolved, len(definitions))
	escapePointer := strings.NewReplacer("~", "~0", "/", "~1")
	for name := range definitions {
		pointer := escapePointer.Replace(name)
		root := &jsonschema.Schema{Defs: definitions, Ref: "#/$defs/" + pointer}
		schema, err := root.Resolve(nil)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", name, err)
		}
		resolved[name] = schema
	}
	return resolved, nil
}

func relocateReferences(value any) {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if ref, ok := child.(string); key == "$ref" && ok && strings.HasPrefix(ref, "#/components/schemas/") {
				value[key] = "#/$defs/" + strings.TrimPrefix(ref, "#/components/schemas/")
			} else {
				relocateReferences(child)
			}
		}
	case []any:
		for _, child := range value {
			relocateReferences(child)
		}
	}
}
