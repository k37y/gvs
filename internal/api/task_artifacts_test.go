package api

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOrphanResultRetention(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	for _, test := range []struct {
		name   string
		expiry string
		keep   bool
	}{
		{"gvs-task-expired", now.Add(-time.Minute).Format(time.RFC3339Nano), false},
		{"gvs-task-other-server", now.Add(time.Hour).Format(time.RFC3339Nano), true},
		{"gvs-task-invalid", "invalid", true},
		{"unrelated", now.Add(-time.Minute).Format(time.RFC3339Nano), true},
	} {
		dir := filepath.Join(root, test.name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "expires"), []byte(test.expiry), 0600); err != nil {
			t.Fatal(err)
		}
		cleanupOrphanResults(root, now)
		_, err := os.Stat(dir)
		if test.keep && err != nil || !test.keep && !os.IsNotExist(err) {
			t.Fatalf("%s keep=%v stat=%v", test.name, test.keep, err)
		}
	}
}
