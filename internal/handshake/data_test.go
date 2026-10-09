package handshake

import (
	"bytes"
	"io/fs"
	"os"
	"testing"
)

func TestProfileDataMatchesSource(t *testing.T) {
	count := 0
	err := fs.WalkDir(os.DirFS("profiles"), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile("profiles/" + path)
		if err != nil {
			return err
		}
		stored, err := profileFile("profiles/" + path)
		if err != nil || !bytes.Equal(data, stored) {
			t.Errorf("内置数据与 %s 不一致，请运行 go run ./cmd/profilegen", path)
		}
		count++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != len(profileFiles) {
		t.Fatalf("内置文件数为 %d，源文件数为 %d", len(profileFiles), count)
	}
}
