package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
)

func main() {
	source := flag.String("source", "internal/handshake/profiles", "握手数据目录")
	output := flag.String("output", "internal/handshake/profile_data.go", "输出 Go 文件")
	flag.Parse()
	if err := generate(*source, *output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate(source, output string) error {
	var code bytes.Buffer
	code.WriteString("package handshake\n\nvar profileFiles = map[string]string{\n")
	err := fs.WalkDir(os.DirFS(source), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(filepath.Join(source, path))
		if err != nil {
			return err
		}
		fmt.Fprintf(&code, "%s: %s,\n", strconv.Quote("profiles/"+path), strconv.Quote(string(data)))
		return nil
	})
	if err != nil {
		return err
	}
	code.WriteString("}\n")
	formatted, err := format.Source(code.Bytes())
	if err != nil {
		return err
	}
	return os.WriteFile(output, formatted, 0o644)
}
