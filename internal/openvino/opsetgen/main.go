// Command opsetgen writes the operation table internal/openvino embeds, from
// OpenVINO's own opset tables:
//
//	go run ./internal/openvino/opsetgen -source <release and commit> <dir> \
//	  > internal/openvino/opsets.txt
//
// <dir> holds opset1_tbl.hpp to opsetN_tbl.hpp from
// src/core/include/openvino/opsets/ at the OpenVINO release the reader
// follows. Each table lists one _OPENVINO_OP_REG(Name, namespace) per
// operation; the IR reader looks a layer's type up by that name, ignoring
// case, in the opset its version attribute names (OpSet::create_insensitive
// in src/core/src/opsets/opset.cpp). The headers are not committed.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var reg = regexp.MustCompile(`^_OPENVINO_OP_REG\(\s*([A-Za-z0-9_]+)\s*,`)

func main() {
	source := flag.String("source", "", "the OpenVINO release and commit the tables come from")
	flag.Parse()
	if *source == "" || flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: opsetgen -source <release and commit> <dir of opset<N>_tbl.hpp>")
		os.Exit(2)
	}
	dir := flag.Arg(0)
	w := bufio.NewWriter(os.Stdout)
	fmt.Fprintln(w, "# OpenVINO's standard operation sets, as its IR reader looks a layer's type up")
	fmt.Fprintln(w, "# (ov::get_available_opsets and OpSet::create_insensitive, src/core/src/opsets/opset.cpp),")
	fmt.Fprintf(w, "# from src/core/include/openvino/opsets/opset<N>_tbl.hpp at %s.\n", *source)
	fmt.Fprintln(w, "# Written by internal/openvino/opsetgen; one opset a line: its name, then its operations.")
	for n := 1; ; n++ {
		p := filepath.Join(dir, fmt.Sprintf("opset%d_tbl.hpp", n))
		ops, err := read(p)
		if errors.Is(err, fs.ErrNotExist) && n > 1 {
			break
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintf(w, "opset%d %s\n", n, strings.Join(ops, " "))
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// read lists the operations one table registers, in its order.
func read(p string) ([]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var ops []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		if m := reg.FindStringSubmatch(strings.TrimSpace(s.Text())); m != nil {
			ops = append(ops, m[1])
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(ops) == 0 {
		return nil, fmt.Errorf("%s registers no operation", p)
	}
	return ops, nil
}
