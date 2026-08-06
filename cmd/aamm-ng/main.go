package main

import (
	"fmt"
	"io"
	"os"
)

func run(w io.Writer) error {
	_, err := fmt.Fprintln(w, "AAMM-NG development build")
	return err
}

func main() {
	if err := run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
