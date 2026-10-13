// Command monarch prepares a customer application build.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] != "seal" {
		return fmt.Errorf("usage: monarch seal -server https://monarch.example.com -tag prod")
	}
	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	server := fs.String("server", "", "API base URL")
	tag := fs.String("tag", "", "Go build tag for this pin, such as prod or staging")
	dir := fs.String("o", defaultPinDir, "package directory to write")
	initOnly := fs.Bool("init", false, "write the development pin and skip the download")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	return executeSeal(sealOpts{Server: *server, Tag: *tag, Dir: *dir, Init: *initOnly})
}
