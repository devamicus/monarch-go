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
		return fmt.Errorf("usage: monarch seal --server https://monarch.example.com --tag prod")
	}
	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(fs.Output(), sealUsage) }
	var server, tag, dir string
	var initOnly bool
	dir = defaultPinDir
	fs.StringVar(&server, "server", "", "API base URL")
	fs.StringVar(&server, "s", "", "API base URL")
	fs.StringVar(&tag, "tag", "", "Go build tag for this pin, such as prod or staging")
	fs.StringVar(&tag, "t", "", "Go build tag for this pin, such as prod or staging")
	fs.StringVar(&dir, "output", defaultPinDir, "package directory to write")
	fs.StringVar(&dir, "o", defaultPinDir, "package directory to write")
	fs.BoolVar(&initOnly, "init", false, "write the development pin and skip the download")
	fs.BoolVar(&initOnly, "i", false, "write the development pin and skip the download")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	return executeSeal(sealOpts{Server: server, Tag: tag, Dir: dir, Init: initOnly})
}

const sealUsage = `monarch seal writes the pin package an application compiles in.

Create the package before you have a server:

  monarch seal --init

Download a public key and bind it to a build tag:

  monarch seal --server https://monarch.example.com --tag prod

Options:

  -i, --init
        Create the package with an empty key. The API is not contacted.

  -s, --server URL
        Address of the control plane. Pass this together with --tag.

  -t, --tag name
        Build tag for the downloaded key, such as prod or staging.

  -o, --output dir
        Where to write the package. Defaults to internal/monarchpin.
`
