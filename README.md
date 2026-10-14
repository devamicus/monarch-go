# Monarch Application SDK in Go

Library an application embeds to enforce a Monarch license. The control plane is a separate server. Someone who runs that server gives you two values: the API URL, and one license key (`MONARCH_LICENSE_KEY`). You do not copy a master key by hand. `monarch seal` downloads the public key and writes it into your module.

## Add the module

From your application:

```sh
go get github.com/devamicus/monarch-go
go install github.com/devamicus/monarch-go/cmd/monarch@latest
```

## Wire it once

Create the pin package, then call `Open` from `main`.

```sh
monarch seal --init
```

`--init` writes `internal/monarchpin` and leaves the key empty, so the application compiles before you have a server. The import below assumes that directory and the module path `example.com/app`. Change the import when your module path is different. `--output` chooses a different directory.

```go
package main

import (
    "context"
    "log"
    "os"

    "github.com/devamicus/monarch-go"
    "example.com/app/internal/monarchpin"
)

func main() {
    client, err := monarch.Open(monarch.Option{
        StateDir:    "/var/lib/app/monarch",
        ServerURL:   os.Getenv("MONARCH_SERVER_URL"),
        LicenseKey:  os.Getenv("MONARCH_LICENSE_KEY"),
        Environment: "prod",
        Masters:     monarchpin.Masters(),
        Sealed:      monarchpin.Sealed(),
    })
    if err != nil {
        log.Fatal(err)
    }
    err = client.Guard(context.Background(), func(ctx context.Context) error {
        if client.Allows("sso") {
            // turn SSO on
        }
        _, cfg, err := client.Config()
        if err != nil {
            return err
        }
        _ = cfg
        return runApp(ctx)
    })
    if err != nil {
        log.Fatal(err)
    }
}
```

Keep this call site. Development and production select behavior around it.

`go run .` with no mode set is development. The process prints `license check disabled for development` and starts the app. It does not call the API and does not create the state directory.

## Develop

| Command | What happens |
|---|---|
| `MONARCH_MODE=off go run .` | Same as an unset mode. `Allows` is true. `Limit` returns the maximum int64. `Config` returns revision 0 and an empty map. |
| `MONARCH_MODE=file go run .` | Serves `monarch.local.json` from the working directory. The API is not called. A missing file stops startup. |
| `MONARCH_MODE=live go run .` | Activates against `MONARCH_SERVER_URL`. Run `monarch seal --server` first, or startup stops with `no master keys; run monarch seal`. |

`monarch.local.json`:

```json
{
  "features": {"sso": true},
  "limits": {"warehouses": 3},
  "config": {"values": {"region": "local"}}
}
```

`features` is what `Allows` reads. `limits` is what `Limit` reads. `config.values` is what `Config` returns. A feature or limit left out is false. Unknown JSON fields are rejected. Set `Option.File` when the file is not in the working directory.

## Try the real server

Ask the operator for the API URL and a license key. The license environment must be `prod` when `Environment` is `prod`. An empty `Environment` also means `prod`.

```sh
monarch seal --server https://monarch.example.com --tag prod
MONARCH_MODE=live \
  MONARCH_SERVER_URL=https://monarch.example.com \
  MONARCH_LICENSE_KEY=mon_live_... \
  go run .
```

The first success prints `activated` and an install id. The next start prints `connected` and reuses the snapshot in the state directory.

## Ship

```sh
monarch seal --server https://monarch.example.com --tag prod
go build -tags prod
```

The binary contains the public key and refuses `MONARCH_MODE=off` and `MONARCH_MODE=file`. With the variable unset, it behaves as live.

A second server gets a second tag. `go build -tags staging` selects it. Passing both tags fails to compile. Do not use a tag the Go toolchain sets on its own (`linux`, `darwin`, `amd64`, and the rest); `seal` rejects those names.

## State directory

`StateDir` is one install and one seat. Mode `0700`. Every process of that deployment must share it. Copying it to another machine takes a second seat. `Open` creates it only for a live or sealed run. Put the license key in the environment of the process, not in the directory.

## Logging

Leave `Option.Info` nil and these lines go to stderr:

```text
monarch: license check disabled for development
monarch: using monarch.local.json for development
monarch: activated instance=inst_... server=https://monarch.example.com
monarch: connected instance=inst_... server=https://monarch.example.com
```

To send them through the logger you already use, pass a function:

```go
Info: slog.Default().Info,
```

```go
Info: func(msg string, args ...any) {
    log.Info().Fields(pairs(args)).Msg(msg)
},
```

`pairs` is yours: it turns the alternating key, value list into the fields your logger expects.

## Calls

`Guard` activates when a license key is set and no snapshot is cached, then calls your function only while the install is serving. A later check that becomes restricted cancels that context. `Config` returns `ErrNotServing` when a live install is restricted. `Mode` is `serving` or `restricted`. `Reason` explains a restriction.

`PublicKey` is the install key. For a host that cannot reach the API, print it and ask the operator for an air-gap file, then `Import` the token and delegation. A file does not heartbeat. It serves until it expires.

## This repository

```sh
go test ./...
```
