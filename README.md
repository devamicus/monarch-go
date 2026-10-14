# Monarch Application SDK in Go

Library an application embeds to enforce a Monarch license. The control plane is a separate server. Someone who runs that server gives you two values: the API URL, and one license key (`MONARCH_LICENSE_KEY`). You do not copy a master key by hand. `monarch seal` downloads the public key and writes it into your module.

## Add the module

From your application:

```sh
go get github.com/devamicus/monarch-go
go install github.com/devamicus/monarch-go/cmd/monarch@latest
```

## monarch seal

```text
$ monarch seal --help
monarch seal writes the pin package an application compiles in.

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
```

```sh
monarch seal --init

monarch seal --server https://monarch.example.com --tag prod

monarch seal --server https://staging.example.com --tag staging --output internal/licensing
```

The first command creates `internal/monarchpin` so the import below compiles. The second downloads the production public key. The third does the same for staging and writes a different directory, so that import path changes with it. The sample below uses `example.com/app`.

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

Ask whoever runs Monarch for the API address and a license key. The license environment is `prod` unless they tell you otherwise. Leave `Environment` empty and the library sends `prod`.

```sh
MONARCH_MODE=live \
  MONARCH_SERVER_URL=https://monarch.example.com \
  MONARCH_LICENSE_KEY=mon_live_... \
  go run .
```

The first success prints `activated` and an install id. The next start prints `connected` and reuses the snapshot already in the state directory.

## Air-gap

Save the JSON from `POST /v1/offline-tokens` and point the process at it:

```sh
MONARCH_LICENSE_FILE=/var/lib/app/monarch/license.json ./app
```

`Open` imports that file. The call site stays `Open` and `Guard`. The file is the response body, with `token` and `delegation`. A newer file replaces the cached snapshot on the next start. `Option.LicenseFile` sets the same path in code.

With no license configured, and again when an air-gap file has expired, startup prints the install public key and both of these procedures:

```text
monarch: no license configured

Online. An admin creates a license and an activation key. Start this process with:

  MONARCH_SERVER_URL=https://monarch.example.com
  MONARCH_LICENSE_KEY=mon_live_...

Offline. An admin issues a file for this public key:

  public key: <base64url>

Save that response and start this process with:

  MONARCH_LICENSE_FILE=/var/lib/app/monarch/license.json
```

An expired file starts with `air-gap license expired` and prints the same public key. Replace the file and restart. The same public key refreshes that install.

## Ship

Build with the same tag you sealed:

```sh
go build -tags prod
```

The public key is inside the binary, and the license check always runs. A staging server is a second seal, with `--tag staging`, and a build of `go build -tags staging`. Build with one tag. `seal` will not accept a name Go already uses, such as `linux` or `amd64`.

## State directory

`StateDir` is one install and one seat. Mode `0700`. Every process of that deployment must share it. Copying it to another machine takes a second seat. `Open` creates it only for a live or sealed run. Put the license key in the environment of the process, not in the directory.

## Logging

Leave `Option.Info` nil and these lines go to stderr:

```text
monarch: license check disabled for development
monarch: using monarch.local.json for development
monarch: activated instance=inst_... server=https://monarch.example.com
monarch: imported instance=inst_...
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

`PublicKey` is the install key. A live process with no license, and a process whose air-gap file has expired, prints that key and the online and offline procedures. `Open` imports `MONARCH_LICENSE_FILE`. A file does not heartbeat. It serves until it expires.

## This repository

```sh
go test ./...
```
