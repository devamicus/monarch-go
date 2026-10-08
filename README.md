# monarch-go

Install library for applications that check a Monarch license.

```go
import (
    "github.com/devamicus/monarch-go"
    "github.com/devamicus/monarch-go/token"
)

client, err := monarch.Open(monarch.Option{
    StateDir:    "/var/lib/warehouse/monarch",
    ServerURL:   "https://monarch.example.com",
    LicenseKey:  os.Getenv("MONARCH_LICENSE_KEY"),
    Environment: "prod",
    Masters:     token.Masters{"master-2026": masterPublicKey},
})
if err != nil {
    log.Fatal(err)
}
err = client.Guard(context.Background(), func(ctx context.Context) error {
    _, cfg, err := client.Config()
    if err != nil {
        return err
    }
    _ = cfg
    return runApp(ctx)
})
```

`Guard` activates when a license key is set and calls the function only while the snapshot is serving. `Config` returns `ErrNotServing` when the install is restricted.

`token` is the signed-snapshot contract. The control plane imports `github.com/devamicus/monarch-go/token` and this library verifies with the same rules.

```sh
go test ./...
```
