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
```

`token` is the signed-snapshot contract. The control plane imports `github.com/devamicus/monarch-go/token` and this library verifies with the same rules.

```sh
go test ./...
```
