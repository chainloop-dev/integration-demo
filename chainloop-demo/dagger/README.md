
Build a Go application, package it in a container image, generate its Software Bill Of Materials (SBOM) and attest the result using the Chainloop platform.

```json
dagger call build-and-publish \
  --proj path/to/go-project \
  --chainloop-token env:CHAINLOOP_TOKEN \
  --chainloop-signing-key file:path/to/cosign.key \
  --chainloop-passphrase env:CHAINLOOP_SIGNING_PASSWORD
```