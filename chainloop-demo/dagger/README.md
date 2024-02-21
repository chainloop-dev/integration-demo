
Dagger Module that builds a Go application, packages it in a container image, generates its Software Bill Of Materials (SBOM) and attests the result using the Chainloop platform.

More info about attestation crafting [here](https://docs.chainloop.dev/getting-started/attestation-crafting)

```sh
$ dagger call -m github.com/chainloop-dev/integration-demo/chainloop-demo/dagger build-and-publish \
  --proj path/to/go-project \
  --chainloop-token env:CHAINLOOP_TOKEN \
  --chainloop-signing-key file:path/to/cosign.key \
  --chainloop-passphrase env:CHAINLOOP_SIGNING_PASSWORD
```