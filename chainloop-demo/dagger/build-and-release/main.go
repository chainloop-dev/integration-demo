package main

import (
	"context"
	"fmt"
	"math"
	"math/rand"
)

type BuildAndRelease struct{}

func (m *BuildAndRelease) BuildAndPublish(ctx context.Context, proj *Directory) (string, error) {
	// Generate SBOM from the code
	_ = dag.Syft().Sbom(proj, "sbom.json", SyftSbomOpts{Output: "cyclonedx-json"})

	// Build the go binary
	binary := dag.Golang().WithProject(proj).Build([]string{"-o", "server"}).File("server")

	imagePath, err := dag.Wolfi().Container().
		WithFile("/server", binary).
		WithEntrypoint([]string{"/server"}).
		Publish(ctx, fmt.Sprintf("ttl.sh/chainloop-demo-%.0f", math.Floor(rand.Float64()*10000000))) //#nosec
	if err != nil {
		return "", err
	}

	return imagePath, nil
}
