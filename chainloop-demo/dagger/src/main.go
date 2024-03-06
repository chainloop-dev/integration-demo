package main

import (
	"context"
	"fmt"
	"math"
	"math/rand"
)

type BuildAndRelease struct{}

// - Build, package and publish a Go application as a container image
// - Generate a CycloneDX Software Bill Of Materials using Syft
func (m *BuildAndRelease) BuildAndPublish(ctx context.Context, proj *Directory) (string, error) {
	var err error

	// Build software artifacts
	res, err := m.doBuildAndPublish(ctx, proj)
	if err != nil {
		return "", fmt.Errorf("failed to build and publish artifacts: %w", err)
	}

	return res.imageRepo, nil
}

type buildResult struct {
	// Go binary
	binary *File
	// Path to the container image repository
	imageRepo string
	// SBOM file
	sbom *File
}

func (m *BuildAndRelease) doBuildAndPublish(ctx context.Context, proj *Directory) (*buildResult, error) {
	// Build the go binary
	binary := dag.Golang().WithProject(proj).Build([]string{"-o", "server"}).File("server")

	// Generate a CycloneDX SBOM from the source code
	sbom := dag.Syft().Sbom(proj, "sbom.json", SyftSbomOpts{Output: "cyclonedx-json"})

	// Build and publish a container image
	imageRepo, err := dag.Wolfi().Container().
		WithFile("/server", binary).
		WithEntrypoint([]string{"/server"}).
		Publish(ctx, fmt.Sprintf("ttl.sh/chainloop-demo-%.0f", math.Floor(rand.Float64()*10000000))) //#nosec
	if err != nil {
		return nil, fmt.Errorf("failed to build and publish container image: %w", err)
	}

	return &buildResult{imageRepo: imageRepo, sbom: sbom, binary: binary}, nil
}
