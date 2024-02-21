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
// - Attest the pieces of evidence (binary, container image, and SBOM) using Chainloop
// https://docs.chainloop.dev/getting-started/attestation-crafting
func (m *BuildAndRelease) BuildAndPublish(ctx context.Context, proj *Directory, chainloopToken, chainloopSigningKey, chainloopPassphrase *Secret) (string, error) {
	var err error
	chainloopClient := dag.Chainloop(chainloopToken)

	// Initialize the attestation
	attestationID, err := chainloopClient.AttestationInit(ctx, ChainloopAttestationInitOpts{Repository: proj})
	if err != nil {
		return "", fmt.Errorf("failed to initialize attestation: %w", err)
	}

	// Finish/Mark as failed the attestation once we are done
	defer func() {
		// If there was an error in the process, mark the attestation as failed in Chainloop
		if err != nil {
			chainloopClient.AttestationReset(ctx, attestationID, ChainloopAttestationResetOpts{Reason: err.Error()})
		} else {
			// Push the attestation to Chainloop
			_, err = chainloopClient.AttestationPush(ctx, attestationID, chainloopSigningKey, chainloopPassphrase)
		}
	}()

	// Build software artifacts
	res, err := m.doBuildAndPublish(ctx, proj)
	if err != nil {
		return "", fmt.Errorf("failed to build and publish artifacts: %w", err)
	}

	// Attest the pieces of evidence
	// Container image
	_, err = chainloopClient.AttestationAdd(ctx, attestationID, "image", ChainloopAttestationAddOpts{Value: res.imageRepo})
	if err != nil {
		return "", fmt.Errorf("failed to add container image piece of evidence: %w", err)
	}

	// Binary
	_, err = chainloopClient.AttestationAdd(ctx, attestationID, "binary", ChainloopAttestationAddOpts{Path: res.binary})
	if err != nil {
		return "", fmt.Errorf("failed to add binary piece of evidence: %w", err)
	}

	// SBOM
	_, err = chainloopClient.AttestationAdd(ctx, attestationID, "sbom", ChainloopAttestationAddOpts{Path: res.sbom})
	if err != nil {
		return "", fmt.Errorf("failed to add SBOM piece of evidence: %w", err)
	}

	// Return information about the attestation
	return chainloopClient.AttestationStatus(ctx, attestationID)
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
