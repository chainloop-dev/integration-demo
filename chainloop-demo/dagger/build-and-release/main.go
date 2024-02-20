package main

import (
	"context"
	"fmt"
	"math"
	"math/rand"
)

type BuildAndRelease struct{}

func (m *BuildAndRelease) BuildAndPublish(ctx context.Context, proj *Directory, chainloopToken, chainloopSigningKey, chainloopPassphrase *Secret) (string, error) {
	var err error

	// Initialize the attestation
	attestationID, err := dag.Chainloop(chainloopToken).AttestationInit(ctx, ChainloopAttestationInitOpts{Repository: proj})
	if err != nil {
		return "", fmt.Errorf("failed to initialize attestation: %w", err)
	}

	// Finish the attestation once we are done
	defer func() {
		// If there was an error in the process, mark the attestation as failed in Chainloop
		if err != nil {
			dag.Chainloop(chainloopToken).AttestationReset(ctx, attestationID, ChainloopAttestationResetOpts{Reason: err.Error()})
		} else {
			// Push the attestation to Chainloop
			_, err = dag.Chainloop(chainloopToken).AttestationPush(ctx, attestationID, chainloopSigningKey, chainloopPassphrase)
		}
	}()

	// Build the go binary
	binary := dag.Golang().WithProject(proj).Build([]string{"-o", "server"}).File("server")

	// Generate SBOM from the code
	sbom := dag.Syft().Sbom(proj, "sbom.json", SyftSbomOpts{Output: "cyclonedx-json"})

	// Build and publish a container image
	imageRepo, err := dag.Wolfi().Container().
		WithFile("/server", binary).
		WithEntrypoint([]string{"/server"}).
		Publish(ctx, fmt.Sprintf("ttl.sh/chainloop-demo-%.0f", math.Floor(rand.Float64()*10000000))) //#nosec
	if err != nil {
		return "", err
	}

	// Attest the pieces of evidence
	// Container image
	_, err = dag.Chainloop(chainloopToken).AttestationAdd(ctx, attestationID, "image", ChainloopAttestationAddOpts{Value: imageRepo})
	if err != nil {
		return "", fmt.Errorf("failed to add image piece of evidence: %w", err)
	}

	// Binary
	_, err = dag.Chainloop(chainloopToken).AttestationAdd(ctx, attestationID, "binary", ChainloopAttestationAddOpts{Path: binary})
	if err != nil {
		return "", fmt.Errorf("failed to add binary piece of evidence: %w", err)
	}

	// SBOM
	_, err = dag.Chainloop(chainloopToken).AttestationAdd(ctx, attestationID, "sbom", ChainloopAttestationAddOpts{Path: sbom})
	if err != nil {
		return "", fmt.Errorf("failed to add SBOM piece of evidence: %w", err)
	}

	return imageRepo, nil
}
