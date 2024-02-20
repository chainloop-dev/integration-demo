package main

import "context"

type BuildAndRelease struct{}

func (m *BuildAndRelease) Build(ctx context.Context, proj *Directory) (*File, error) {
	// Build the go binary
	binary := dag.Golang().WithProject(proj).Build([]string{"-o", "server"}).File("server")
	return binary, nil
}
