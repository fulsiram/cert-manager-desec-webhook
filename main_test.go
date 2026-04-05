package main

import (
	"os"
	"testing"

	acmetest "github.com/cert-manager/cert-manager/test/acme"

	"github.com/cert-manager/webhook-example/desec"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

func TestRunsSuite(t *testing.T) {
	if os.Getenv("DESEC_API_TOKEN") == "" {
		t.Skip("DESEC_API_TOKEN not set, skipping conformance tests")
	}

	fixture := acmetest.NewFixture(desec.NewSolver(),
		acmetest.SetResolvedZone(zone),
		acmetest.SetAllowAmbientCredentials(true),
		acmetest.SetManifestPath("testdata/desec"),
		acmetest.SetStrict(true),
	)
	fixture.RunBasic(t)
	fixture.RunExtended(t)
}
