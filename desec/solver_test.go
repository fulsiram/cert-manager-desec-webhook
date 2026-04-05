package desec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractDomainAndSubname(t *testing.T) {
	tests := []struct {
		name            string
		fqdn            string
		zone            string
		expectedDomain  string
		expectedSubname string
	}{
		{
			name:            "simple challenge",
			fqdn:            "_acme-challenge.example.com.",
			zone:            "example.com.",
			expectedDomain:  "example.com",
			expectedSubname: "_acme-challenge",
		},
		{
			name:            "subdomain challenge",
			fqdn:            "_acme-challenge.sub.example.com.",
			zone:            "example.com.",
			expectedDomain:  "example.com",
			expectedSubname: "_acme-challenge.sub",
		},
		{
			name:            "deep subdomain",
			fqdn:            "_acme-challenge.a.b.c.example.com.",
			zone:            "example.com.",
			expectedDomain:  "example.com",
			expectedSubname: "_acme-challenge.a.b.c",
		},
		{
			name:            "zone apex",
			fqdn:            "example.com.",
			zone:            "example.com.",
			expectedDomain:  "example.com",
			expectedSubname: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, subname := extractDomainAndSubname(tt.fqdn, tt.zone)
			assert.Equal(t, tt.expectedDomain, domain)
			assert.Equal(t, tt.expectedSubname, subname)
		})
	}
}
