package desec

import (
	"context"
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

type mockDNSClient struct {
	getRRset    func(ctx context.Context, domain, subname string) (*RRset, error)
	createRRset func(ctx context.Context, domain string, rrset RRset) error
	updateRRset func(ctx context.Context, domain, subname string, records []string) error
	deleteRRset func(ctx context.Context, domain, subname string) error
}

func (m *mockDNSClient) GetRRset(ctx context.Context, domain, subname string) (*RRset, error) {
	return m.getRRset(ctx, domain, subname)
}
func (m *mockDNSClient) CreateRRset(ctx context.Context, domain string, rrset RRset) error {
	return m.createRRset(ctx, domain, rrset)
}
func (m *mockDNSClient) UpdateRRset(ctx context.Context, domain, subname string, records []string) error {
	return m.updateRRset(ctx, domain, subname, records)
}
func (m *mockDNSClient) DeleteRRset(ctx context.Context, domain, subname string) error {
	return m.deleteRRset(ctx, domain, subname)
}

func TestPresent_CreatesNewRRset(t *testing.T) {
	var created RRset
	mock := &mockDNSClient{
		getRRset: func(_ context.Context, _, _ string) (*RRset, error) {
			return nil, ErrNotFound
		},
		createRRset: func(_ context.Context, domain string, rrset RRset) error {
			created = rrset
			return nil
		},
	}
	s := &Solver{newClient: func(_ string) DNSClient { return mock }}
	err := s.presentWithClient(mock, "example.com", "_acme-challenge", "challenge-key-123")
	assert.NoError(t, err)
	assert.Equal(t, "_acme-challenge", created.Subname)
	assert.Equal(t, "TXT", created.Type)
	assert.Equal(t, []string{QuoteTXT("challenge-key-123")}, created.Records)
	assert.Equal(t, defaultTTL, created.TTL)
}

func TestPresent_AppendsToExistingRRset(t *testing.T) {
	var updatedRecords []string
	mock := &mockDNSClient{
		getRRset: func(_ context.Context, _, _ string) (*RRset, error) {
			return &RRset{Records: []string{QuoteTXT("existing-key")}}, nil
		},
		updateRRset: func(_ context.Context, _, _ string, records []string) error {
			updatedRecords = records
			return nil
		},
	}
	s := &Solver{newClient: func(_ string) DNSClient { return mock }}
	err := s.presentWithClient(mock, "example.com", "_acme-challenge", "new-key")
	assert.NoError(t, err)
	assert.Equal(t, []string{QuoteTXT("existing-key"), QuoteTXT("new-key")}, updatedRecords)
}

func TestPresent_SkipsDuplicateRecord(t *testing.T) {
	mock := &mockDNSClient{
		getRRset: func(_ context.Context, _, _ string) (*RRset, error) {
			return &RRset{Records: []string{QuoteTXT("already-here")}}, nil
		},
		updateRRset: func(_ context.Context, _, _ string, _ []string) error {
			t.Fatal("updateRRset should not be called for duplicate record")
			return nil
		},
	}
	s := &Solver{newClient: func(_ string) DNSClient { return mock }}
	err := s.presentWithClient(mock, "example.com", "_acme-challenge", "already-here")
	assert.NoError(t, err)
}

func TestCleanUp_RemovesOneRecordRetainsOthers(t *testing.T) {
	var updatedRecords []string
	mock := &mockDNSClient{
		getRRset: func(_ context.Context, _, _ string) (*RRset, error) {
			return &RRset{Records: []string{QuoteTXT("keep-me"), QuoteTXT("remove-me")}}, nil
		},
		updateRRset: func(_ context.Context, _, _ string, records []string) error {
			updatedRecords = records
			return nil
		},
	}
	s := &Solver{newClient: func(_ string) DNSClient { return mock }}
	err := s.cleanUpWithClient(mock, "example.com", "_acme-challenge", "remove-me")
	assert.NoError(t, err)
	assert.Equal(t, []string{QuoteTXT("keep-me")}, updatedRecords)
}

func TestCleanUp_DeletesRRsetWhenLastRecord(t *testing.T) {
	deleted := false
	mock := &mockDNSClient{
		getRRset: func(_ context.Context, _, _ string) (*RRset, error) {
			return &RRset{Records: []string{QuoteTXT("last-one")}}, nil
		},
		deleteRRset: func(_ context.Context, _, _ string) error {
			deleted = true
			return nil
		},
	}
	s := &Solver{newClient: func(_ string) DNSClient { return mock }}
	err := s.cleanUpWithClient(mock, "example.com", "_acme-challenge", "last-one")
	assert.NoError(t, err)
	assert.True(t, deleted)
}

func TestCleanUp_NoOpWhenRRsetNotFound(t *testing.T) {
	mock := &mockDNSClient{
		getRRset: func(_ context.Context, _, _ string) (*RRset, error) {
			return nil, ErrNotFound
		},
	}
	s := &Solver{newClient: func(_ string) DNSClient { return mock }}
	err := s.cleanUpWithClient(mock, "example.com", "_acme-challenge", "nonexistent")
	assert.NoError(t, err)
}

func TestCleanUp_NoOpWhenKeyNotInRRset(t *testing.T) {
	mock := &mockDNSClient{
		getRRset: func(_ context.Context, _, _ string) (*RRset, error) {
			return &RRset{Records: []string{QuoteTXT("other-key")}}, nil
		},
		updateRRset: func(_ context.Context, _, _ string, _ []string) error {
			t.Fatal("should not update")
			return nil
		},
		deleteRRset: func(_ context.Context, _, _ string) error {
			t.Fatal("should not delete")
			return nil
		},
	}
	s := &Solver{newClient: func(_ string) DNSClient { return mock }}
	err := s.cleanUpWithClient(mock, "example.com", "_acme-challenge", "not-present")
	assert.NoError(t, err)
}
