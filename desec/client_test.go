package desec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	c := NewClient("test-token")
	assert.Equal(t, defaultBaseURL, c.baseURL)
	assert.Equal(t, "test-token", c.token)
	assert.NotNil(t, c.httpClient)
}

func TestNewClientWithBaseURL(t *testing.T) {
	c := NewClientWithBaseURL("tok", "http://localhost:8080")
	assert.Equal(t, "http://localhost:8080", c.baseURL)
	assert.Equal(t, "tok", c.token)
}

func TestQuoteTXT(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", `"hello"`},
		{"challenge-key-abc123", `"challenge-key-abc123"`},
		{"", `""`},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, QuoteTXT(tt.input))
	}
}

func TestUnquoteTXT(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`"hello"`, "hello"},
		{`"challenge-key-abc123"`, "challenge-key-abc123"},
		{`""`, ""},
		{"noquotes", "noquotes"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, UnquoteTXT(tt.input))
	}
}

func TestClientSendsAuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClientWithBaseURL("my-secret-token", srv.URL)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/test", nil)
	_, _ = c.do(req)
	assert.Equal(t, "Token my-secret-token", gotAuth)
}

func TestClientRetriesOn429(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClientWithBaseURL("tok", srv.URL)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/test", nil)
	resp, err := c.do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, attempts)
	resp.Body.Close()
}

func TestClientFailsAfterSecond429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := NewClientWithBaseURL("tok", srv.URL)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/test", nil)
	resp, err := c.do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	resp.Body.Close()
}

func TestGetRRset_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/domains/example.com/rrsets/_acme-challenge/TXT/", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(RRset{
			Subname: "_acme-challenge",
			Type:    "TXT",
			Records: []string{`"existing-value"`},
			TTL:     3600,
		})
	}))
	defer srv.Close()

	c := NewClientWithBaseURL("tok", srv.URL)
	rrset, err := c.GetRRset(context.Background(), "example.com", "_acme-challenge")
	assert.NoError(t, err)
	assert.Equal(t, "_acme-challenge", rrset.Subname)
	assert.Equal(t, []string{`"existing-value"`}, rrset.Records)
}

func TestGetRRset_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewClientWithBaseURL("tok", srv.URL)
	_, err := c.GetRRset(context.Background(), "example.com", "_acme-challenge")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestGetRRset_EmptySubname(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/domains/example.com/rrsets/.../TXT/", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(RRset{})
	}))
	defer srv.Close()

	c := NewClientWithBaseURL("tok", srv.URL)
	_, err := c.GetRRset(context.Background(), "example.com", "")
	assert.NoError(t, err)
}
