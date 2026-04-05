package desec

import (
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
