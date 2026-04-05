package desec

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	ErrNotFound = errors.New("rrset not found")
)

const (
	defaultBaseURL = "https://desec.io"
	defaultTTL     = 3600
	maxRetryAfter  = 60
)

// RRset represents a DeSEC DNS resource record set.
type RRset struct {
	Subname string   `json:"subname"`
	Type    string   `json:"type"`
	Records []string `json:"records"`
	TTL     int      `json:"ttl"`
}

// DNSClient defines the interface for interacting with the DeSEC API.
type DNSClient interface {
	GetRRset(ctx context.Context, domain, subname string) (*RRset, error)
	CreateRRset(ctx context.Context, domain string, rrset RRset) error
	UpdateRRset(ctx context.Context, domain, subname string, records []string) error
	DeleteRRset(ctx context.Context, domain, subname string) error
}

// Client implements DNSClient using the DeSEC REST API.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewClient creates a Client targeting the production DeSEC API.
func NewClient(token string) *Client {
	return &Client{
		baseURL: defaultBaseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewClientWithBaseURL creates a Client with a custom base URL (for testing).
func NewClientWithBaseURL(token, baseURL string) *Client {
	c := NewClient(token)
	c.baseURL = baseURL
	return c
}

// QuoteTXT wraps a raw string in the double quotes DeSEC requires for TXT records.
func QuoteTXT(value string) string {
	return fmt.Sprintf("%q", value)
}

// UnquoteTXT strips the surrounding double quotes from a DeSEC TXT record value.
func UnquoteTXT(record string) string {
	s, err := strconv.Unquote(record)
	if err != nil {
		return strings.Trim(record, "\"")
	}
	return s
}
