package desec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// do executes an HTTP request with auth header and single-retry on 429.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Token "+c.token)
	if req.Header.Get("Content-Type") == "" && req.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("desec API request failed: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		resp.Body.Close()
		wait := parseRetryAfter(resp.Header.Get("Retry-After"))
		select {
		case <-time.After(wait):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		if req.GetBody != nil {
			req.Body, _ = req.GetBody()
		}
		resp, err = c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("desec API retry failed: %w", err)
		}
	}

	return resp, nil
}

func parseRetryAfter(value string) time.Duration {
	if value == "" {
		return 1 * time.Second
	}
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds < 0 {
		return 1 * time.Second
	}
	if seconds > maxRetryAfter {
		seconds = maxRetryAfter
	}
	return time.Duration(seconds) * time.Second
}

// rrsetURL builds the URL for a specific RRset endpoint.
// Empty subname uses "..." per DeSEC docs to avoid URL normalization issues.
func (c *Client) rrsetURL(domain, subname string) string {
	sub := subname
	if sub == "" {
		sub = "..."
	}
	return fmt.Sprintf("%s/api/v1/domains/%s/rrsets/%s/TXT/", c.baseURL, domain, sub)
}

func (c *Client) rrsetCollectionURL(domain string) string {
	return fmt.Sprintf("%s/api/v1/domains/%s/rrsets/", c.baseURL, domain)
}

func (c *Client) GetRRset(ctx context.Context, domain, subname string) (*RRset, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.rrsetURL(domain, subname), nil)
	if err != nil {
		return nil, fmt.Errorf("building GET request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("desec API error (GET %d): %s", resp.StatusCode, string(body))
	}

	var rrset RRset
	if err := json.NewDecoder(resp.Body).Decode(&rrset); err != nil {
		return nil, fmt.Errorf("decoding RRset response: %w", err)
	}
	return &rrset, nil
}
