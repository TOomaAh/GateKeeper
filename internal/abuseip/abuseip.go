package abuseip

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/TOomaAh/GateKeeper/internal/domain"
)

const (
	// AbuseIPDBAPIURL is the base URL of the AbuseIPDB API
	AbuseIPDBAPIURL = "https://api.abuseipdb.com/api/v2/check"
)

var (
	// ErrEmptyAPIKey is returned when the API key is empty
	ErrEmptyAPIKey = errors.New("abuseipdb: API key is empty")
	// ErrInvalidResponse is returned when the API response is invalid
	ErrInvalidResponse = errors.New("abuseipdb: invalid API response")
)

// Client manages requests to the AbuseIPDB API
type Client struct {
	apiKey     string
	httpClient *http.Client
}

// Response represents the AbuseIPDB API response
type Response struct {
	Data struct {
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		CountryCode          string `json:"countryCode"`
		IsWhitelisted        bool   `json:"isWhitelisted"`
		TotalReports         int    `json:"totalReports"`
	} `json:"data"`
}

// NewClient creates a new AbuseIPDB client
func NewClient(apiKey string) (*Client, error) {
	if apiKey == "" {
		return nil, ErrEmptyAPIKey
	}

	return &Client{
		apiKey:     apiKey,
		httpClient: &http.Client{},
	}, nil
}

// Check verifies the reputation score of an IP address
func (c *Client) Check(ip string) (domain.IPScore, string, error) {

	if i := net.ParseIP(ip); i.IsPrivate() || i.IsLoopback() {
		return 0, "", fmt.Errorf("abuseipdb: ip is private")
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s?ipAddress=%s", AbuseIPDBAPIURL, ip), nil)
	if err != nil {
		return 0, "", fmt.Errorf("abuseipdb: failed to create request: %w", err)
	}

	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("abuseipdb: API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("abuseipdb: API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", fmt.Errorf("abuseipdb: failed to read response: %w", err)
	}

	var result Response
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, "", fmt.Errorf("abuseipdb: failed to parse response: %w", err)
	}

	return domain.IPScore(result.Data.AbuseConfidenceScore), result.Data.CountryCode, nil
}
