package unifi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/TOomaAh/GateKeeper/internal/config"
)

const (
	// FirewallGroupName is the firewall group name used to block IPs
	FirewallGroupName = "WAN_IN"
	// SessionCookieName is the UniFi session cookie name
	SessionCookieName = "unifises"
	// DefaultSite is the default UniFi site
	DefaultSite = "default"
)

var (
	// ErrAuthenticationFailed is returned on authentication failure
	ErrAuthenticationFailed = errors.New("unifi: authentication failed")
	// ErrFirewallGroupNotFound is returned when the firewall group does not exist
	ErrFirewallGroupNotFound = errors.New("unifi: firewall group not found")
)

// Client manages interactions with the UniFi Controller API
type Client struct {
	httpClient *http.Client
	cookie     string
	username   string
	password   string
	baseURL    string
}

// FirewallGroup represents a UniFi firewall group
type FirewallGroup struct {
	ID      string   `json:"_id"`
	Name    string   `json:"name"`
	Members []string `json:"group_members"`
}

// NewClient creates a new UniFi client
func NewClient(cfg *config.UnifiConfig) *Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Required for self-signed certificates
		},
	}

	return &Client{
		httpClient: &http.Client{Transport: tr},
		username:   cfg.Username,
		password:   cfg.Password,
		baseURL:    cfg.URL,
	}
}

// Login authenticates the client with the UniFi controller
func (c *Client) Login() error {
	loginData := map[string]string{
		"username": c.username,
		"password": c.password,
	}

	data, err := json.Marshal(loginData)
	if err != nil {
		return fmt.Errorf("unifi: failed to marshal login data: %w", err)
	}

	resp, err := c.httpClient.Post(
		fmt.Sprintf("%s/api/auth/login", c.baseURL),
		"application/json",
		bytes.NewReader(data),
	)
	if err != nil {
		return fmt.Errorf("unifi: login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unifi: login failed with status %d", resp.StatusCode)
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == SessionCookieName {
			c.cookie = cookie.Value
			log.Printf("Successfully authenticated to UniFi controller at %s", c.baseURL)
			return nil
		}
	}

	return ErrAuthenticationFailed
}

// AddIPToFirewall adds an IP address to the WAN_IN firewall group
func (c *Client) AddIPToFirewall(ip string) error {
	groups, err := c.getFirewallGroups()
	if err != nil {
		return err
	}

	wanGroup := c.findFirewallGroup(groups, FirewallGroupName)
	if wanGroup == nil {
		return ErrFirewallGroupNotFound
	}

	if c.ipExistsInGroup(wanGroup, ip) {
		log.Printf("IP %s already exists in %s firewall group", ip, FirewallGroupName)
		return nil
	}

	if err := c.updateFirewallGroup(wanGroup, ip); err != nil {
		return err
	}

	log.Printf("Successfully added IP %s to UniFi %s firewall group", ip, FirewallGroupName)
	return nil
}

func (c *Client) getFirewallGroups() ([]FirewallGroup, error) {
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/firewallgroup", c.baseURL, DefaultSite)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("unifi: failed to create request: %w", err)
	}

	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: c.cookie})

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unifi: failed to get firewall groups: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unifi: API returned status %d", resp.StatusCode)
	}

	var result struct {
		Data []FirewallGroup `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("unifi: failed to parse response: %w", err)
	}

	return result.Data, nil
}

func (c *Client) findFirewallGroup(groups []FirewallGroup, name string) *FirewallGroup {
	for i := range groups {
		if groups[i].Name == name {
			return &groups[i]
		}
	}
	return nil
}

func (c *Client) ipExistsInGroup(group *FirewallGroup, ip string) bool {
	for _, member := range group.Members {
		if member == ip {
			return true
		}
	}
	return false
}

func (c *Client) updateFirewallGroup(group *FirewallGroup, ip string) error {
	group.Members = append(group.Members, ip)

	updateData := map[string]interface{}{
		"group_members": group.Members,
	}

	data, err := json.Marshal(updateData)
	if err != nil {
		return fmt.Errorf("unifi: failed to marshal update data: %w", err)
	}

	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/firewallgroup/%s", c.baseURL, DefaultSite, group.ID)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("unifi: failed to create update request: %w", err)
	}

	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: c.cookie})
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("unifi: failed to update firewall group: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unifi: update failed with status %d", resp.StatusCode)
	}

	return nil
}
