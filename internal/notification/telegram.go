package notification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"text/template"

	"github.com/TOomaAh/GateKeeper/internal/config"
	"github.com/TOomaAh/GateKeeper/internal/domain"
)

// Notifier interface for notification systems
type Notifier interface {
	Notify(info *domain.IPInfo) error
}

// TelegramNotifier manages Telegram notifications
type TelegramNotifier struct {
	config   config.TelegramNotificationConfig
	client   *http.Client
	template *template.Template
}

// TemplateData contains data for the template
type TemplateData struct {
	Emoji    string
	IP       string
	Country  string
	Score    int
	Severity string
	Blocked  string
	Path     string
}

// NewTelegramNotifier creates a new Telegram notifier
func NewTelegramNotifier(cfg config.TelegramNotificationConfig) *TelegramNotifier {
	tmpl, err := template.New("telegram").Parse(cfg.Template)
	if err != nil {
		log.Printf("Failed to parse telegram template: %v, using default", err)
		defaultTemplate := `{{.Emoji}} *Accès direct par IP détecté*

🌐 *IP:* {{.IP}}
🌍 *Pays:* {{.Country}}
📊 *Score AbuseIPDB:* {{.Score}}/100 ({{.Severity}})
🛡️ *Bloqué:* {{.Blocked}}
📂 *Path:* {{.Path}}`
		tmpl, _ = template.New("telegram").Parse(defaultTemplate)
	}

	return &TelegramNotifier{
		config:   cfg,
		client:   &http.Client{},
		template: tmpl,
	}
}

// Notify sends a Telegram notification
func (t *TelegramNotifier) Notify(info *domain.IPInfo) error {
	message, err := t.formatMessage(info)
	if err != nil {
		return fmt.Errorf("failed to format message: %w", err)
	}

	payload := map[string]any{
		"chat_id":    t.config.ChatId,
		"text":       message,
		"parse_mode": "Markdown",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal telegram payload: %w", err)
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.config.Token)
	resp, err := t.client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to send telegram notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned status %d", resp.StatusCode)
	}

	log.Printf("Telegram notification sent for IP %s (score: %d)", info.Address, info.Score)
	return nil
}

func (t *TelegramNotifier) formatMessage(info *domain.IPInfo) (string, error) {
	severity := info.GetSeverity()
	emoji := severity.GetEmoji()

	blockedStatus := "Non"
	if info.BlockedInFW {
		blockedStatus = "✓ Oui (ajouté au firewall)"
	}

	data := TemplateData{
		Emoji:    emoji,
		IP:       fmt.Sprintf("`%s`", info.Address),
		Country:  info.Country,
		Score:    int(info.Score),
		Severity: severity.String(),
		Blocked:  blockedStatus,
		Path:     info.Path,
	}

	var buf bytes.Buffer
	if err := t.template.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("template execution failed: %w", err)
	}

	return buf.String(), nil
}

// MultiNotifier sends notifications to multiple destinations
type MultiNotifier struct {
	notifiers []Notifier
}

// NewMultiNotifier creates a multi notifier
func NewMultiNotifier(configs []config.TelegramNotificationConfig) *MultiNotifier {
	notifiers := make([]Notifier, 0, len(configs))
	for _, cfg := range configs {
		notifiers = append(notifiers, NewTelegramNotifier(cfg))
	}
	return &MultiNotifier{notifiers: notifiers}
}

// Notify sends a notification to all notifiers
func (m *MultiNotifier) Notify(info *domain.IPInfo) {
	for _, notifier := range m.notifiers {
		go func(n Notifier) {
			if err := n.Notify(info); err != nil {
				log.Printf("Notification error: %v", err)
			}
		}(notifier)
	}
}
