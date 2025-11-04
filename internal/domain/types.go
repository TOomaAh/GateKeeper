package domain

import "time"

type IPScore int

const (
	ScoreLow       IPScore = 25
	ScoreMedium    IPScore = 75
	ScoreHigh      IPScore = 100
	ScoreThreshold IPScore = 75
)

type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
)

type IPInfo struct {
	Address     string
	Score       IPScore
	Country     string
	Path        string
	PayloadPath string
	BlockedInFW bool
	Timestamp   time.Time
}

func (i *IPInfo) IsHighRisk() bool {
	return i.Score > ScoreThreshold
}

func (i *IPInfo) GetSeverity() Severity {
	switch {
	case i.Score > ScoreThreshold:
		return SeverityHigh
	case i.Score >= ScoreLow:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

func (s Severity) String() string {
	switch s {
	case SeverityHigh:
		return "High"
	case SeverityMedium:
		return "Medium"
	case SeverityLow:
		return "Low"
	default:
		return "Unknown"
	}
}

func (s Severity) GetEmoji() string {
	switch s {
	case SeverityHigh:
		return "🔴"
	case SeverityMedium:
		return "🟡"
	case SeverityLow:
		return "🟢"
	default:
		return "⚪"
	}
}
