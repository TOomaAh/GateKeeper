package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/TOomaAh/GateKeeper/internal/domain"
	_ "github.com/glebarez/go-sqlite"
)

const (
	// DefaultCleanupInterval to remove old entries
	DefaultCleanupInterval = 10 * time.Minute
)

// IPDatabase manages IP information persistence in SQLite
type IPDatabase struct {
	db  *sql.DB
	ttl time.Duration
}

// NewIPDatabase creates a new database instance
func NewIPDatabase(dbPath string, ttl time.Duration) (*IPDatabase, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// SQLite performance configuration
	if _, err := db.Exec(`
		PRAGMA journal_mode = WAL;
		PRAGMA synchronous = NORMAL;
		PRAGMA cache_size = -64000;
		PRAGMA busy_timeout = 5000;
	`); err != nil {
		return nil, fmt.Errorf("failed to configure database: %w", err)
	}

	if err := createSchema(db); err != nil {
		db.Close()
		return nil, err
	}

	ipDB := &IPDatabase{
		db:  db,
		ttl: ttl,
	}

	log.Printf("SQLite database initialized at %s", dbPath)
	return ipDB, nil
}

func createSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS ip_info (
		address TEXT PRIMARY KEY,
		score INTEGER NOT NULL,
		country TEXT NOT NULL,
		path TEXT NOT NULL,
		payload_path TEXT,
		blocked_in_fw BOOLEAN NOT NULL DEFAULT 0,
		timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_timestamp ON ip_info(timestamp);
	CREATE INDEX IF NOT EXISTS idx_score ON ip_info(score);
	CREATE INDEX IF NOT EXISTS idx_blocked ON ip_info(blocked_in_fw);
	`

	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	return nil
}

func (db *IPDatabase) Get(ip string) (*domain.IPInfo, bool) {
	query := `
		SELECT address, score, country, path, payload_path, blocked_in_fw, timestamp
		FROM ip_info
		WHERE address = ? AND datetime(timestamp, '+' || ? || ' seconds') > datetime('now')
	`

	var info domain.IPInfo
	var timestamp string
	var payloadPath sql.NullString

	err := db.db.QueryRow(query, ip, int(db.ttl.Seconds())).Scan(
		&info.Address,
		&info.Score,
		&info.Country,
		&info.Path,
		&payloadPath,
		&info.BlockedInFW,
		&timestamp,
	)

	if err == sql.ErrNoRows {
		return nil, false
	}

	if err != nil {
		log.Printf("Database Get error: %v", err)
		return nil, false
	}

	// Parse timestamp - try multiple formats
	var parsedTime time.Time
	var parseErr error

	// Try RFC3339 format first (ISO8601)
	parsedTime, parseErr = time.Parse(time.RFC3339, timestamp)
	if parseErr != nil {
		// Try SQLite default format
		parsedTime, parseErr = time.ParseInLocation("2006-01-02 15:04:05", timestamp, time.Local)
	}

	if parseErr == nil {
		info.Timestamp = parsedTime
	} else {
		log.Printf("Failed to parse timestamp '%s': %v", timestamp, parseErr)
		info.Timestamp = time.Time{}
	}

	if payloadPath.Valid {
		info.PayloadPath = payloadPath.String
	}

	return &info, true
}

func (db *IPDatabase) Set(info *domain.IPInfo) error {
	query := `
		INSERT INTO ip_info (address, score, country, path, payload_path, blocked_in_fw, timestamp, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
		ON CONFLICT(address) DO UPDATE SET
			score = excluded.score,
			country = excluded.country,
			path = excluded.path,
			payload_path = excluded.payload_path,
			blocked_in_fw = excluded.blocked_in_fw,
			updated_at = datetime('now')
		WHERE address = excluded.address
	`

	var payloadPath sql.NullString
	if info.PayloadPath != "" {
		payloadPath = sql.NullString{String: info.PayloadPath, Valid: true}
	}

	_, err := db.db.Exec(query, info.Address, info.Score, info.Country, info.Path, payloadPath, info.BlockedInFW)
	if err != nil {
		return fmt.Errorf("failed to set IP info: %w", err)
	}

	return nil
}

func (db *IPDatabase) MarkBlocked(ip string) error {
	query := `UPDATE ip_info SET blocked_in_fw = 1, updated_at = datetime('now') WHERE address = ?`

	_, err := db.db.Exec(query, ip)
	if err != nil {
		return fmt.Errorf("failed to mark IP as blocked: %w", err)
	}

	return nil
}

func (db *IPDatabase) Delete(ip string) error {
	_, err := db.db.Exec("DELETE FROM ip_info WHERE address = ?", ip)
	return err
}

func (db *IPDatabase) cleanupLoop() {
	ticker := time.NewTicker(DefaultCleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		db.cleanup()
	}
}

func (db *IPDatabase) cleanup() {
	query := `
		DELETE FROM ip_info
		WHERE datetime(timestamp, '+' || ? || ' seconds') < datetime('now')
	`

	result, err := db.db.Exec(query, int(db.ttl.Seconds()))
	if err != nil {
		log.Printf("Cleanup error: %v", err)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		log.Printf("Cleaned up %d expired IP entries from database", rowsAffected)
		db.db.Exec("PRAGMA optimize")
	}
}

func (db *IPDatabase) GetStats() (Stats, error) {
	var stats Stats

	err := db.db.QueryRow("SELECT COUNT(*) FROM ip_info").Scan(&stats.TotalEntries)
	if err != nil {
		return stats, err
	}

	err = db.db.QueryRow("SELECT COUNT(*) FROM ip_info WHERE blocked_in_fw = 1").Scan(&stats.BlockedEntries)
	if err != nil {
		return stats, err
	}

	query := `
		SELECT COUNT(*)
		FROM ip_info
		WHERE datetime(timestamp, '+' || ? || ' seconds') > datetime('now')
	`
	err = db.db.QueryRow(query, int(db.ttl.Seconds())).Scan(&stats.ActiveEntries)
	if err != nil {
		return stats, err
	}

	err = db.db.QueryRow("SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()").Scan(&stats.DBSize)
	if err != nil {
		return stats, err
	}

	return stats, nil
}

// Stats contains database statistics
type Stats struct {
	TotalEntries   int64
	ActiveEntries  int64
	BlockedEntries int64
	DBSize         int64
}

// GetAllIPs returns all IP entries from the database
func (db *IPDatabase) GetAllIPs() ([]*domain.IPInfo, error) {
	query := `
		SELECT address, score, country, path, payload_path, blocked_in_fw, timestamp
		FROM ip_info
		ORDER BY timestamp DESC
		LIMIT 100
	`

	rows, err := db.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []*domain.IPInfo
	for rows.Next() {
		var info domain.IPInfo
		var timestamp string
		var payloadPath sql.NullString

		err := rows.Scan(
			&info.Address,
			&info.Score,
			&info.Country,
			&info.Path,
			&payloadPath,
			&info.BlockedInFW,
			&timestamp,
		)
		if err != nil {
			continue
		}

		// Parse timestamp - try multiple formats
		var parsedTime time.Time
		var parseErr error

		// Try RFC3339 format first (ISO8601)
		parsedTime, parseErr = time.Parse(time.RFC3339, timestamp)
		if parseErr != nil {
			// Try SQLite default format
			parsedTime, parseErr = time.ParseInLocation("2006-01-02 15:04:05", timestamp, time.Local)
		}

		if parseErr == nil {
			info.Timestamp = parsedTime
		} else {
			log.Printf("Failed to parse timestamp '%s': %v", timestamp, parseErr)
			info.Timestamp = time.Time{}
		}

		if payloadPath.Valid {
			info.PayloadPath = payloadPath.String
		}

		ips = append(ips, &info)
	}

	return ips, nil
}

func (db *IPDatabase) Close() error {
	db.db.Exec("VACUUM")
	return db.db.Close()
}

func (db *IPDatabase) Vacuum() error {
	log.Println("Running database VACUUM...")
	_, err := db.db.Exec("VACUUM")
	if err != nil {
		return fmt.Errorf("vacuum failed: %w", err)
	}
	log.Println("VACUUM completed")
	return nil
}
