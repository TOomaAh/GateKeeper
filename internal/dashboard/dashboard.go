package dashboard

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/TOomaAh/GateKeeper/internal/config"
	"github.com/TOomaAh/GateKeeper/internal/database"
)

// Dashboard manages the web dashboard
type Dashboard struct {
	config *config.Configuration
	db     *database.IPDatabase
}

// NewDashboard creates a new dashboard instance
func NewDashboard(cfg *config.Configuration, db *database.IPDatabase) *Dashboard {
	return &Dashboard{
		config: cfg,
		db:     db,
	}
}

// Run starts the dashboard HTTP server
func (d *Dashboard) Run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", d.handleIndex)
	mux.HandleFunc("/api/stats", d.handleStats)
	mux.HandleFunc("/api/ips", d.handleIPs)

	log.Printf("Dashboard listening on %s", d.config.Dashboard.Port)
	return http.ListenAndServe(d.config.Dashboard.Port, mux)
}

func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("dashboard").Parse(dashboardHTML))
	tmpl.Execute(w, nil)
}

type StatsResponse struct {
	DatabaseStats database.Stats `json:"database_stats"`
	Uptime        string         `json:"uptime"`
	Timestamp     string         `json:"timestamp"`
}

func (d *Dashboard) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := d.db.GetStats()
	if err != nil {
		http.Error(w, "Failed to get stats", http.StatusInternalServerError)
		return
	}

	response := StatsResponse{
		DatabaseStats: stats,
		Uptime:        time.Since(startTime).Round(time.Second).String(),
		Timestamp:     time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

type IPResponse struct {
	Address     string `json:"address"`
	Score       int    `json:"score"`
	Country     string `json:"country"`
	Path        string `json:"path"`
	PayloadPath string `json:"payload_path,omitempty"`
	BlockedInFW bool   `json:"blocked_in_fw"`
	Timestamp   string `json:"timestamp"`
}

func (d *Dashboard) handleIPs(w http.ResponseWriter, r *http.Request) {
	ips, err := d.db.GetAllIPs()
	if err != nil {
		http.Error(w, "Failed to get IPs", http.StatusInternalServerError)
		return
	}

	// Convert to response format with RFC3339 timestamps
	response := make([]IPResponse, len(ips))
	for i, ip := range ips {
		response[i] = IPResponse{
			Address:     ip.Address,
			Score:       int(ip.Score),
			Country:     ip.Country,
			Path:        ip.Path,
			PayloadPath: ip.PayloadPath,
			BlockedInFW: ip.BlockedInFW,
			Timestamp:   ip.Timestamp.Format(time.RFC3339),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

var startTime = time.Now()

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GateKeeper Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0a;
            min-height: 100vh;
            padding: 40px 20px;
            color: #fff;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        header {
            margin-bottom: 60px;
            border-bottom: 1px solid #222;
            padding-bottom: 30px;
        }
        h1 {
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 8px;
            background: linear-gradient(135deg, #fff 0%, #888 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .subtitle {
            font-size: 0.95em;
            color: #666;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 24px;
            margin-bottom: 40px;
        }
        .stat-card {
            background: linear-gradient(135deg, #1a1a1a 0%, #0f0f0f 100%);
            border: 1px solid #222;
            border-radius: 16px;
            padding: 32px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent, #fff, transparent);
            opacity: 0;
            transition: opacity 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-4px);
            border-color: #333;
            box-shadow: 0 20px 40px rgba(0,0,0,0.5);
        }
        .stat-card:hover::before {
            opacity: 0.5;
        }
        .stat-label {
            color: #888;
            font-size: 0.75em;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin-bottom: 16px;
            font-weight: 600;
        }
        .stat-value {
            font-size: 3em;
            font-weight: 700;
            background: linear-gradient(135deg, #fff 0%, #999 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            line-height: 1;
        }
        .stat-icon {
            font-size: 2.5em;
            margin-bottom: 16px;
            opacity: 0.8;
        }
        .info-card {
            background: linear-gradient(135deg, #1a1a1a 0%, #0f0f0f 100%);
            border: 1px solid #222;
            border-radius: 16px;
            padding: 32px;
            backdrop-filter: blur(10px);
        }
        .info-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            border-bottom: 1px solid #1a1a1a;
        }
        .info-row:last-child {
            border-bottom: none;
        }
        .info-label {
            color: #888;
            font-weight: 500;
            font-size: 0.95em;
        }
        .info-value {
            color: #fff;
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
        }
        .loading {
            text-align: center;
            color: #666;
            font-size: 1.2em;
            padding: 60px;
        }
        .db-size {
            font-size: 0.85em;
            color: #666;
            margin-top: 8px;
            font-weight: 500;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .loading {
            animation: pulse 2s ease-in-out infinite;
        }
        .ip-table-container {
            background: linear-gradient(135deg, #1a1a1a 0%, #0f0f0f 100%);
            border: 1px solid #222;
            border-radius: 16px;
            padding: 32px;
            margin-top: 40px;
            overflow-x: auto;
        }
        .ip-table-header {
            font-size: 1.5em;
            font-weight: 600;
            margin-bottom: 24px;
            color: #fff;
        }
        .ip-table {
            width: 100%;
            border-collapse: collapse;
        }
        .ip-table th {
            text-align: left;
            padding: 16px;
            color: #888;
            font-size: 0.75em;
            text-transform: uppercase;
            letter-spacing: 1px;
            border-bottom: 1px solid #222;
            font-weight: 600;
        }
        .ip-table td {
            padding: 16px;
            border-bottom: 1px solid #1a1a1a;
            color: #ccc;
        }
        .ip-table tr:hover {
            background: rgba(255,255,255,0.02);
        }
        .ip-address {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 600;
            color: #fff;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-blocked {
            background: #ff4444;
            color: #fff;
        }
        .badge-active {
            background: #44ff44;
            color: #000;
        }
        .score-high {
            color: #ff4444;
            font-weight: 700;
        }
        .score-medium {
            color: #ffaa44;
            font-weight: 600;
        }
        .score-low {
            color: #44ff44;
            font-weight: 500;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ GateKeeper</h1>
            <div class="subtitle">Security Dashboard</div>
        </header>

        <div id="loading" class="loading">Loading statistics...</div>

        <div id="dashboard" style="display:none;">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon">📊</div>
                    <div class="stat-label">Total IPs</div>
                    <div class="stat-value" id="total-ips">-</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">⚡</div>
                    <div class="stat-label">Active Entries</div>
                    <div class="stat-value" id="active-entries">-</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">🛡️</div>
                    <div class="stat-label">Blocked IPs</div>
                    <div class="stat-value" id="blocked-ips">-</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">💾</div>
                    <div class="stat-label">Database Size</div>
                    <div class="stat-value" id="db-size">-</div>
                    <div class="db-size" id="db-size-bytes"></div>
                </div>
            </div>

            <div class="info-card">
                <div class="info-row">
                    <div class="info-label">System Uptime</div>
                    <div class="info-value" id="uptime">-</div>
                </div>
                <div class="info-row">
                    <div class="info-label">Last Updated</div>
                    <div class="info-value" id="timestamp">-</div>
                </div>
            </div>

            <div class="ip-table-container">
                <div class="ip-table-header">📋 Recent IP Activity</div>
                <table class="ip-table">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Score</th>
                            <th>Country</th>
                            <th>Path</th>
                            <th>Status</th>
                            <th>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody id="ip-table-body">
                        <tr>
                            <td colspan="6" style="text-align:center; color: #666;">Loading...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
        }

        function formatNumber(num) {
            return num.toLocaleString();
        }

        function updateStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('loading').style.display = 'none';
                    document.getElementById('dashboard').style.display = 'block';

                    document.getElementById('total-ips').textContent = formatNumber(data.database_stats.TotalEntries);
                    document.getElementById('active-entries').textContent = formatNumber(data.database_stats.ActiveEntries);
                    document.getElementById('blocked-ips').textContent = formatNumber(data.database_stats.BlockedEntries);

                    const dbSize = formatBytes(data.database_stats.DBSize);
                    const sizeValue = dbSize.split(' ')[0];
                    const sizeUnit = dbSize.split(' ')[1];
                    document.getElementById('db-size').textContent = sizeValue;
                    document.getElementById('db-size-bytes').textContent = sizeUnit;

                    document.getElementById('uptime').textContent = data.uptime;
                    document.getElementById('timestamp').textContent = new Date(data.timestamp).toLocaleString();
                })
                .catch(error => {
                    console.error('Error fetching stats:', error);
                });
        }

        function getScoreClass(score) {
            if (score >= 75) return 'score-high';
            if (score >= 25) return 'score-medium';
            return 'score-low';
        }

        function updateIPTable() {
            fetch('/api/ips')
                .then(response => response.json())
                .then(data => {
                    const tbody = document.getElementById('ip-table-body');
                    if (!data || data.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: #666;">No IP entries found</td></tr>';
                        return;
                    }

                    tbody.innerHTML = data.map(ip => {
                        const timestamp = new Date(ip.timestamp).toLocaleString();
                        const scoreClass = getScoreClass(ip.score);
                        const statusBadge = ip.blocked_in_fw
                            ? '<span class="badge badge-blocked">Blocked</span>'
                            : '<span class="badge badge-active">Active</span>';

                        return ` + "`" + `
                            <tr>
                                <td class="ip-address">${ip.address}</td>
                                <td class="${scoreClass}">${ip.score}</td>
                                <td>${ip.country || 'Unknown'}</td>
                                <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;">${ip.path}</td>
                                <td>${statusBadge}</td>
                                <td>${timestamp}</td>
                            </tr>
                        ` + "`" + `;
                    }).join('');
                })
                .catch(error => {
                    console.error('Error fetching IPs:', error);
                });
        }

        // Update stats every 5 seconds
        updateStats();
        setInterval(updateStats, 5000);

        // Update IP table every 10 seconds
        updateIPTable();
        setInterval(updateIPTable, 10000);
    </script>
</body>
</html>`
