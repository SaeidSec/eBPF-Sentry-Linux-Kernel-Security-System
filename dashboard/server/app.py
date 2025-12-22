from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import datetime
import os

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

DB_FILE = "sentry_logs.db"

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                log_type TEXT,
                severity TEXT,
                rule_name TEXT,
                process TEXT,
                details TEXT,
                raw_data TEXT
            )
        ''')
        conn.commit()

@app.route('/api/login', methods=['POST'])
def login():
    # Mock login for demo purposes
    return jsonify({"token": "mock-jwt-token-sentry-123456"})

@app.route('/api/logs', methods=['POST'])
def ingest_logs():
    data = request.json
    log_type = data.get('logType', 'unknown')
    log_data = data.get('logData', {})
    timestamp = data.get('timestamp') or datetime.datetime.utcnow().isoformat()

    # Extract common fields based on log type
    severity = log_data.get('severity', 'info')
    rule_name = log_data.get('rule_name', 'Unknown')
    process = log_data.get('process') or log_data.get('process_name') or 'N/A'
    details = log_data.get('details') or log_data.get('info') or ''
    
    if log_type == 'ips':
        severity = 'high' # IPS actions are usually high
        rule_name = log_data.get('rule') or rule_name
        details = f"[BLOCKED] {log_data.get('info')}"

    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('''
            INSERT INTO logs (timestamp, log_type, severity, rule_name, process, details, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, log_type, severity, rule_name, process, details, str(log_data)))
        conn.commit()

    return jsonify({"status": "received"}), 201

@app.route('/api/stats', methods=['GET'])
def get_stats():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        
        # Total events
        c.execute("SELECT COUNT(*) FROM logs")
        total_events = c.fetchone()[0]
        
        # Severity breakdown
        c.execute("SELECT severity, COUNT(*) FROM logs GROUP BY severity")
        severity_counts = {row[0].lower(): row[1] for row in c.fetchall()} # e.g. {'high': 5, 'info': 10}

        # Recent trend (last 24h - mocked as just recent events for simplicity or limited sql)
        # For a real chart, we'd group by hour. Let's send simple breakdown for now.

    stats = {
        "total_events": total_events,
        "high": severity_counts.get('high', 0),
        "medium": severity_counts.get('medium', 0),
        "low": severity_counts.get('low', 0) + severity_counts.get('info', 0), # grouping info as low
    }
    return jsonify(stats)

@app.route('/api/events', methods=['GET'])
def get_events():
    limit = request.args.get('limit', 50)
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,))
        rows = [dict(row) for row in c.fetchall()]
    return jsonify(rows)

if __name__ == '__main__':
    init_db()
    print("eBPF-Sentry Dashboard Backend Running on :5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
