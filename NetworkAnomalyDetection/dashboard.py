from flask import Flask, render_template
from flask_socketio import SocketIO
import os
import time
from collections import Counter
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'  # For SocketIO
socketio = SocketIO(app)

# Path to anomalies log
LOG_FILE = 'anomalies.log'

def clean_anomaly_type(text):
    """Convert Unicode escape sequences to actual characters."""
    try:
        # Decode Unicode escape sequences (e.g., \u26a0\ufe0f to ⚠️)
        return text.encode().decode('unicode_escape')
    except (UnicodeEncodeError, UnicodeDecodeError):
        return text

def parse_anomalies():
    """Parse anomalies.log to count anomalies by type and track timestamps."""
    anomaly_counts = Counter()
    anomaly_times = []
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    try:
                        timestamp_str, message = line.strip().split('] ', 1)
                        timestamp = datetime.strptime(timestamp_str[1:], '%Y-%m-%d %H:%M:%S')
                        # Extract anomaly type (e.g., "ARP Reply", "Port Scan") and clean emojis
                        anomaly_type = message.split(' from ')[0].split('⚠️ ')[-1].split('🚨 ')[-1].strip()
                        anomaly_type = clean_anomaly_type(anomaly_type)
                        anomaly_counts[anomaly_type] += 1
                        anomaly_times.append({'time': timestamp, 'type': anomaly_type})
                    except (ValueError, IndexError):
                        continue
    except FileNotFoundError:
        pass

    # Filter times for last 10 minutes
    cutoff = datetime.now() - timedelta(minutes=10)
    anomaly_times = [t for t in anomaly_times if t['time'] >= cutoff]

    return anomaly_counts, anomaly_times

def get_log_mtime():
    """Get the last modified time of anomalies.log."""
    try:
        return os.path.getmtime(LOG_FILE)
    except FileNotFoundError:
        return 0

@app.route('/')
def index():
    anomaly_counts, anomaly_times = parse_anomalies()
    return render_template('dashboard.html', anomaly_counts=anomaly_counts)

@socketio.on('connect')
def handle_connect():
    """Send initial data on client connection."""
    anomaly_counts, anomaly_times = parse_anomalies()
    socketio.emit('update', {
        'anomaly_counts': dict(anomaly_counts),
        'anomaly_times': [
            {'time': t['time'].strftime('%Y-%m-%d %H:%M:%S'), 'type': t['type']}
            for t in anomaly_times
        ]
    })

def monitor_log():
    """Monitor anomalies.log for changes and emit updates."""
    last_mtime = get_log_mtime()
    while True:
        time.sleep(1)
        current_mtime = get_log_mtime()
        if current_mtime != last_mtime:
            last_mtime = current_mtime
            anomaly_counts, anomaly_times = parse_anomalies()
            socketio.emit('update', {
                'anomaly_counts': dict(anomaly_counts),
                'anomaly_times': [
                    {'time': t['time'].strftime('%Y-%m-%d %H:%M:%S'), 'type': t['type']}
                    for t in anomaly_times
                ]
            })

if __name__ == '__main__':
    socketio.start_background_task(monitor_log)
    socketio.run(app, host='0.0.0.0', port=5000)