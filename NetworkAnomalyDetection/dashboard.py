from flask import Flask, render_template
import json
from collections import defaultdict
from datetime import datetime

app = Flask(__name__)

def parse_anomalies():
    anomalies = []
    type_counts = defaultdict(int)
    with open('anomalies.log', 'r') as f:
        for line in f:
            try:
                timestamp = line[1:20]
                message = line[22:].strip()
                anomaly_type = message.split(':')[0].split('from')[0].strip()
                anomalies.append({'timestamp': timestamp, 'message': message})
                type_counts[anomaly_type] += 1
            except:
                continue
    return anomalies[-50:], dict(type_counts)  # Last 50 anomalies for performance

@app.route('/')
def dashboard():
    anomalies, type_counts = parse_anomalies()
    return render_template('dashboard.html', anomalies=anomalies, type_counts=json.dumps(type_counts))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
