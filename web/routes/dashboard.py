from flask import Blueprint, render_template, jsonify
from pymongo import MongoClient

dashboard = Blueprint("dashboard", __name__)

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client["ransomware_detection"]
threat_collection = db["threat_logs"]
monitor_collection = db["monitor_logs"]

@dashboard.route("/")
def index():
    threat_logs = list(threat_collection.find().sort("timestamp", -1))
    monitor_logs = list(monitor_collection.find().sort("timestamp", -1))
    return render_template("index.html", threat_logs=threat_logs, monitor_logs=monitor_logs)

@dashboard.route("/api/logs")
def api_logs():
    threat_logs = list(threat_collection.find().sort("timestamp", -1))
    monitor_logs = list(monitor_collection.find().sort("timestamp", -1))

    # Convert ObjectId and datetime fields to string for JSON serialization
    for log in threat_logs + monitor_logs:
        log["_id"] = str(log["_id"])
        if "timestamp" in log and not isinstance(log["timestamp"], str):
            log["timestamp"] = log["timestamp"].strftime("%Y-%m-%d %H:%M:%S")

    return jsonify({
        "threat_logs": threat_logs,
        "monitor_logs": monitor_logs
    })
