import os
from dotenv import load_dotenv
import psycopg2
from datetime import datetime

# Load environment variables from .env file
load_dotenv()

# PostgreSQL (Supabase) connection config from environment
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")

# Connect to Supabase PostgreSQL
try:
    conn = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT
    )
    cursor = conn.cursor()
    print("[✓] Connected to Supabase PostgreSQL")
except Exception as e:
    print(f"[!] Connection failed: {e}")
    exit(1)

# Log threat event
def log_threat(file_path, action_taken, processes_killed):
    timestamp = datetime.now()
    query = """
        INSERT INTO threat_logs (timestamp, file_path, action_taken, processes_killed)
        VALUES (%s, %s, %s, %s);
    """
    try:
        cursor.execute(query, (timestamp, file_path, action_taken, processes_killed))
        conn.commit()
        print("[✓] Threat logged to Supabase")
    except Exception as e:
        print(f"[!] Failed to log threat to Supabase: {e}")
        conn.rollback()

# Log monitor event
def log_monitor_event(file_path, event_type, prediction_label, prediction_proba=None):
    timestamp = datetime.now()
    prediction = "legitimate" if prediction_label == 1 else "ransomware"
    query = """
        INSERT INTO monitor_logs (timestamp, file_path, event_type, prediction, confidence)
        VALUES (%s, %s, %s, %s, %s);
    """
    try:
        cursor.execute(query, (timestamp, file_path, event_type, prediction, prediction_proba))
        conn.commit()
        print(f"[✓] File event '{event_type}' logged")
    except Exception as e:
        print(f"[!] Failed to log monitor event: {e}")
        conn.rollback()

# Optional: test log calls
if __name__ == "__main__":
    log_threat("/home/user/test.exe", "deleted", ["badproc1", "badproc2"])
    log_monitor_event("/home/user/test.docx", "open", 0, 0.87)

    # Clean up
    cursor.close()
    conn.close()
