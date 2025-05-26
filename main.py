from multiprocessing import Process
import time
import os

def start_dashboard():
    os.system("python web/app.py")

def start_monitor():
    os.system("python realmonitor.py")

if __name__ == "__main__":
    print("[✓] Starting Ransomware Detection System...")

    # Start dashboard in one process
    dashboard_process = Process(target=start_dashboard)
    dashboard_process.start()
    print("[✓] Flask Dashboard started.")

    # Start file monitoring in another process
    monitor_process = Process(target=start_monitor)
    monitor_process.start()
    print("[✓] Real-time File Monitor started.")

    try:
        # Keep the main process alive
        dashboard_process.join()
        monitor_process.join()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down...")
        dashboard_process.terminate()
        monitor_process.terminate()
        dashboard_process.join()
        monitor_process.join()
        print("✅ Shutdown complete.")
