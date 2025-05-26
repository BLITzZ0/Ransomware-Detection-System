import os
import shutil
import psutil
import json
from datetime import datetime
from response.logger import log_threat

def log_quarantine_action(file_path, action_taken, processes_killed):
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "file_path": file_path,
        "action_taken": action_taken,
        "processes_killed": processes_killed
    }

    os.makedirs("results", exist_ok=True)
    log_file_path = os.path.join("results", "quarantine_logs.jsonl")

    with open(log_file_path, "a") as logfile:
        logfile.write(json.dumps(log_entry) + "\n")

def handle_threat(file_path):
    print(f"[*] handle_threat called with: {file_path}")

    if not os.path.exists(file_path):
        print(f"[~] File already removed: {file_path}")
        return

    file_path = os.path.abspath(file_path)

    found = False
    processes_killed = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid = proc.info['pid']
            name = proc.info['name']

            # Check open files
            for f in proc.open_files():
                if os.path.abspath(f.path) == file_path:
                    print(f"[x] Killing process {pid} ({name}) [open_files]")
                    proc.kill()
                    found = True
                    processes_killed.append((pid, name))
                    break
            else:
                # Check memory maps (DLLs, loaded files)
                for mmap in proc.memory_maps():
                    if file_path in mmap.path:
                        print(f"[x] Killing process {pid} ({name}) [memory_maps]")
                        proc.kill()
                        found = True
                        processes_killed.append((pid, name))
                        break

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception as e:
            print(f"[!] Error while handling process {proc.pid}: {e}")
            continue

    if not found:
        print(f"[!] No process found using: {file_path}")

    # Move file to quarantine
    quarantine_dir = "quarantine"
    os.makedirs(quarantine_dir, exist_ok=True)

    filename = os.path.basename(file_path)
    quarantine_path = os.path.join(quarantine_dir, filename)

    try:
        shutil.move(file_path, quarantine_path)
        print(f"[+] File moved to quarantine: {quarantine_path}")
        action_taken = "Moved to quarantine"
    except Exception as e:
        print(f"[!] Failed to move file to quarantine: {e}")
        action_taken = f"Failed to move file to quarantine: {e}"

    # Log the action taken
    log_quarantine_action(file_path, action_taken, processes_killed)
    log_threat(file_path, action_taken="Moved to quarantine", processes_killed=processes_killed)
