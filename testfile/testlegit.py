import shutil
import os

# Folder where the clean files will be copied
test_folder = r"testfolder"

# List of known clean files with full paths
known_clean_files = [
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\System32\calc.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\kernel32.dll",
    r"C:\Windows\System32\user32.dll",
    r"C:\Windows\System32\gdi32.dll"
]

# Copy each file if it exists
for file_path in known_clean_files:
    try:
        if os.path.exists(file_path):
            dest_path = os.path.join(test_folder, os.path.basename(file_path))
            shutil.copy2(file_path, dest_path)
            print(f"✅ Copied: {file_path} ➜ {dest_path}")
        else:
            print(f"⚠️ File not found: {file_path}")
    except Exception as e:
        print(f"❌ Error copying {file_path}: {e}")
