import os
import time
import json
import joblib
import pefile
import numpy as np
import pandas as pd
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from threat_response import handle_threat
from response.logger import log_monitor_event

# Load model and scaler
model = joblib.load("model/ransomware_model.pkl")
scaler = joblib.load("model/scaler.pkl")

# Features expected by the model
feature_names = [
    'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion', 'MinorLinkerVersion',
    'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode',
    'BaseOfData', 'ImageBase', 'SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion',
    'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion',
    'MinorSubsystemVersion', 'SizeOfImage', 'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics',
    'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags',
    'NumberOfRvaAndSizes', 'SectionsNb', 'SectionsMeanEntropy', 'SectionsMinEntropy', 'SectionsMaxEntropy',
    'SectionsMeanRawsize', 'SectionsMinRawsize', 'SectionMaxRawsize', 'SectionsMeanVirtualsize',
    'SectionsMinVirtualsize', 'SectionMaxVirtualsize', 'ImportsNbDLL', 'ImportsNb', 'ImportsNbOrdinal',
    'ExportNb', 'ResourcesNb', 'ResourcesMeanEntropy', 'ResourcesMinEntropy', 'ResourcesMaxEntropy',
    'ResourcesMeanSize', 'ResourcesMinSize', 'ResourcesMaxSize', 'LoadConfigurationSize',
    'VersionInformationSize'
]

def extract_features_real_time(file_path):
    try:
        pe = pefile.PE(file_path)

        section_entropies = [s.get_entropy() for s in pe.sections] or [0]
        raw_sizes = [s.SizeOfRawData for s in pe.sections] or [0]
        virtual_sizes = [s.Misc_VirtualSize for s in pe.sections] or [0]

        res_entries, res_characteristics, res_sizes = [], [], []

        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            try:
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    data_rva = resource_lang.data.struct.OffsetToData
                                    size = resource_lang.data.struct.Size
                                    res_entries.append(resource_lang)
                                    res_characteristics.append(resource_lang.data.struct.CodePage)
                                    res_sizes.append(size)
            except Exception:
                pass

        imports = getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])
        import_count = sum(len(i.imports) for i in imports) if imports else 0
        import_ordinal_count = sum(
            1 for i in imports for imp in i.imports if hasattr(imp, 'ordinal') and imp.ordinal is not None
        ) if imports else 0

        try:
            load_config_size = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
        except AttributeError:
            load_config_size = 0

        try:
            version_info_signature = pe.VS_FIXEDFILEINFO.Signature
        except AttributeError:
            version_info_signature = 0

        features = [
            pe.FILE_HEADER.Machine,
            pe.FILE_HEADER.SizeOfOptionalHeader,
            pe.FILE_HEADER.Characteristics,
            pe.OPTIONAL_HEADER.MajorLinkerVersion,
            pe.OPTIONAL_HEADER.MinorLinkerVersion,
            pe.OPTIONAL_HEADER.SizeOfCode,
            pe.OPTIONAL_HEADER.SizeOfInitializedData,
            pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            pe.OPTIONAL_HEADER.BaseOfCode,
            getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0),
            pe.OPTIONAL_HEADER.ImageBase,
            pe.OPTIONAL_HEADER.SectionAlignment,
            pe.OPTIONAL_HEADER.FileAlignment,
            pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            pe.OPTIONAL_HEADER.MajorImageVersion,
            pe.OPTIONAL_HEADER.MinorImageVersion,
            pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            pe.OPTIONAL_HEADER.SizeOfImage,
            pe.OPTIONAL_HEADER.SizeOfHeaders,
            pe.OPTIONAL_HEADER.CheckSum,
            pe.OPTIONAL_HEADER.Subsystem,
            pe.OPTIONAL_HEADER.DllCharacteristics,
            pe.OPTIONAL_HEADER.SizeOfStackReserve,
            pe.OPTIONAL_HEADER.SizeOfStackCommit,
            pe.OPTIONAL_HEADER.SizeOfHeapReserve,
            pe.OPTIONAL_HEADER.SizeOfHeapCommit,
            pe.OPTIONAL_HEADER.LoaderFlags,
            pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
            len(pe.sections),
            np.mean(section_entropies),
            np.min(section_entropies),
            np.max(section_entropies),
            np.mean(raw_sizes),
            np.min(raw_sizes),
            np.max(raw_sizes),
            np.mean(virtual_sizes),
            np.min(virtual_sizes),
            np.max(virtual_sizes),
            len(imports),
            import_count,
            import_ordinal_count,
            len(getattr(pe.DIRECTORY_ENTRY_EXPORT, 'symbols', [])) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
            len(res_entries),
            np.mean(res_characteristics) if res_characteristics else 0,
            np.min(res_characteristics) if res_characteristics else 0,
            np.max(res_characteristics) if res_characteristics else 0,
            np.mean(res_sizes) if res_sizes else 0,
            np.min(res_sizes) if res_sizes else 0,
            np.max(res_sizes) if res_sizes else 0,
            load_config_size,
            version_info_signature
        ]

        pe.close()
        return pd.DataFrame([features], columns=feature_names)

    except Exception as e:
        print(f"⚠️ PE Parsing error: {file_path}\n   Reason: {e}")
        return pd.DataFrame([np.zeros(len(feature_names))], columns=feature_names)


def log_prediction(file_path, event_type, prediction_label, prediction_proba=None):
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "file_path": os.path.abspath(file_path),
        "event_type": event_type,
        "prediction": "legitimate" if prediction_label == 1 else "ransomware"
    }

    if prediction_proba is not None:
        log_entry["confidence"] = prediction_proba

    os.makedirs("results", exist_ok=True)
    log_file_path = os.path.join("results", "monitor_logs.jsonl")

    with open(log_file_path, "a") as logfile:
        logfile.write(json.dumps(log_entry) + "\n")


class RealTimeRansomwareDetector(FileSystemEventHandler):
    def __init__(self, model, scaler):
        self.model = model
        self.scaler = scaler
        self.last_classification_time = {}
        self.created_timestamps = {}

    def on_created(self, event):
        if not event.is_directory:
            print(f"[+] Created: {event.src_path}")
            self.created_timestamps[event.src_path] = time.time()
            self.classify_file(event.src_path, event_type="created")

    def on_modified(self, event):
        if not event.is_directory:
            if not os.path.exists(event.src_path):
                return  # File has already been quarantined or deleted
            now = time.time()
            created_time = self.created_timestamps.get(event.src_path)
            if created_time and now - created_time < 1:
                return
            last_time = self.last_classification_time.get(event.src_path, 0)
            if now - last_time > 1.5:
                print(f"[!] Modified: {event.src_path}")
                self.classify_file(event.src_path, event_type="modified")
                self.last_classification_time[event.src_path] = now



    def classify_file(self, file_path, event_type="unknown", retries=3, delay=0.5):
        try:
            if not file_path.lower().endswith(('.exe', '.dll')):
                print(f"[X] Skipped (not PE): {file_path}")
                return

            for _ in range(retries):
                try:
                    with open(file_path, 'rb') as f:
                        if f.read(2) != b'MZ':
                            print(f"[X] Skipped (invalid MZ): {file_path}")
                            return
                    break
                except PermissionError:
                    time.sleep(delay)
            else:
                print(f"❗ Skipped (locked): {file_path}")
                return

            features_df = extract_features_real_time(file_path)

            if features_df.empty or features_df.isnull().values.any():
                print("❌ Feature extraction failed.")
                return

            scaled = self.scaler.transform(features_df)
            prediction = self.model.predict(scaled)[0]
            proba = round(self.model.predict_proba(scaled)[0][prediction], 2)

            if prediction == 1:
                print("✅ Legitimate file.")
            else:
                print("🚨 RANSOMWARE ALERT!")

            log_prediction(file_path, event_type, prediction, proba)
            log_monitor_event(file_path, event_type, prediction, proba)

            if prediction == 0:
                handle_threat(file_path)

        except Exception as e:
            print(f"❗ Error: {e}")


# Start monitoring
folder_to_watch = r"testfolder"
os.makedirs(folder_to_watch, exist_ok=True)

event_handler = RealTimeRansomwareDetector(model, scaler)
observer = Observer()
observer.schedule(event_handler, folder_to_watch, recursive=True)

print(f"🔍 Monitoring started at: {folder_to_watch}")
observer.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("🛑 Monitoring interrupted.")
    observer.stop()

observer.join()
