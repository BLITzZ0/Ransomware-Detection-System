
# 🛡️ Ransomware Detection System

A Python-based ransomware detection system that monitors file activity, detects threats using a machine learning model, and logs events to a Supabase (PostgreSQL) database in real time.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Supabase-informational)

---

## 📌 Features

- ✅ Real-time file monitoring
- ✅ Ransomware detection using a trained ML model
- ✅ Automatic threat logging
- ✅ Integration with Supabase (PostgreSQL) for data storage
- ✅ Modular and scalable codebase

---

## 📁 Project Structure

```
Ransomware_Detection_Project/
│
├── database/                # Handles DB connection and logging
│   └── logger.py
│
├── model/                   # ML models and data preprocessing
│   ├── ml_model.py
│   ├── new_model.py
│   ├── feature_names.pkl
│   ├── scaler.pkl
│   ├── ransomware_model.pkl (not in repo, see GDrive)
│   └── MalwareData.csv      (not in repo, see GDrive)
│
├── monitor/                 # File activity monitoring
│   └── monitor.py
│
├── .env                     # Environment variables (not in repo)
├── .gitignore               # Git ignore config
├── README.md                # Project documentation
└── main.py                  # Entry point
```

---

## ⚙️ Installation & Setup

### 1. Clone the Repo

```bash
git clone https://github.com/BLITzZ0/Ransomware-Detection-System.git
cd Ransomware-Detection-System
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Requirements

```bash
pip install -r requirements.txt
```

> If `requirements.txt` is missing, install manually:
```bash
pip install psycopg2-binary pandas scikit-learn gdown python-dotenv
```

### 4. Set Up `.env` File

Create a `.env` file with your Supabase PostgreSQL credentials:

```env
DB_NAME=postgres
DB_USER=postgres
DB_PASSWORD=your_password
DB_HOST=db.your-supabase-instance.supabase.co
DB_PORT=5432
```

---

## 💾 Download Model & Data Files

The model and dataset are too large for GitHub and are stored externally on Google Drive.

### 🔗 [Google Drive Folder](https://drive.google.com/drive/folders/1IlDV2tzp0XSsGGAmDv3g1UmgCG19pFbl?usp=sharing)

## 🚀 Running the Project

Make sure your database is set up and reachable. Then, run:

```bash
python main.py
```

You should see output confirming:

- ✅ Connection to Supabase
- ✅ Threat and monitor logs being written

---

## 🧠 How It Works

1. **Monitoring**: Watches specified directories for file activity.
2. **Prediction**: Uses a trained ML model to classify file behavior.
3. **Logging**: Logs results to `monitor_logs` or `threat_logs` in Supabase DB.
4. **Actions**: If ransomware is detected, kills malicious processes or logs the action.

---

## 📊 Database Tables

### `monitor_logs`
| Column         | Type      |
|----------------|-----------|
| timestamp      | datetime  |
| file_path      | text      |
| event_type     | text      |
| prediction     | text      |
| confidence     | float     |

### `threat_logs`
| Column         | Type      |
|----------------|-----------|
| timestamp      | datetime  |
| file_path      | text      |
| action_taken   | text      |
| processes_killed | text[] |

---

## 📎 TODOs / Improvements

- [ ] Add GUI for monitoring status
- [ ] Dockerize the application
- [ ] Use real-time OS-level hooks for better detection
- [ ] Add email/SMS alerts on detection

---

## 🧾 License

This project is licensed under the MIT License.  
See `LICENSE` for details.

---

## 🤝 Contributing

Pull requests are welcome. For major changes, open an issue first to discuss what you would like to change.

---

## 📬 Contact

Created by [BLITzZ0](https://github.com/BLITzZ0)  [Ankit-2039](https://github.com/Ankit-2039)
For questions or feedback, open an issue on GitHub.
