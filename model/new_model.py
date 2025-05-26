# %%
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
import joblib

# Load dataset
df = pd.read_csv("MalwareData.csv", sep="|")

# Drop unused columns
df.drop(columns=["Name", "md5"], inplace=True)

# Features and labels
X = df.drop(columns=["legitimate"])
y = df["legitimate"]

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split data (70% train, 30% test)
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.3, stratify=y, random_state=42
)

# Train optimized model
rf_model = RandomForestClassifier(
    n_estimators=1200,
    max_depth=None,
    min_samples_split=3,
    min_samples_leaf=1,
    max_features='log2',
    bootstrap=True,
    class_weight='balanced_subsample',
    n_jobs=-1,
    random_state=42
)
rf_model.fit(X_train, y_train)

# Evaluation
print("Evaluating model...")
y_pred = rf_model.predict(X_test)

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
cm = confusion_matrix(y_test, y_pred)


print(f"Accuracy: {acc:.4f}")
print(f"Precision: {prec:.4f}")
print(f"Recall: {rec:.4f}")
print(f"F1 Score: {f1:.4f}")
print("Confusion Matrix:")
print(cm)

# Save model & scaler
joblib.dump(rf_model, "ransomware_model.pkl")
joblib.dump(scaler, "scaler.pkl")

print(f"Model and Scaler saved")
