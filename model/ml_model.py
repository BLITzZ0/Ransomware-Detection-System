# %%
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
import joblib

# 1. Load dataset (only if not already done)
malData=pd.read_csv(r"MalwareData.csv" , sep="|")

# 2. Drop unused columns
malData = malData.drop(['Name', 'md5'], axis=1)

# 3. Separate features and labels
X = malData.drop(['legitimate'], axis=1)
y = malData['legitimate']

# 4. Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# 5. Train the model
rf_model = RandomForestClassifier()
rf_model.fit(X_scaled, y)

# 6. Save model and scaler
joblib.dump(rf_model, 'ransomware_model.pkl')
joblib.dump(scaler, 'scaler.pkl')

print("✅ Model and Scaler saved successfully.")
