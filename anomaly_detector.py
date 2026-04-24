import json
import os
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

MODEL_PATH = os.path.join(os.getcwd(), "data", "anomaly_model.pkl")
SCALER_PATH = os.path.join(os.getcwd(), "data", "anomaly_scaler.pkl")
KEYSTROKE_PATH = os.path.join(os.getcwd(), "data", "keystrokes.json")

def load_keystroke_data():
    if not os.path.exists(KEYSTROKE_PATH):
        return None
    with open(KEYSTROKE_PATH, "r") as f:
        data = json.load(f)
    return data

def extract_features(data):
    features = []
    for entry in data:
        features.append([
            entry["inter_key_delay"],
            entry["burst_length"],
            1 if entry["key_type"] == "alphanum" else (2 if entry["key_type"] == "special" else 3)
        ])
    return np.array(features)

def train_model(contamination=0.05):
    data = load_keystroke_data()
    if data is None or len(data) < 50:
        print(f"Pas assez de donnees pour entrainer le modele ({len(data) if data else 0} frappes, minimum 50)")
        return False

    features = extract_features(data)

    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)

    model = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=100
    )
    model.fit(features_scaled)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    print(f"Modele entraine sur {len(data)} frappes et sauvegarde.")
    return True

def detect_anomaly(keystroke_entry):
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        return False

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    features = extract_features([keystroke_entry])
    features_scaled = scaler.transform(features)

    prediction = model.predict(features_scaled)
    return prediction[0] == -1


if __name__ == "__main__":
    print("=== Entrainement du modele d'anomalies ===")
    success = train_model()
    if success:
        print("\nTest de detection:")
        normal = {"inter_key_delay": 0.15, "burst_length": 5, "key_type": "alphanum"}
        anomal = {"inter_key_delay": 5.0, "burst_length": 1, "key_type": "special"}
        print(f"Frappe normale => anomalie: {detect_anomaly(normal)}")
        print(f"Frappe anormale => anomalie: {detect_anomaly(anomal)}")