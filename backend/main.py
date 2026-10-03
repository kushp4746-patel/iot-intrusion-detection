from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import numpy as np
import pandas as pd
import xgboost as xgb
import joblib
import io

app = FastAPI(title="IoT Intrusion Detection API")

# Allow a website (HTML page) to call this API
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

# Load the files saved from the notebook
model = xgb.Booster()
model.load_model("xgb_ids.json")
scaler = joblib.load("scaler.pkl")
label_encoder = joblib.load("label_encoder.pkl")
features = joblib.load("features.pkl")

# Your old notebook names normal traffic "BenignTraffic"; the new one uses "BENIGN"
NORMAL = {"BENIGN", "BenignTraffic"}


def predict_df(df):
    missing = [c for c in features if c not in df.columns]
    if missing:
        raise HTTPException(400, f"Missing columns: {missing[:5]}")
    X = scaler.transform(df[features])
    preds = model.predict(xgb.DMatrix(X)).astype(int)
    return label_encoder.inverse_transform(preds).tolist()


@app.get("/")
def home():
    return {"status": "running"}


@app.post("/predict")
def predict(data: dict):
    """Send one traffic flow as JSON (all feature names + values)."""
    df = pd.DataFrame([data])
    missing = [c for c in features if c not in df.columns]
    if missing:
        raise HTTPException(400, f"Missing fields: {missing[:5]}")
    X = scaler.transform(df[features])
    margins = model.predict(xgb.DMatrix(X), output_margin=True)[0]
    probs = np.exp(margins - margins.max())
    probs = probs / probs.sum()
    top = [
        {
            "label": str(label_encoder.classes_[i]),
            "probability": round(float(probs[i]), 4),
        }
        for i in probs.argsort()[::-1][:3]
    ]
    label = top[0]["label"]
    return {
        "prediction": label,
        "is_attack": label not in NORMAL,
        "confidence": top[0]["probability"],
        "top": top,
    }


@app.post("/predict-csv")
async def predict_csv(file: UploadFile = File(...)):
    """Upload a CSV file of traffic flows (without the 'label' column is fine)."""
    df = pd.read_csv(io.BytesIO(await file.read()))
    labels = predict_df(df)
    summary = pd.Series(labels).value_counts().to_dict()
    return {
        "total": len(labels),
        "attacks": sum(l not in NORMAL for l in labels),
        "summary": summary,
        "predictions": labels,
    }
