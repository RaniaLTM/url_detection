from fastapi import FastAPI, Query
import pickle
import re
import os
import requests
from dotenv import load_dotenv

# ========== Load environment variables ==========
load_dotenv("/etc/secrets/.env")  # Render secret mount point

# ========== Get the file ID from the environment ==========
file_id = os.getenv("MODEL_FILE_ID")  # Make sure to define this in Render secret env file

# ========== Google Drive Download Helper ==========
def download_model_from_drive(file_id: str):
    print("Attempting to download model from Google Drive...")
    URL = "https://docs.google.com/uc?export=download"
    session = requests.Session()
    response = session.get(URL, params={'id': file_id}, stream=True)

    # Confirm token for large files
    def get_confirm_token(resp):
        for key, value in resp.cookies.items():
            if key.startswith('download_warning'):
                return value
        return None

    token = get_confirm_token(response)
    if token:
        response = session.get(URL, params={'id': file_id, 'confirm': token}, stream=True)

    # Save to rf.pkl
    with open("rf.pkl", "wb") as f:
        for chunk in response.iter_content(32768):
            if chunk:
                f.write(chunk)

    print("✅ Model downloaded successfully.")

# ========== Model Loader ==========
def load_model():
    if not os.path.exists("rf.pkl"):
        if not file_id:
            raise Exception("❌ MODEL_FILE_ID is not set in .env")
        download_model_from_drive(file_id)

    with open("rf.pkl", "rb") as f:
        return pickle.load(f)

# ========== Initialize App ==========
app = FastAPI()
model = load_model()

# ========== Feature Extraction ==========
def extract_features(url: str):
    features = [
        int(re.search(r"\d+\.\d+\.\d+\.\d+", url) is not None),  # use_of_ip
        int('://' in url and not url.startswith('https')),       # abnormal_url
        url.count('.'),
        url.count('www'),
        url.count('@'),
        url.count('/'),
        int('embed' in url),
        int(len(url) < 20),
        int('https' in url),
        int('http' in url),
        url.count('%'),
        url.count('-'),
        url.count('='),
        len(url),
        len(url.split('//')[1].split('/')[0]) if '//' in url else 0,
        int('suspicious' in url),
        len(url.split('//')[1]) if '//' in url else 0,
        len(url.split('.')[-1]),
        sum(c.isdigit() for c in url),
        sum(c.isalpha() for c in url)
    ]
    return features

# ========== API Routes ==========
@app.get("/check-url")
def check_url(url: str = Query(...)):
    features = extract_features(url)
    prediction = model.predict([features])[0]
    return {"url": url, "is_malicious": bool(prediction)}

@app.get("/healthz")
def health_check():
    return {"status": "ok"}
