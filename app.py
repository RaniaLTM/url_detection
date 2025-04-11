from fastapi import FastAPI, Query
import pickle
import re
import os
import requests
import os


# Function to download the model from Google Drive
def download_model_from_drive(file_id: str):
    # URL to download the model file from Google Drive
    URL = f"https://drive.google.com/uc?id={file_id}"
    response = requests.get(URL)
    
    if response.status_code == 200:
        with open('rf.pkl', 'wb') as f:
            f.write(response.content)
        print("Model downloaded successfully!")
    else:
        print("Failed to download the model.")
        raise Exception("Error downloading model from Google Drive.")

# Function to load the model from a local file (after downloading)
def load_model():
    if not os.path.exists('rf.pkl'):
        # If the model is not found, download it
        file_id = '1B4cCZVPUCORudafMMCqItvQUeN5s4ATU'  # Replace this with your actual Google Drive file ID
        download_model_from_drive(file_id)

    # Load the model
    with open("rf.pkl", "rb") as f:
        model = pickle.load(f)
    return model

# Initialize FastAPI app
app = FastAPI()

# Load the model at the start of the app
model = load_model()

# ======== Feature Extraction Function =========
def extract_features(url: str):
    # Extracting features based on the trained model
    features = [
        int(re.search(r"\d+\.\d+\.\d+\.\d+", url) is not None),  # use_of_ip
        int('://' in url and not url.startswith('https')),  # abnormal_url (example: http instead of https)
        url.count('.'),  # count.
        url.count('www'),  # count-www
        url.count('@'),  # count@
        url.count('/'),  # count_dir
        int('embed' in url),  # count_embed_domian (just a guess based on the name)
        int(len(url) < 20),  # short_url (example: URL length less than 20)
        int('https' in url),  # count-https
        int('http' in url),  # count-http
        url.count('%'),  # count%
        url.count('-'),  # count-
        url.count('='),  # count=
        len(url),  # url_length
        len(url.split('//')[1].split('/')[0]),  # hostname_length (length of the domain name)
        int('suspicious' in url),  # sus_url (just an example, you'd define this based on your needs)
        len(url.split('//')[1]) if '//' in url else 0,  # fd_length (could be a guess for path length)
        len(url.split('.')[-1]),  # tld_length (length of the top-level domain)
        sum(c.isdigit() for c in url),  # count-digits
        sum(c.isalpha() for c in url)  # count-letters
    ]
    
    return features

# ========= API Endpoint =========
@app.get("/check-url")
def check_url(url: str = Query(...)):
    features = extract_features(url)
    prediction = model.predict([features])[0]
    return {"url": url, "is_malicious": bool(prediction)}

@app.get("/healthz")
def health_check():
    return {"status": "ok"}






