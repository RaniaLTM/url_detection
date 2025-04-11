# app.py
from fastapi import FastAPI, Query
from pydantic import BaseModel
import pickle
import re

# Load your trained model
with open("rf.pkl", "rb") as f:
    model = pickle.load(f)

app = FastAPI()

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

# You must match this structure to your original training data features.

# ========= API Endpoint =========
@app.get("/check-url")
def check_url(url: str = Query(...)):
    features = extract_features(url)
    prediction = model.predict([features])[0]
    return {"url": url, "is_malicious": bool(prediction)}
