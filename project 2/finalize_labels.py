import pandas as pd
import json
import re
from pathlib import Path

PARTIALLY_LABELED_FILE = r"C:your/path/here/partially_labeled_data.csv"
VT_CACHE_FILE = "vt_results_cache.json"
FULLY_LABELED_FILE = r"C:your/path/here/fully_labeled_data.csv"

def load_vt_results():
    """Load VirusTotal results from cache if available, otherwise return an empty dict."""
    if Path(VT_CACHE_FILE).exists():
        with open(VT_CACHE_FILE, "r") as f:
            return json.load(f)
    print("VirusTotal cache not found. Proceeding with default safe labels (0) for all URLs.")
    return {}  # Return an empty dictionary if the file doesn't exist

def apply_vt_labels(df, vt_cache):
    """Label emails based on VirusTotal URL checks with default safe labels."""
    # Default all URL labels to 0 (safe)
    df["url_label"] = 0

    # Update URL labels to 1 only for URLs marked as malicious in VT cache
    def url_phishing_label(text):
        url_pattern = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
        urls = re.findall(url_pattern, text)
        return any(vt_cache.get(url) is True for url in urls)

    df["url_label"] = df["text"].apply(url_phishing_label).astype(int)

    # Set the final label: 1 if either keyword or URL indicates phishing, else 0
    df["label"] = df[["keyword_label", "url_label"]].max(axis=1)
    return df

def finalize_labels():
    """Combine keyword-based and URL-based labels to finalize data."""
    vt_cache = load_vt_results()  # Load VT results or an empty dict if absent
    df = pd.read_csv(PARTIALLY_LABELED_FILE)
    df = apply_vt_labels(df, vt_cache)
    df.to_csv(FULLY_LABELED_FILE, index=False)
    print(f"Fully labeled data saved to {FULLY_LABELED_FILE}.")

