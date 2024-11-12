import pandas as pd
import re
import vt
import time
import json
from pathlib import Path
from datetime import datetime

# Paths for caching and tracking files
CACHE_FILE = "vt_cache.json"
LOOKUP_TRACKER_FILE = "lookup_tracker.json"

# Load or initialize a cache to avoid duplicate lookups
if Path(CACHE_FILE).exists():
    with open(CACHE_FILE, "r") as f:
        vt_cache = json.load(f)
else:
    vt_cache = {}

if Path(LOOKUP_TRACKER_FILE).exists():
    with open(LOOKUP_TRACKER_FILE, "r") as f:
        lookup_tracker = json.load(f)
else:
    lookup_tracker = {"monthly_count": 0, "last_reset": str(datetime.now().date())}

# Save cache to file
def save_cache():
    with open(CACHE_FILE, "w") as f:
        json.dump(vt_cache, f)

# Save lookup tracker to file
def save_lookup_tracker():
    with open(LOOKUP_TRACKER_FILE, "w") as f:
        json.dump(lookup_tracker, f)

def reset_monthly_count():
    current_date = str(datetime.now().date())
    if lookup_tracker["last_reset"][:7] != current_date[:7]:  # Check if it's a new month
        lookup_tracker["monthly_count"] = 0
        lookup_tracker["last_reset"] = current_date
        save_lookup_tracker()

# VirusTotal check function
def check_url_virustotal(url, api_key):
    reset_monthly_count()
    
    # Check if the URL is already in the cache
    if url in vt_cache:
        return vt_cache[url]
    
    # Check if monthly limit is reached
    if lookup_tracker["monthly_count"] >= 15500:
        print("Monthly VirusTotal lookup limit reached.")
        return False

    with vt.Client(api_key) as client:
        try:
            # Standardize and fetch URL information
            url_id = vt.url_id(url)
            url_info = client.get_object(f"/urls/{url_id}")
            positives = url_info.last_analysis_stats['malicious']
            is_malicious = positives > 0  # True if the URL is considered malicious
            
            # Cache the result and update monthly count
            vt_cache[url] = is_malicious
            lookup_tracker["monthly_count"] += 1
            save_cache()
            save_lookup_tracker()
            return is_malicious

        except vt.error.APIError as e:
            if e.code == "NotFoundError":
                print(f"URL not found on VirusTotal (404): {url}. Treating as safe.")
                vt_cache[url] = False  # Treat as safe if not found
                save_cache()
                return False
            elif e.code == "QuotaExceededError":
                print("Rate limit exceeded. Waiting 15 seconds...")
                time.sleep(15)
                return check_url_virustotal(url, api_key)  # Retry after delay
            else:
                print(f"Error checking URL on VirusTotal: {e.message}")
                vt_cache[url] = False  # Treat as safe if there’s an unexpected error
                save_cache()
                return False

# Label emails based on URLs using VirusTotal API
def label_based_on_urls(text, api_key):
    url_pattern = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
    urls = re.findall(url_pattern, text)
    count = 0
    for url in urls:
        print("Checking URL:", url)
        
        if count >= 4:
            print("Reached 4 lookups, waiting 60 seconds...")
            time.sleep(60)  # Wait for a minute after 4 checks
            count = 0
        
        is_malicious = check_url_virustotal(url, api_key)
        if is_malicious:
            return 1  # Label as phishing if any URL is malicious
        
        count += 1  # Increment the count for each lookup
    
    return 0  # Label as non-phishing if no URLs are malicious

# Load the Enron dataset
def load_enron_data(csv_path, nrows=1000):
    print("Loading data with a limit of", nrows, "rows...")
    df = pd.read_csv(csv_path, usecols=["file", "message"], nrows=nrows)
    df["text"] = df["message"].fillna("")
    print(f"Loaded {len(df)} emails.")
    return df

# Label emails based on phishing keywords
def is_phishing_email(text):
    phishing_keywords = [
        r"urgent", r"verify.*account", r"click.*here", r"login.*now", r"prize", r"reward", r"reset.*password",
        r"confirm.*account", r"security.*alert", r"payment.*update"
    ]
    for keyword in phishing_keywords:
        if re.search(keyword, text, re.IGNORECASE):
            return 1  # Label as phishing
    return 0  # Label as non-phishing

def label_emails(df, api_key):
    # Apply keyword based labeling
    df["keyword_label"] = df["text"].apply(is_phishing_email)
    
    # Apply URL based labeling and combine results
    df["url_label"] = df["text"].apply(lambda text: label_based_on_urls(text, api_key))
    df["label"] = df[["keyword_label", "url_label"]].max(axis=1)  # Use 1 if either method labels it as phishing
    return df

# Save the labeled dataset
def save_labeled_data(df, output_path):
    df.to_csv(output_path, index=False)
    print(f"Labeled dataset saved to {output_path}")

# Main script
if __name__ == "__main__":
    # Paths and API key
    csv_path = "input csv"
    output_path = "output csv"
    api_key ="api key"


    df = load_enron_data(csv_path, nrows=1000)  # Load 1000 rows for testing; adjust as needed
    df = label_emails(df, api_key)  # Label emails based on keywords and URLs
    save_labeled_data(df, output_path)  # Save the labeled dataset