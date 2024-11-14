import json
import vt
import time
from pathlib import Path
from datetime import datetime

UNIQUE_URLS_FILE = "unique_urls.json"
VT_CACHE_FILE = "vt_results_cache.json"
API_KEY = "your api key"

DAILY_LIMIT = 500
MONTHLY_LIMIT = 15500

class QuotaExceededException(Exception):
    """Custom exception to indicate that the VirusTotal quota has been exceeded."""
    pass

# Initialize or load the VirusTotal cache and tracker
def load_unique_urls():
    with open(UNIQUE_URLS_FILE, "r") as f:
        return json.load(f)

def load_vt_cache():
    if Path(VT_CACHE_FILE).exists():
        with open(VT_CACHE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_vt_cache(vt_cache):
    with open(VT_CACHE_FILE, "w") as f:
        json.dump(vt_cache, f)

def reset_daily_and_monthly_counts(tracker):
    current_date = str(datetime.now().date())
    if tracker["last_reset"] != current_date:
        tracker["daily_count"] = 0
        tracker["monthly_count"] += tracker["daily_count"]
        tracker["last_reset"] = current_date
    if tracker["monthly_count"] >= MONTHLY_LIMIT:
        print("Monthly VirusTotal lookup limit reached.")
        return False
    return True

def check_urls_with_virustotal():
    vt_cache = load_vt_cache()
    urls = load_unique_urls()
    
    # Tracker for daily/monthly limits
    tracker = {"daily_count": 0, "monthly_count": 0, "last_reset": str(datetime.now().date())}

    if not reset_daily_and_monthly_counts(tracker):
        return

    with vt.Client(API_KEY) as client:
        lookup_counter = 0  # Tracks lookups for 60-second delay

        for url in urls:
            # Skip URL if it's already in the cache or if daily/monthly limit is reached
            if url in vt_cache:
                continue
            if tracker["daily_count"] >= DAILY_LIMIT:
                print("Daily VirusTotal lookup limit reached.")
                break
            if tracker["monthly_count"] >= MONTHLY_LIMIT:
                print("Monthly VirusTotal lookup limit reached.")
                break
            
            try:
                url_id = vt.url_id(url)
                url_info = client.get_object(f"/urls/{url_id}")
                positives = url_info.last_analysis_stats['malicious']
                vt_cache[url] = positives > 0
                tracker["daily_count"] += 1
                tracker["monthly_count"] += 1
                save_vt_cache(vt_cache)
                lookup_counter += 1

                # Delay after every 4 lookups
                if lookup_counter % 4 == 0:
                    print("Reached 4 lookups, waiting 60 seconds to avoid rate limits...")
                    time.sleep(60)

            except vt.error.APIError as e:
                if e.code == "QuotaExceededError":
                    print("Quota exceeded. Moving to the next pipeline step.")
                    raise QuotaExceededException
                else:
                    print(f"VirusTotal API error for URL {url}: {e}")

    print("VirusTotal checks completed.")