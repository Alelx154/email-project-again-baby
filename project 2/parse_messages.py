import pandas as pd
import re
import json

CSV_PATH = r"C:/your/path/here/emails.csv"  # Update this path if necessary
UNIQUE_URLS_FILE = "unique_urls.json"
PARTIALLY_LABELED_FILE = r"C:/your/path/here/partially_labeled_data.csv"

def load_emails(csv_path, nrows):
    """Load emails from CSV file with a limit on rows."""
    df = pd.read_csv(csv_path, usecols=["file", "message"], nrows=nrows)
    df["text"] = df["message"].fillna("")
    return df

def extract_unique_urls(df):
    """Extract unique URLs from email messages."""
    url_pattern = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
    unique_urls = set()

    for message in df["text"]:
        urls = re.findall(url_pattern, message)
        unique_urls.update(urls)

    with open(UNIQUE_URLS_FILE, "w") as f:
        json.dump(list(unique_urls), f)
    print(f"Unique URLs saved to {UNIQUE_URLS_FILE}")

def is_phishing_email(text):
    """Check if email text contains phishing keywords."""
    phishing_keywords = [
    # Urgency and Action Triggers
    r"urgent", r"immediate", r"important", r"action required", r"act now", r"asap", r"limited time", r"final notice",
    r"verify.*account", r"click.*here", r"login.*now", r"reset.*password", r"confirm.*account",
    r"account.*suspend", r"account.*hold", r"secure.*account", r"account.*verify", r"security.*update",
    r"attention required", r"respond.*immediately", r"take action", r"deactivation", r"reactivate.*account",
    
    # Financial Keywords and Triggers
    r"payment.*update", r"confirm.*payment", r"payment.*required", r"overdue", r"refund", r"balance.*due",
    r"credit card.*information", r"account.*locked", r"payment.*failed", r"update.*billing",
    r"invoice.*attached", r"wire transfer", r"bank account", r"validate.*payment", r"transfer.*funds",
    r"verify.*transaction", r"charge.*account", r"credit card.*update", r"overdraft",

    # Offers, Rewards, and Prizes
    r"prize", r"reward", r"free", r"claim.*reward", r"limited offer", r"win", r"winner", r"exclusive deal",
    r"special promotion", r"act now to claim", r"redeem.*reward", r"gift.*card", r"you've been selected",
    r"you are a winner", r"get.*reward", r"congratulations", r"you.*won", r"no purchase necessary",
    
    # Fake Support/Impersonation of Legitimate Entities
    r"support.*team", r"technical support", r"customer service", r"fraud alert", r"your bank",
    r"your account", r"apple.*support", r"paypal.*account", r"microsoft.*security", r"amazon.*billing",
    r"google.*security", r"bank.*alert", r"your.*bank", r"it department", r"update.*account", r"reset.*security",
    r"billing.*team", r"administrator", r"compliance", r"security center", r"service notice", r"email.*administrator",
    r"online.*banking",

    # Generic Security Warnings and Alerts
    r"security.*alert", r"account.*activity", r"unusual.*activity", r"suspicious.*activity",
    r"access.*attempt", r"unauthorized login", r"secure.*account", r"account.*breach", r"malware",
    r"virus detected", r"your device", r"verify identity", r"confirm identity", r"session expired",

    # Document-Related Phrases (for Phishing Attachments)
    r"document.*attached", r"download.*file", r"open.*attachment", r"view.*statement", r"see attached",
    r"attached.*file", r"important document", r"confidential document", r"download.*pdf", r"attachment.*required",
    
    # Miscellaneous Phishing Terms
    r"check.*account", r"verify.*details", r"reactivate", r"login.*failed", r"confirm.*information",
    r"access.*secure.*account", r"verify.*login", r"reset.*login", r"login.*credentials", r"update.*profile",
    r"log in.*verify", r"validate.*identity", r"revalidate.*account", r"confirm.*order"
    ]
    for keyword in phishing_keywords:
        if re.search(keyword, text, re.IGNORECASE):
            return 1
    return 0

def label_emails_by_keywords(df):
    """Label emails based on presence of phishing keywords."""
    df["keyword_label"] = df["text"].apply(is_phishing_email)
    return df

def parse_messages(nrows):
    """Parse messages, extract URLs, and label emails by keywords."""
    df = load_emails(CSV_PATH, nrows)
    extract_unique_urls(df)
    df = label_emails_by_keywords(df)
    df.to_csv(PARTIALLY_LABELED_FILE, index=False)
    print(f"Partially labeled data saved to {PARTIALLY_LABELED_FILE}")