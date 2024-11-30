import pandas as pd
import re
import joblib

# ---- PATHS ----
PHISHING_CSV = r"data\processed_emails.csv"  # Path to the phishing dataset
FORTUNE500_CSV = r"data\fortune500_domains.csv"  # Path to the Fortune 500 domains dataset
OUTPUT_CSV = r"data\preprocessed_with_domains.csv"  # Output file path
# ----------------

# Load domain classifier and vectorizer
domain_model = joblib.load("models/domain_model.pkl")
domain_vectorizer = joblib.load("models/domain_vectorizer.pkl")

def extract_domain(email_text):
    """Extract domains from email text if URLs or email addresses are mentioned."""
    if not isinstance(email_text, str):  # Ensure the input is a string
        return "unknown"
    domain_pattern = r"http[s]?://([\w.-]+)|@([\w.-]+)"
    matches = re.findall(domain_pattern, email_text)
    domains = [m[0] if m[0] else m[1] for m in matches]
    return domains[0].lower() if domains else "unknown"

def classify_domain(domain):
    """Classify a domain as legitimate (1) or suspicious (0)."""
    if domain == "unknown":
        return 0  # Default to suspicious if no domain is found
    domain_vec = domain_vectorizer.transform([domain])
    return domain_model.predict(domain_vec)[0]

def preprocess_phishing_dataset(input_file, output_file):
    """Preprocess phishing dataset by extracting and classifying domains."""
    df = pd.read_csv(input_file)

    # Extract domains
    df["domain"] = df["email_text"].apply(extract_domain)

    # Classify domains
    df["domain_classification"] = df["domain"].apply(classify_domain)

    # Save the preprocessed dataset
    df.to_csv(output_file, index=False)
    print(f"Preprocessed data saved to {output_file}")

if __name__ == "__main__":
    preprocess_phishing_dataset(PHISHING_CSV, OUTPUT_CSV)