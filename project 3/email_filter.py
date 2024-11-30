import imaplib
import email
import time
from email.header import decode_header
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences # type: ignore
from tensorflow.keras.preprocessing.text import tokenizer_from_json # type: ignore
import json
import re
import os
import numpy as np
import joblib

# Email configuration
IMAP_SERVER = "imap.mail.yahoo.com"
IMAP_PORT = 993
EMAIL_USER = "Yahoo email here"  # Replace with your email
EMAIL_PASS = "Generated email password"

# Load phishing detection model
phishing_model = tf.keras.models.load_model("models/phishing_model.h5")

# Load tokenizer for text classification
with open("models/tokenizer.json", "r") as f:  # Updated path to models folder
    tokenizer_data = json.load(f)
    tokenizer = tokenizer_from_json(tokenizer_data)

# Load domain classifier and vectorizer
domain_model = joblib.load("models/domain_model.pkl")
domain_vectorizer = joblib.load("models/domain_vectorizer.pkl")


# Function to classify domains
def classify_domain(domain):
    """Classify a domain as legitimate (1) or suspicious (0)."""
    if domain == "unknown":
        return 0  # Default to suspicious if no domain is found
    domain_vec = domain_vectorizer.transform([domain])
    return domain_model.predict(domain_vec)[0]


# Extract domain from email text
def extract_domain(email_text):
    """Extract domains from email text if URLs or email addresses are mentioned."""
    domain_pattern = r"http[s]?://([\w.-]+)|@([\w.-]+)"
    matches = re.findall(domain_pattern, email_text)
    domains = [m[0] if m[0] else m[1] for m in matches]
    return domains[0].lower() if domains else "unknown"


# Text classification function
def classify_email(email_text, domain_classification):
    """Classify an email as phishing or safe using text and domain."""
    # Tokenize and pad email text
    sequence = tokenizer.texts_to_sequences([email_text])
    padded_sequence = pad_sequences(sequence, maxlen=200, padding='post')

    # Combine text and domain features
    prediction = phishing_model.predict(
        {"text_input": np.array(padded_sequence), "domain_input": np.array([domain_classification])}
    )
    return prediction[0][0] > 0.5  # True if phishing, False otherwise


# Process each email
def process_email(email_body):
    # Extract domain from email text
    domain = extract_domain(email_body)
    domain_classification = classify_domain(domain)

    # Classify the email
    is_phishing = classify_email(email_body, domain_classification)
    return is_phishing


def check_new_emails():
    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    mail.login(EMAIL_USER, EMAIL_PASS)

    mail.select("inbox")
    status, messages = mail.search(None, 'UNSEEN')
    email_ids = messages[0].split()

    for num in email_ids:
        status, data = mail.fetch(num, '(RFC822)')
        msg = email.message_from_bytes(data[0][1])

        # Decode the subject
        subject, encoding = decode_header(msg["Subject"])[0]
        if isinstance(subject, bytes):
            try:
                subject = subject.decode(encoding or "utf-8")
            except (LookupError, UnicodeDecodeError):
                subject = subject.decode("utf-8", errors="replace")
        print(f"Subject: {subject}")

        # Process email body
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    try:
                        body = part.get_payload(decode=True).decode("utf-8", errors="replace")
                    except UnicodeDecodeError:
                        body = part.get_payload(decode=True).decode("ISO-8859-1", errors="replace")
        else:
            body = msg.get_payload(decode=True).decode("utf-8", errors="replace")

        # Check if the email is phishing
        is_phishing = process_email(body)
        if is_phishing:
            print("This email is classified as phishing and will be moved to Spam.")
            move_to_spam(mail, num)
        else:
            print("This email is classified as safe.")

    mail.logout()


def move_to_spam(mail, email_id):
    try:
        # Try moving the email directly to the "Bulk" folder using the MOVE command
        mail.select("inbox")  # Make sure we're in the Inbox
        mail.uid("MOVE", email_id, "Bulk")
        print(f"Email {email_id} successfully moved to Spam (Bulk) folder.")
    except imaplib.IMAP4.error as e:
        print(f"Error using MOVE command: {e}")
        # If MOVE fails, fallback to COPY/STORE/EXPUNGE sequence
        try:
            mail.copy(email_id, "Bulk")
            mail.store(email_id, '+FLAGS', '\\Deleted')
            mail.expunge()
            print(f"Email {email_id} copied and marked as deleted for Bulk (Spam) folder.")
        except imaplib.IMAP4.error as e:
            print(f"Error with COPY/STORE sequence: {e}")


# Main function to periodically check emails
def main():
    while True:
        print("Checking for new emails...")
        check_new_emails()
        time.sleep(300)  # Check every 5 minutes


if __name__ == "__main__":
    main()