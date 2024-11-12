import re
import nltk
import spacy
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, confusion_matrix
import requests

# Load spaCy English model
nlp = spacy.load("en_core_web_sm")

# Load NLTK stop words
nltk.download("stopwords")
from nltk.corpus import stopwords

# Customizable parameters
STOP_WORDS = set(stopwords.words("english"))
THREAT_INTELLIGENCE_API = "https://www.virustotal.com/api/v3/urls/{url_id}"
API_KEY = "YOUR_VIRUSTOTAL_API_KEY"

# Function for Text Cleaning
def preprocess_text(text):
    # Tokenization and stop words removal
    doc = nlp(text)
    tokens = [token.lemma_.lower() for token in doc if token.is_alpha and token.text.lower() not in STOP_WORDS]
    return " ".join(tokens)

# Feature Extraction: Suspicious URLs and Attachments
def extract_features(email_text):
    # Check for URLs and suspicious keywords
    features = {}
    features["url_count"] = len(re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", email_text))
    features["suspicious_words"] = int(any(word in email_text.lower() for word in ["urgent", "password", "click", "verify"]))
    return features

# Preprocessing Function to Transform Email Text into Bag-of-Words
def prepare_dataset(emails):
    cleaned_texts = [preprocess_text(email) for email in emails]
    vectorizer = CountVectorizer()
    X = vectorizer.fit_transform(cleaned_texts)
    return X, vectorizer

# Loading and Preprocessing Data
def load_data():
    # Load Enron dataset or mock email data (substitute with Enron dataset path)
    data = pd.read_csv("mail_data.csv")
    emails = data["Message"]
    labels = data["Category"]  # 1 for phishing, 0 for legitimate
    return emails, labels

# Training a Naïve Bayes Classifier
def train_model(X, y):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = MultinomialNB()
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    conf_matrix = confusion_matrix(y_test, predictions)
    return model, accuracy, conf_matrix

# Threat Intelligence Integration (URL Analysis)
def check_url(url):
    url_id = requests.utils.quote(url, safe="")
    headers = {"x-apikey": API_KEY}
    response = requests.get(THREAT_INTELLIGENCE_API.format(url_id=url_id), headers=headers)
    return response.json()

# System Prototype Flow
def detect_phishing(email_text, model, vectorizer):
    # Extract text features
    features = extract_features(email_text)
    print("Extracted Features:", features)
    
    # Preprocess and transform for ML model
    cleaned_text = preprocess_text(email_text)
    text_vector = vectorizer.transform([cleaned_text])
    prediction = model.predict(text_vector)
    
    # Threat Intelligence API (optional)
    urls = re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", email_text)
    if urls:
        for url in urls:
            threat_data = check_url(url)
            print("Threat Intelligence Check for URL:", threat_data)
    
    return "Phishing" if prediction[0] == 1 else "Legitimate"

# Main function to run all steps
def main():
    # Load data
    emails, labels = load_data()
    
    # Prepare dataset and extract features
    X, vectorizer = prepare_dataset(emails)
    
    # Train model
    model, accuracy, conf_matrix = train_model(X, labels)
    print("Model Accuracy:", accuracy)
    print("Confusion Matrix:\n", conf_matrix)
    
    # Test example email
    sample_email = "Dear user, please click here to verify your account: http://suspicious-link.com"
    print("Classification:", detect_phishing(sample_email, model, vectorizer))

if __name__ == "__main__":
    main()
