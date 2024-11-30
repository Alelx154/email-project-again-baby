import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

# ---- PATHS ----
FORTUNE500_CSV = r"data\fortune500_domains.csv"  # Path to the Fortune 500 domains dataset
# ----------------

# Ensure the models directory exists
os.makedirs("models", exist_ok=True)

# Load legitimate domains
legit_domains_df = pd.read_csv(FORTUNE500_CSV)
legit_domains = legit_domains_df["Domain"].str.lower()

# Generate synthetic phishing-like domains
phishing_domains = ["netflix-secure.com", "apple-verify.net", "paypal-update.org", "google-login.com", "amazon-help.me"]
phishing_domains = pd.Series(phishing_domains)

# Combine into a labeled dataset
domains = pd.concat([legit_domains, phishing_domains])
labels = [1] * len(legit_domains) + [0] * len(phishing_domains)  # 1 = legitimate, 0 = phishing
domain_df = pd.DataFrame({"domain": domains, "label": labels})

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(domain_df["domain"], domain_df["label"], test_size=0.2, random_state=42)

# Vectorize the domains
vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(2, 4))  # Character-level n-grams for domain analysis
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# Train a logistic regression model
domain_model = LogisticRegression()
domain_model.fit(X_train_vec, y_train)

# Evaluate the model
y_pred = domain_model.predict(X_test_vec)
print("Classification Report:\n", classification_report(y_test, y_pred, zero_division=0))
print("Accuracy:", accuracy_score(y_test, y_pred))

# Save the model and vectorizer
joblib.dump(domain_model, "models/domain_model.pkl")
joblib.dump(vectorizer, "models/domain_vectorizer.pkl")