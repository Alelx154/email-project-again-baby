import pandas as pd
import json
from tensorflow.keras.models import Model # type: ignore
from tensorflow.keras.layers import Input, Embedding, LSTM, Dense, Dropout, Bidirectional, concatenate # type: ignore
from tensorflow.keras.preprocessing.text import Tokenizer # type: ignore
from tensorflow.keras.preprocessing.sequence import pad_sequences # type: ignore
from sklearn.model_selection import train_test_split

# ---- PATHS ----
PROCESSED_CSV = r"data\preprocessed_with_domains.csv"  # Path to the preprocessed dataset
# ----------------

def train_phishing_model():
    # Load preprocessed dataset
    df = pd.read_csv(PROCESSED_CSV)

    # Ensure email_text is cleaned and all values are strings
    df["email_text"] = df["email_text"].fillna("unknown").apply(str)

    # Prepare features and labels
    X_text = df["email_text"].values
    X_domain = df["domain_classification"].values
    y = df["label"].values

    # Tokenize and pad email text
    tokenizer = Tokenizer(num_words=10000, oov_token="<OOV>")
    tokenizer.fit_on_texts(X_text)  # Tokenize text data
    X_text_padded = pad_sequences(tokenizer.texts_to_sequences(X_text), maxlen=200, padding="post", truncating="post")

    # Save the tokenizer to a file
    with open("models/tokenizer.json", "w") as f:
        json.dump(tokenizer.to_json(), f)
    print("Tokenizer saved to models/tokenizer.json.")

    # Train/test split
    X_train_text, X_test_text, X_train_domain, X_test_domain, y_train, y_test = train_test_split(
        X_text_padded, X_domain, y, test_size=0.2, random_state=42
    )

    # Build the phishing detection model
    text_input = Input(shape=(200,), name="text_input")
    x = Embedding(10000, 64)(text_input)
    x = Bidirectional(LSTM(64, return_sequences=True))(x)
    x = Dropout(0.5)(x)
    x = Bidirectional(LSTM(32))(x)
    x = Dense(32, activation="relu")(x)
    x = Dropout(0.5)(x)

    domain_input = Input(shape=(1,), name="domain_input")
    domain_dense = Dense(8, activation="relu")(domain_input)

    concatenated = concatenate([x, domain_dense])
    output = Dense(1, activation="sigmoid")(concatenated)

    model = Model(inputs=[text_input, domain_input], outputs=output)
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])

    # Train the model
    model.fit(
        {"text_input": X_train_text, "domain_input": X_train_domain},
        y_train,
        batch_size=32,
        epochs=10,
        validation_split=0.1,
    )

    # Evaluate the model
    model.evaluate({"text_input": X_test_text, "domain_input": X_test_domain}, y_test)

    # Save the phishing detection model
    model.save("models/phishing_model.h5")
    print("Phishing detection model saved.")

if __name__ == "__main__":
    train_phishing_model()