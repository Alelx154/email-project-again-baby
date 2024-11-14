# train_model.py
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import Sequential # type: ignore
from tensorflow.keras.layers import Embedding, LSTM, Dense, Dropout, Bidirectional # type: ignore
from tensorflow.keras.preprocessing.text import Tokenizer # type: ignore
from tensorflow.keras.preprocessing.sequence import pad_sequences # type: ignore
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

def train_model_script():
    # Load labeled data
    df = pd.read_csv("C:/your/path/here/fully_labeled_data.csv")
    X = df['text'].values
    y = df['label'].values

    # Text preprocessing
    tokenizer = Tokenizer(num_words=10000, oov_token="<OOV>")
    tokenizer.fit_on_texts(X)
    sequences = tokenizer.texts_to_sequences(X)
    X_padded = pad_sequences(sequences, maxlen=200, padding='post', truncating='post')

    # Model building
    model = Sequential([
        Embedding(10000, 64, input_length=200),
        Bidirectional(LSTM(64, return_sequences=True)),
        Dropout(0.5),
        Bidirectional(LSTM(32)),
        Dense(32, activation='relu'),
        Dropout(0.5),
        Dense(1, activation='sigmoid')
    ])
    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

    # Train/test split and training
    X_train, X_test, y_train, y_test = train_test_split(X_padded, y, test_size=0.2, random_state=42)
    model.fit(X_train, y_train, batch_size=32, epochs=5, validation_split=0.1)

    # Evaluate model
    y_pred = (model.predict(X_test) > 0.5).astype("int32")
    print("Classification Report:\n", classification_report(y_test, y_pred))
    print("Accuracy:", accuracy_score(y_test, y_pred))

    # Save model and tokenizer
    model.save("phishing_detection_model.h5")
    with open("tokenizer.json", "w") as f:
        f.write(tokenizer.to_json())
    print("Model and tokenizer saved.")