import imaplib
import email
import time
from email.header import decode_header
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences # type: ignore
from tensorflow.keras.preprocessing.text import tokenizer_from_json # type: ignore
from tensorflow.keras.preprocessing import image # type: ignore
from tensorflow.keras.applications.vgg16 import VGG16, preprocess_input, decode_predictions # type: ignore
import pytesseract
from PIL import Image
import numpy as np
import os

# Email configuration
IMAP_SERVER = "imap.mail.yahoo.com"
IMAP_PORT = 993
EMAIL_USER = "your email"  # Replace with your email
EMAIL_PASS = "your generated password"

# Load text classification model and tokenizer
model = tf.keras.models.load_model("phishing_detection_model.h5")
with open("tokenizer.json", "r") as f:
    tokenizer_data = f.read()
    tokenizer = tokenizer_from_json(tokenizer_data)

# Load pre-trained image classifier
image_model = VGG16(weights='imagenet')

# OCR function to extract text from images
def extract_text_from_image(image_path):
    try:
        img = Image.open(image_path)
        return pytesseract.image_to_string(img)
    except Exception as e:
        print(f"Error reading image: {e}")
        return ""

# Image classification function
def classify_image(img_path):
    img = image.load_img(img_path, target_size=(224, 224))
    img_array = image.img_to_array(img)
    img_array = np.expand_dims(img_array, axis=0)
    img_array = preprocess_input(img_array)

    preds = image_model.predict(img_array)
    decoded_preds = decode_predictions(preds, top=3)[0]
    print("Image Classification:", decoded_preds)
    # Return True if a known phishing indicator is present
    for _, label, _ in decoded_preds:
        if 'indicator' in label:  # Adjust this based on specific labels in your data
            return True
    return False

# Text classification function
def classify_text(text):
    sequence = tokenizer.texts_to_sequences([text])
    padded_sequence = pad_sequences(sequence, maxlen=200, padding='post')
    prediction = model.predict(padded_sequence)
    return prediction[0][0] > 0.5  # True if phishing, False otherwise

# Process each email
def process_email(email_body, image_paths):
    # Check email body text
    text_phishing = classify_text(email_body)

    # OCR text extraction and classification from images
    ocr_phishing = False
    for img_path in image_paths:
        img_text = extract_text_from_image(img_path)
        if classify_text(img_text):
            ocr_phishing = True
            break

    # Image classification for phishing indicators
    image_phishing = False
    for img_path in image_paths:
        if classify_image(img_path):
            image_phishing = True
            break

    # Final phishing determination
    return text_phishing or ocr_phishing or image_phishing

def check_new_emails():
    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    mail.login(EMAIL_USER, EMAIL_PASS)
    
    mail.select("inbox")
    status, messages = mail.search(None, 'UNSEEN')
    email_ids = messages[0].split()

    for num in email_ids:
        status, data = mail.fetch(num, '(RFC822)')
        msg = email.message_from_bytes(data[0][1])

        subject, encoding = decode_header(msg["Subject"])[0]
        if isinstance(subject, bytes):
            try:
                subject = subject.decode(encoding or "utf-8")
            except (LookupError, UnicodeDecodeError):
                subject = subject.decode("utf-8", errors="replace")
        print(f"Subject: {subject}")

        # Process email body
        body = ""
        image_paths = []
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    try:
                        body = part.get_payload(decode=True).decode("utf-8", errors="replace")
                    except UnicodeDecodeError:
                        body = part.get_payload(decode=True).decode("ISO-8859-1", errors="replace")
                elif "image" in content_type:
                    filename = part.get_filename()
                    if filename:
                        filepath = os.path.join("/tmp", filename)
                        with open(filepath, "wb") as f:
                            f.write(part.get_payload(decode=True))
                        image_paths.append(filepath)
        else:
            body = msg.get_payload(decode=True).decode("utf-8", errors="replace")

        # Check if email is phishing
        is_phishing = process_email(body, image_paths)
        if is_phishing:
            print("This email is classified as phishing and will be moved to Spam.")
            move_to_spam(mail, num)
        else:
            print("This email is classified as safe.")

        # Clean up temp images
        for path in image_paths:
            os.remove(path)

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
