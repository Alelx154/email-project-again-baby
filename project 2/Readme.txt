Enron Data Set: https://www.kaggle.com/datasets/wcukierski/enron-email-dataset

For running the trainer:
1.) get and put virustotal API key in check_urls.py
2.) In finalize_labels.py, replace paths for PARTIALLY_LABELED_FILE, and FULLY_LABELED_FILE.
3.) In parse_messages.py, replace paths for CSV_PATH and PARTIALLY_LABELED_FILE.
4.) In train_model.py, replace path to read_CSV
5.) Execute run_pipeline.py


For running the Filter:
1.) Have a yahoo account and generate an app password from this link
https://help.yahoo.com/kb/SLN15241.html
2.) In email_filter.py, replace EMAIL_USER with your email, and EMAIL_PASS with your generated password.
3.) run the program.

pip install:
numpy==1.24.3
pandas==2.0.3
Pillow==11.0.0
pytesseract==0.3.13
scikit_learn==1.3.2
tensorflow==2.13.0
tensorflow_intel==2.13.0
vt_py==0.18.4



