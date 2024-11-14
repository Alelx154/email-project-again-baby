import os
from parse_messages import parse_messages
from check_urls import check_urls_with_virustotal, QuotaExceededException
from finalize_labels import finalize_labels
from train_model import train_model_script


def main(nrows=5000):
    print("Starting pipeline...")

    # Step 1: Parse messages and extract URLs
    print("Step 1: Parsing messages and extracting URLs...")
    parse_messages(nrows=nrows)

    # Step 2: Check URLs with VirusTotal
    print("Step 2: Checking URLs with VirusTotal...")
    try:
        check_urls_with_virustotal()
    except QuotaExceededException:
        print("Quota exceeded. Moving to the next pipeline step.")

    # Step 3: Finalize labels and combine results
    print("Step 3: Finalizing labels and combining results...")
    finalize_labels()

    print("Step 4: Training the model...")
    train_model_script()

if __name__ == "__main__":
    main(nrows=100000)