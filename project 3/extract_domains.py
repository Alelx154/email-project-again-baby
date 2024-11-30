import pandas as pd

# Input text file and output CSV file
INPUT_FILE = r"data\fortune-500-domains.txt"  # Replace with the path to your text file
OUTPUT_FILE = r"data\fortune500_domains.csv"

def extract_relevant_columns(input_file, output_file):
    """Extract relevant columns from the text file and save as CSV."""
    # Load the text file into a DataFrame
    try:
        df = pd.read_csv(input_file, sep=",", quotechar='"')
    except Exception as e:
        print(f"Error reading the file: {e}")
        return

    # Print the column names for verification
    print("Columns in the dataset:", df.columns)

    # Select relevant columns
    relevant_columns = ["Company", "Domain", "Primary Website", "Primary Domain"]
    if all(col in df.columns for col in relevant_columns):
        filtered_df = df[relevant_columns]
    else:
        missing_columns = [col for col in relevant_columns if col not in df.columns]
        print(f"Missing columns in the dataset: {missing_columns}")
        return

    # Save the filtered data to a new CSV file
    filtered_df.to_csv(output_file, index=False)
    print(f"Relevant information saved to {output_file}")

if __name__ == "__main__":
    extract_relevant_columns(INPUT_FILE, OUTPUT_FILE)
