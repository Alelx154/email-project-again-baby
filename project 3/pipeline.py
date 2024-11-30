import subprocess

def run_script(script_name):
    """Run a Python script and capture the output."""
    try:
        print(f"Running {script_name}...")
        result = subprocess.run(
            ["python", script_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        print(result.stdout)  # Print script output
        if result.returncode != 0:
            print(f"Error running {script_name}:\n{result.stderr}")
            return False
        return True
    except Exception as e:
        print(f"Failed to execute {script_name}: {e}")
        return False

def main():
    scripts = [
        "train_domain_model.py",
        "preprocess_data.py",
        "train_phishing_model.py",
    ]

    for script in scripts:
        success = run_script(script)
        if not success:
            print(f"Pipeline halted due to an error in {script}.")
            return

    print("Pipeline completed successfully!")

if __name__ == "__main__":
    main()
