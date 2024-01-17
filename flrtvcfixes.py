import csv
import argparse
import os

def validate_arguments(args):
    if not 0 <= args.min_cvss_base_score <= 10:
        raise ValueError(f"Error: min_cvss_base_score must be between 0 and 10, but received: {args.min_cvss_base_score}")

    if not os.path.exists(args.csv_file):
        raise FileNotFoundError(f"Error: CVSS file not found: {args.csv_file}")

    if not os.path.exists(args.output_directory):
        raise ValueError(f"Error: Output directory does not exist: {args.output_directory}")


def process_csv_file(file_path, min_cvss_base_score, output_directory):

    """Processes a CSV file, extracting rows with specific criteria and printing a summary."""
    try:
        with open(file_path, 'r') as f:
            reader = csv.reader(f)

            unique_values = set()  # Use a set for faster uniqueness checks
            unique_rows = []
            current_row_index = -1

            for row in reader:
                current_row_index += 1

                # Skip the header row
                if current_row_index == 0:
                    continue

                # Handle hiper fixes and CVSS scores above 7
                if row[2] == "hiper":
                    if row[4] not in unique_values:
                        unique_values.add(row[4])  # Add to set for uniqueness
                        unique_rows.append(row)
                        continue

                cvss_base_scores = row[9]
                scores = cvss_base_scores.split()

                for score in scores:
                    cvss_value = float(score.split(":")[1])  # Extract score efficiently
                    if cvss_value >= min_cvss_base_score:
                        if row[4] not in unique_values:
                            unique_values.add(row[4])  # Add to set for uniqueness
                            unique_rows.append(row)
                            break  # Exit the inner loop if a high score is found

            save_results(unique_rows, output_directory)  # Save results to the output directory

    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")


def save_results(unique_rows, output_directory):
    """Saves the processed data to a file named flrtvcapars.txt in the output directory."""
    output_file_path = os.path.join(output_directory, "flrtvcapars.txt")

    with open(output_file_path, "w", newline="") as output_file:  # Ensure consistent line endings across platforms
        writer = csv.writer(output_file)
        writer.writerows(unique_rows)

    print(f"Results saved to: {output_file_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process a CSV file and filter rows based on CVSS score")
    parser.add_argument("csv_file", help="Path to the CSV file")
    parser.add_argument("min_cvss_base_score", type=float, help="Minimum CVSS Base Score")
    parser.add_argument("output_directory", help="Output directory to save results")

    try:
        args = parser.parse_args()
        validate_arguments(args)  # Call the validation function
        process_csv_file(args.csv_file, args.min_cvss_base_score, args.output_directory)
    except (FileNotFoundError, ValueError) as e:
        print(e)
        exit(1)
  