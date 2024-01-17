import csv
import argparse

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
    """Saves the processed data to the specified output directory."""
    
    for unique in unique_rows:
      print(unique,"\n\n")

    # Implement logic to save the unique rows to a file within the output directory
    # (e.g., using CSV, JSON, or other suitable format)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process a CSV file and filter rows based on CVSS score")
    parser.add_argument("csv_file", help="Path to the CSV file")
    parser.add_argument("min_cvss_base_score", type=float, help="Minimum CVSS Base Score")
    parser.add_argument("output_directory", help="Output directory to save results")
    args = parser.parse_args()

    process_csv_file(args.csv_file, args.min_cvss_base_score, args.output_directory)
  