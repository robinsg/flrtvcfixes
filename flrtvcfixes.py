import csv
import argparse
import os
import urllib.request

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
            headers = next(reader)  # Extract the header row

            unique_values = set() 
            unique_rows = []
            current_row_index = -1

            """Select unique rows with CVSS Base Score equal to or higher than value passed"""
            for row in reader:
                cvss_base_scores = row[headers.index("CVSS Base Score")]
                apar_type = row[headers.index("Type")]
                abstract = row[headers.index("Abstract")]

                # Handle hiper fixes and CVSS scores above 7
                if "hiper" in apar_type:
                    if abstract not in unique_values:
                        unique_values.add(abstract)  # Add to set for uniqueness
                        unique_rows.append(row)
                        continue

                scores = cvss_base_scores.split()

                for score in scores:
                    cvss_value = float(score.split(":")[1])  # Extract scores
                    if cvss_value >= min_cvss_base_score:
                        if abstract not in unique_values:
                            unique_values.add(abstract)  # Add to set for uniqueness
                            unique_rows.append(row)
                            break  # Exit the inner loop if a high score is found

            save_results(unique_rows, output_directory, headers)  # Save results to the output directory

            """Now download the tar file for the unique apar rows"""
            for row in unique_rows:
                download_url = row[headers.index("Download URL")]
                if download_url.endswith(".tar"):  # Check if URL ends with ".tar"
                    try:
                        filename = os.path.basename(download_url)  # Extract filename from URL
                        download_path = os.path.join(output_directory, filename)
                        print(f"Attempting to download file {filename}")
                        urllib.request.urlretrieve(download_url, download_path)
                        print(f"Downloaded file: {filename}")
                    except Exception as e:
                        print(f"Error downloading file from {download_url}: {e}")                


    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")


def save_results(unique_rows, output_directory, headers):
    """Saves the processed data to a file named flrtvcapars.txt in the output directory."""
    output_file_path = os.path.join(output_directory, "flrtvcapars.txt")

    with open(output_file_path, "w", newline="") as output_file:  # Ensure consistent line endings across platforms
        writer = csv.writer(output_file)
        #writer.writerows(unique_rows)
        writer.writerows([
            [row[headers.index(column)] for column in ["Fileset", "Type", "Reboot Required", "Abstract", "Bulletin URL", "Download URL"]]
            for row in unique_rows
        ])

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
  