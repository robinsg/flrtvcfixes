import csv

def process_csv_file(file_path):
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
                    if cvss_value > 7:
                        if row[4] not in unique_values:
                            unique_values.add(row[4])  # Add to set for uniqueness
                            unique_rows.append(row)
                            break  # Exit the inner loop if a high score is found

            print_summary(unique_rows)  # Print a summary of the results

    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")

def print_summary(unique_rows):
    """Prints a summary of the processed data."""

    #print(f"Number of unique rows: {len(unique_rows)}")
    print(unique_rows)
    # Add more summary statistics as needed

if __name__ == "__main__":
    process_csv_file("vc20240103-090138.txt")
  