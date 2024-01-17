# Import the csv library
import csv

# Open the csv file in read mode and create a csv reader object
with open('vc20240103-090138.txt', 'r') as f:
    reader = csv.reader(f)

    unique_values = []
    unique_rows = []
    rowcount = -1
    for row in reader:
    
      # Ignore first row as this is the header row
      # Retrieve the CVSS Base Score(s)
      if rowcount > -1:
      
        # If this row is for a hiper fix then store the row
        if row[2] == "hiper":
          if row[4] not in unique_values:
            unique_values.append(row[4])
            unique_rows.append(row)
            continue        
        
        cvss_base_scores = row[9]
        scores = cvss_base_scores.split()
  
        # Extract the score value which is immediately after the : char
        for score in scores:
          index = score.find(":")
          index += 1
          cvss_score = "" * index + score[index:]
          cvss_value = float(cvss_score)
      
          # If we find a CVSS score of 7 or greater then store the row
          if cvss_value > 7:
            
            # Only store the row if there's not already an entry for it in unique_values
            if row[4] not in unique_values:
              unique_values.append(row[4])
              unique_rows.append(row)
      else:
        unique_rows.append(row)
      
      rowcount += 1
      

rowcount = 0
for row in unique_rows:
  if rowcount > 0:
    print(row[8])
    
  rowcount += 1

exit(0)
