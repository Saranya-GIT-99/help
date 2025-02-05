import pandas as pd

def export_excel_to_csv(input_excel, output_csv):
    # Read the Excel file. 
    # If your Excel file has headers, you can adjust header=0 or skip the header row.
    df = pd.read_excel(input_excel, header=None)
    
    with open(output_csv, 'w', encoding='utf-8') as f:
        # Iterate through each row of the DataFrame
        for _, row in df.iterrows():
            # Drop any empty cells (NaN) and convert the rest to strings
            values = row.dropna().tolist()
            values_str = [str(val).strip() for val in values if str(val).strip() != '']
            if values_str:
                # Join the values with commas
                line = ",".join(values_str)
                f.write(line + "\n")

if __name__ == "__main__":
    input_excel = "input.xlsx"  # Change this to your Excel file name
    output_csv = "output.csv"   # Change this to your desired output file name
    export_excel_to_csv(input_excel, output_csv)
    print(f"Export complete! Output written to: {output_csv}")
