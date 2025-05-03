# the purposse of the class is to preprocess the data from combining all csv files which are in
# data/raw folder in one full_dataset.csv which will be in  data/processed , after that we will prepare
# the data to preprocessing and feature engineering

import pandas as pd
import glob
import os

def loadData():
    # Check if the raw folder exists
    if not os.path.exists("/home/ahmed/deep-anomaly-ips/python/data/raw"):
        print("Raw data folder does not exist!")
        return

    csv_files = glob.glob("/home/ahmed/deep-anomaly-ips/python/data/raw/*.csv")

    if not csv_files:
        print("No CSV files found in raw data folder.")
        return
    
    combined_df = pd.DataFrame()

    for file in csv_files: 
        try:
            # Read the current CSV file into a DataFrame
            df = pd.read_csv(file)
            # Concatenate with the combined dataframe
            combined_df = pd.concat([combined_df, df], ignore_index=True)
        except Exception as e:
            print(f"Error reading {file}: {e}")
    
    if combined_df.empty:
        print("No data combined from the CSV files.")
        return
    

    return combined_df
    
    # # Ensure processed folder exists before saving the file
    # processed_folder = "/home/ahmed/deep-anomaly-ips/python/data/processed"
    # os.makedirs(processed_folder, exist_ok=True)
    
    # # Save the combined DataFrame to the processed folder
    # combined_df.to_csv(f"{processed_folder}/processed.csv", index=False)

    # print("All files are combined in processed.csv")

if __name__ == '__main__':
    loadData()
