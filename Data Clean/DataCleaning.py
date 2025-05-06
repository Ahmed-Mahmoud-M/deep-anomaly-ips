import pandas as pd
import glob

# تحضير ملف CSV جديد
output_file = "merged_cleaned_data.csv"
first = True

def clean_dataframe(df):
    nunique = df.nunique()
    df.drop(columns=nunique[nunique <= 1].index, inplace=True)

    missing_ratio = df.isnull().mean()
    df.drop(columns=missing_ratio[missing_ratio > 0.4].index, inplace=True)

    df.fillna(method='ffill', inplace=True)
    df.fillna(method='bfill', inplace=True)

    return df

for file in glob.glob("*.csv"):
    print(f"🔄 \033[91mFile is being processed\033[0m : {file}")
    df = pd.read_csv(file)
    df = clean_dataframe(df)

    if first:
        df.to_csv(output_file, index=False)
        first = False
    else:
        df.to_csv(output_file, mode='a', header=False, index=False)

print("✅ The clean data file was saved successfully : merged_cleaned_data.csv")
