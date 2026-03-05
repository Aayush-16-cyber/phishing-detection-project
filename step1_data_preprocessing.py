import pandas as pd

# load the dataset file
file_path = r"E:\CAPSTONE\Phishing_Detection_Project\dataset\phishing_dataset.csv"
df = pd.read_csv(file_path)

print("Initial dataset shape:", df.shape)


# remove null values because they can create problems in training
df = df.dropna()
print("After removing null values:", df.shape)


# remove duplicate URLs so same data is not repeated
df = df.drop_duplicates(subset='url')
print("After removing duplicate URLs:", df.shape)


# keep only required columns (url and result)
df = df[['url', 'result']]

# rename result column to label for simplicity
df = df.rename(columns={'result': 'label'})

print("\nLabel distribution before balancing:")
print(df['label'].value_counts())


# separate legitimate and phishing URLs
legit_urls = df[df['label'] == 0]
phishing_urls = df[df['label'] == 1]

sample_size = 10000   # taking 10000 from each class

# take random samples to make dataset balanced
legit_sample = legit_urls.sample(n=sample_size, random_state=42)
phishing_sample = phishing_urls.sample(n=sample_size, random_state=42)

# combine both samples and shuffle the data
final_df = pd.concat([legit_sample, phishing_sample])
final_df = final_df.sample(frac=1, random_state=42).reset_index(drop=True)

print("\nBalanced dataset shape:", final_df.shape)
print(final_df['label'].value_counts())


# save the cleaned and balanced dataset
output_path = r"E:\CAPSTONE\Phishing_Detection_Project\dataset\cleaned_phishing_dataset.csv"
final_df.to_csv(output_path, index=False)

print("\nDataset cleaned and saved successfully!")