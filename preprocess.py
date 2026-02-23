import pandas as pd
import re
from nltk.stem import PorterStemmer

def clean(df):
    
    # open up stemmer
    stemmer = PorterStemmer()

    # drop null text rows
    original_length = len(df)
    df = df.dropna(subset=["text"]).copy()
    print(f"Dropped null text rows: {original_length - len(df)} rows dropped.")

    # fill null labels with -1
    df["target"] = df["target"].fillna(-1)

    # lowercase
    df["text"] = df["text"].str.lower()


    # remove URLs, domains, and file extensions
    df["text"] = df["text"].str.replace(
        r"http\S+|www\.\S+|\S+\.(com|org|net|gov|html|php|php\d|txt|asc|xml|cgi)\S*|\d+",
        "", regex=True
    )

    # nuclear option. remove anything that isn't a letter or space
    df["text"] = df["text"].str.replace(r"[^a-z\s]", "", regex=True)

    # stem words + remove duplicate words
    stemmed_texts = []
    total = len(df)
    last_printed = -1

    for i, text in enumerate(df["text"]):
        if isinstance(text, str):
            
            stemmed_words = {}
            
            for w in text.split():
                stemmed_words[stemmer.stem(w)] = None
            
            stemmed_texts.append(" ".join(stemmed_words.keys()))
        
        else:
            stemmed_texts.append(text)

        percent = int((i + 1) / total * 100)
        if percent % 5 == 0 and percent != last_printed:
            print(f"   Processing. {i + 1}/{total} completed \t({percent}%)")
            last_printed = percent

    df["text"] = stemmed_texts

    # keep first occurrence of each record and drop duplicates
    before = len(df)
    df = df.drop_duplicates(subset=["text"])
    print(f"Dropped duplicate rows: {before - len(df)} rows dropped.\n")
    
    rows_remaining = len(df)
    rows_dropped = original_length - rows_remaining
    percent_remaining = (rows_remaining / original_length) * 100

    print(f"Done. {rows_dropped} total rows dropped.")
    print(f"{rows_remaining}/{original_length} {percent_remaining:.1f}% of rows remaining ")
    
    return df


# load dataset and call clean function
df = pd.read_csv("labeled.csv")
cleaned_df = clean(df)
cleaned_df.to_csv("preprocessed.csv", index=False)

