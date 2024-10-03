import pandas as pd
import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="openpyxl")

def process_files(uk_file_path, usa_file_path):
    uk_df = pd.read_excel(uk_file_path, engine='openpyxl')
    usa_df = pd.read_excel(usa_file_path, engine='openpyxl')
    
    if 'ASIN' not in uk_df.columns:
        raise ValueError("UK dosyasında 'ASIN' sütunu bulunamadı.")
    if 'ASIN' not in usa_df.columns:
        raise ValueError("USA dosyasında 'ASIN' sütunu bulunamadı.")
    
    merged_df = pd.merge(uk_df, usa_df, on='ASIN', suffixes=('_uk', '_usa'))
    
    if 'Buy Box: Current_uk' not in merged_df.columns or 'Buy Box: Current_usa' not in merged_df.columns:
        raise ValueError("'Buy Box: Current' sütunları bulunamadı.")
    
    merged_df['Buy Box: Current_uk'] = pd.to_numeric(merged_df['Buy Box: Current_uk'], errors='coerce')
    merged_df['Buy Box: Current_usa'] = pd.to_numeric(merged_df['Buy Box: Current_usa'], errors='coerce')
    
    merged_df = merged_df.dropna(subset=['Buy Box: Current_uk', 'Buy Box: Current_usa'])
    
    merged_df['profit'] = merged_df['Buy Box: Current_uk'] - merged_df['Buy Box: Current_usa']
    
    merged_df = merged_df.dropna(subset=['profit'])
    
    result_df = merged_df[['ASIN', 'profit']]
    
    return result_df
