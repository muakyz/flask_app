import pandas as pd
import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="openpyxl")

def process_files(uk_file_path, usa_file_path):
    uk_df = pd.read_excel(uk_file_path, engine='openpyxl')
    usa_df = pd.read_excel(usa_file_path, engine='openpyxl')

    merged_df = pd.merge(uk_df, usa_df, on='ASIN', suffixes=('_uk', '_usa'))

    if 'Buy Box: Current_uk' in merged_df.columns and 'Buy Box: Current_usa' in merged_df.columns:
        merged_df['profit'] = merged_df['Buy Box: Current_uk'] - merged_df['Buy Box: Current_usa']
    else:
        raise ValueError("'Buy Box: Current' sütunları bulunamadı.")

    result_df = merged_df[['ASIN', 'profit']]

    return result_df
