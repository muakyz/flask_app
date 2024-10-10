import pandas as pd
import numpy as np
import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="openpyxl")

def process_files(source_file_path, target_file_path, conversion_rate):
    df_source = pd.read_excel(source_file_path)
    df_target = pd.read_excel(target_file_path)
    
    df_source_filtered = df_source.dropna(subset=['Buy Box: Current'])
    df_target_filtered = df_target.dropna(subset=['Buy Box: Current'])
    
    merged_df = pd.merge(df_source_filtered, df_target_filtered, on='ASIN', suffixes=('_source', '_target'))
    
    merged_df['VAT on Fees'] = (merged_df['FBA Fees:_target'] + merged_df['Referral Fee based on current Buy Box price_target']) * 0.2
    merged_df['Buy Box: Current_source_converted'] = round(merged_df['Buy Box: Current_source'] * conversion_rate, 2)
    merged_df['profit'] = round((merged_df['Buy Box: Current_target'] - merged_df['Buy Box: Current_source_converted'] - 
                                   merged_df['FBA Fees:_target'] - merged_df['Referral Fee based on current Buy Box price_target'] - 
                                   merged_df['VAT on Fees']), 2)
    merged_df['roi'] = round(((merged_df['profit']) / merged_df['Buy Box: Current_source_converted']) * 100, 2)
    
    merged_df.replace({np.inf: np.nan, -np.inf: np.nan}, inplace=True)
    merged_df.fillna(0, inplace=True)  
    
    result_df = merged_df[['ASIN', 
                           'Buy Box: Current_source', 
                           'Buy Box: Current_source_converted',  
                           'Buy Box: Current_target', 
                           'profit', 
                           'roi',  
                           'Bought in past month_target', 
                           'Buy Box: % Amazon 30 days_target',
                           'Buy Box Eligible Offer Count: New FBA_target',
                           'Amazon: Availability of the Amazon offer_target']]
    
    for col in ['Buy Box: Current_source', 'Buy Box: Current_source_converted', 
                'Buy Box: Current_target', 'profit', 'roi']:
        result_df.loc[:, col] = result_df[col].astype(float)
    
    result_df = result_df[result_df['roi'] > 0]

    return result_df


