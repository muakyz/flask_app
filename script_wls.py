import pandas as pd
import logging

def process_files_wls(source_file_path, target_file_path, conversion_rate, current_user_id):
    try:
        with open(source_file_path, 'r') as file:
            selected_values = file.read().strip().split(',')

        df_target = pd.read_csv(target_file_path)
        logging.info("Dosyalar başarıyla okundu.")
    except Exception as e:
        logging.error(f"Dosyalar okunurken hata oluştu: {e}")
        raise

    ean_column = 'Product Codes: EAN'
    upc_column = 'Product Codes: UPC'
    asin_column = 'ASIN'

    matched_rows_count = 0

    for value in selected_values:
        matched_rows = df_target[
            (df_target[ean_column].astype(str).str.contains(value.strip())) | 
            (df_target[upc_column].astype(str).str.contains(value.strip())) | 
            (df_target[asin_column].astype(str).str.contains(value.strip()))
        ]
        matched_rows_count += matched_rows.shape[0]

    logging.info(f"Eşleşen satır sayısı: {matched_rows_count}")
