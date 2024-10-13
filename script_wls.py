import pandas as pd
import numpy as np
import logging
import os
import pyodbc

def get_connection():
    server = os.getenv('DB_SERVER', '45.155.159.142,1433')
    database = os.getenv('DB_DATABASE', 'AMAZINGO')
    driver = os.getenv('DB_DRIVER', 'ODBC Driver 17 for SQL Server')
    username = os.getenv('DB_USERNAME', 'remote2')
    password = os.getenv('DB_PASSWORD', 'your_db_password')
    connection_string = (
        f'DRIVER={{{driver}}};'
        f'SERVER={server};'
        f'DATABASE={database};'
        f'UID={username};'
        f'PWD={password};'
    )
    try:
        return pyodbc.connect(connection_string)
    except pyodbc.Error as e:
        logging.error(f"Veritabanı bağlantı hatası: {e}")
        raise

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

    rename_dict = {
        'Buy Box: Current': 'Buy Box: Current',
        'Buy Box: % Amazon 30 days': 'Buy Box: % Amazon 30 days',
        'Buy Box Eligible Offer Count: New FBA': 'Buy Box Eligible Offer Counts: New FBA',
        'FBA Fees:': 'FBA Pick&Pack Fee',
        'Referral Fee based on current Buy Box price': 'Referral Fee based on current Buy Box price'
    }

    float_columns = [
        'Bought in past month',
        'Buy Box: Current',
        'Buy Box: % Amazon 30 days',
        'Buy Box Eligible Offer Counts: New FBA',
        'FBA Pick&Pack Fee',
        'Referral Fee based on current Buy Box price'
    ]

    try:
        df_target.columns = df_target.columns.str.replace(' 🚚', '', regex=False)
        
        for col in float_columns:
            if col in df_target.columns:
                logging.info(f"{col} sütunu float'a dönüştürülüyor.")
                df_target[col] = df_target[col].astype(str).str.extract('(\d+\.?\d*)')[0].astype(float)
            else:
                logging.warning(f"{col} sütunu hedef veri çerçevesinde bulunamadı.")
                
        df_target.rename(columns=rename_dict, inplace=True)
        logging.info("Sütun isimleri başarıyla yeniden adlandırıldı.")
    except Exception as e:
        logging.error(f"Sütunları yeniden adlandırırken veya float'a çevirirken hata oluştu: {e}")
        raise

    matched_rows_count = 0
    for value in selected_values:
        matched_rows = df_target[
            (df_target[ean_column].astype(str).str.contains(value.strip(), na=False)) | 
            (df_target[upc_column].astype(str).str.contains(value.strip(), na=False)) | 
            (df_target[asin_column].astype(str).str.contains(value.strip(), na=False))
        ]
        matched_rows_count += matched_rows.shape[0]

    logging.info(f"Eşleşen satır sayısı: {matched_rows_count}")

    if matched_rows_count > 0:
        logging.info("Eşleşen satırlar:")
        for index, row in matched_rows.iterrows():
            logging.info(row.to_dict())

    df_target_filtered = df_target.dropna(subset=['Buy Box: Current'])

    df_target_filtered['profit'] = (
        df_target_filtered['Buy Box: Current'] - 
        df_target_filtered['FBA Pick&Pack Fee'] - 
        df_target_filtered['Referral Fee based on current Buy Box price']
    )

    df_target_filtered['roi'] = round((df_target_filtered['profit'] / df_target_filtered['Buy Box: Current']) * 100, 2)

  
    result_list = []  

    for _, row in df_target_filtered.iterrows():
        product_info = {
            "asin": row['ASIN'],
            "bb_amazon_percentage": row.get('Buy Box: % Amazon 30 days', "0.0"),
            "bb_source": row['Buy Box: Current'],
            "bb_source_converted": row['Buy Box: Current'],  
            "bb_target": row['Buy Box: Current'], 
            "fba_seller_count": row.get('Buy Box Eligible Counts: New FBA', 0),
            "image": row['Image'],
            "is_amazon_selling": row.get('Amazon: Availability of the Amazon offer', "no Amazon offer exists"),
            "is_favorited": row.get('is_favorited', False),  
            "profit": row['profit'],
            "roi": row['roi'],
            "sold_target": row.get('Bought in past month', 0) 
        }

        result_list.append(product_info) 

    if not result_list:
        logging.warning("ROI filtresinden geçen hiçbir satır yok.")
        return {'message': 'No results meet the ROI criteria.'}

    return result_list  
