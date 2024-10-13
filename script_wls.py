import pandas as pd
import numpy as np
import warnings
import pyodbc
import logging
import os
import time

logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(levelname)s:%(message)s')

pd.set_option('mode.chained_assignment', None)
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=pd.errors.PerformanceWarning)
warnings.filterwarnings("ignore", category=pd.errors.DtypeWarning)

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

def process_files_wls(txt_file_path, source_file_path, conversion_rate, current_user_id):
    start_time = time.time()

    try:
        df_source = pd.read_csv(txt_file_path, sep=',', header=None, names=['key', 'Buy Box: Current_source'])
        df_target = pd.read_csv(source_file_path)
        df_target.columns = df_target.columns.str.replace(' 🚚', '', regex=False)
    except Exception as e:
        logging.error(f"Dosyalar okunurken hata oluştu: {e}")
        raise

    rename_dict = {
        'Buy Box: Current': 'Buy Box: Current',
        'Buy Box: % Amazon 30 days': 'Buy Box: % Amazon 30 days',
        'Buy Box Eligible Offer Count: New FBA': 'Buy Box Eligible Offer Counts: New FBA',
        'FBA Fees:': 'FBA Pick&Pack Fee',
        'Referral Fee based on current Buy Box price': 'Referral Fee based on current Buy Box price'
    }

    try:
        df_target.rename(columns=rename_dict, inplace=True)
        logging.info("Sütun isimleri başarıyla yeniden adlandırıldı.")
    except Exception as e:
        logging.error(f"Sütun isimlerini yeniden adlandırırken hata oluştu: {e}")
        raise

    float_columns = [
        'Bought in past month',
        'Buy Box: Current',
        'Buy Box: % Amazon 30 days',
        'Buy Box Eligible Offer Counts: New FBA',
        'FBA Pick&Pack Fee',
        'Referral Fee based on current Buy Box price'
    ]

    try:
        for col in float_columns:
            df_target[col] = df_target[col].astype(str).str.extract(r'(\d+\.?\d*)')[0].astype(float)
        df_source['Buy Box: Current_source'] = df_source['Buy Box: Current_source'].astype(float)
        logging.info("Belirtilen sütunlar başarıyla float değerine çevrildi.")
    except Exception as e:
        logging.error(f"Sütunları float değerine çevirirken hata oluştu: {e}")
        raise

    df_target_filtered = df_target.dropna(subset=['Buy Box: Current'])

    df_codes_melted = df_target_filtered[['ASIN', 'Product Codes: EAN', 'Product Codes: UPC']].melt(
        id_vars=['ASIN'],
        value_vars=['Product Codes: EAN', 'Product Codes: UPC', 'ASIN'],
        var_name='matched_column',
        value_name='matched_value'
    ).dropna(subset=['matched_value'])

    df_codes_melted['matched_value'] = df_codes_melted['matched_value'].astype(str)

    df_source['key'] = df_source['key'].astype(str)

    merged_df = pd.merge(df_source, df_codes_melted, left_on='key', right_on='matched_value', how='inner')

    merged_df = pd.merge(merged_df, df_target_filtered, on='ASIN', how='inner', suffixes=('_source', '_target'))

    logging.info(f"Eşleşen satır sayısı: {merged_df.shape[0]}")

    if merged_df.empty:
        logging.warning("Birleştirilmiş DataFrame boş. İşlem durduruluyor.")
        return pd.DataFrame()

    source_currency = 'usd'
    target_locale = merged_df['Locale'].str.lower().unique()

    def determine_currency(locales):
        for locale in locales:
            if 'ca' in locale:
                return 'cad'
            elif 'co.uk' in locale:
                return 'gbp'
            elif 'com' in locale:
                return 'usd'
        return 'usd'

    target_currency = determine_currency(target_locale)

    logging.info(f"Kaynak para birimi: {source_currency.upper()}")
    logging.info(f"Hedef para birimi: {target_currency.upper()}")

    logging.info(f"Kullanılan dönüşüm oranı: {conversion_rate}")

    merged_df['VAT on Fees'] = (merged_df['FBA Pick&Pack Fee'] + merged_df['Referral Fee based on current Buy Box price']) * 0.2
    merged_df['Buy Box: Current_source_converted'] = round(merged_df['Buy Box: Current_source'] * conversion_rate, 2)

    merged_df['profit'] = (
        merged_df['Buy Box: Current'] -
        merged_df['FBA Pick&Pack Fee'] -
        merged_df['Referral Fee based on current Buy Box price'] -
        merged_df['VAT on Fees'] -
        merged_df['Buy Box: Current_source_converted']
    )

    merged_df['roi'] = round((merged_df['profit'] / merged_df['Buy Box: Current_source_converted']) * 100, 2)

    merged_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    merged_df.fillna(0, inplace=True)
    merged_df = merged_df.infer_objects()

    result_df = merged_df[['ASIN',
                           'Buy Box: Current_source',
                           'Buy Box: Current_source_converted',
                           'Buy Box: Current',
                           'profit',
                           'roi',
                           'Bought in past month',
                           'Buy Box: % Amazon 30 days',
                           'Buy Box Eligible Offer Counts: New FBA',
                           'Amazon: Availability of the Amazon offer',
                           'Image',
                           'matched_column',
                           'matched_value']]

    numeric_columns = ['Buy Box: Current_source', 'Buy Box: Current_source_converted',
                       'Buy Box: Current', 'profit', 'roi']
    for col in numeric_columns:
        result_df[col] = pd.to_numeric(result_df[col], errors='coerce').fillna(0)

    #result_df = result_df[result_df['roi'] > 30]

    if result_df.empty:
        logging.warning("ROI filtresinden geçen hiçbir satır yok. Veri tabanına ekleme yapılmayacak.")
    else:
        db_start_time = time.time()

        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.fast_executemany = True

            existing_asins_query = "SELECT asin FROM wls_User_Temporary_Data WHERE user_id = ?"
            cursor.execute(existing_asins_query, (current_user_id,))
            existing_asins = {row[0] for row in cursor.fetchall()}

            insert_data = []
            update_data = []

            for _, row in result_df.iterrows():
                currency_info = f"{source_currency.upper()}/{target_currency.upper()}"
                if row['ASIN'] not in existing_asins:
                    insert_data.append((
                        current_user_id,
                        row['ASIN'],
                        row['profit'],
                        row['Buy Box: Current_source'],
                        row['Buy Box: Current_source_converted'],
                        row['Buy Box: Current'],
                        row['Bought in past month'],
                        row['Buy Box: % Amazon 30 days'],
                        row['Buy Box Eligible Offer Counts: New FBA'],
                        row['Amazon: Availability of the Amazon offer'],
                        row['roi'],
                        0,
                        row['Image'],
                        currency_info,
                        row['matched_column'],
                        row['matched_value']
                    ))
                else:
                    update_data.append((
                        row['profit'],
                        row['Buy Box: Current_source'],
                        row['Buy Box: Current_source_converted'],
                        row['Buy Box: Current'],
                        row['Bought in past month'],
                        row['Buy Box: % Amazon 30 days'],
                        row['Buy Box Eligible Offer Counts: New FBA'],
                        row['Amazon: Availability of the Amazon offer'],
                        row['roi'],
                        currency_info,
                        row['matched_column'],
                        row['matched_value'],
                        current_user_id,
                        row['ASIN']
                    ))

            logging.info(f"Yeni eklenmesi gereken satır sayısı: {len(insert_data)}")
            logging.info(f"Güncellenmesi gereken satır sayısı: {len(update_data)}")

            if insert_data:
                insert_query = """
                    INSERT INTO wls_User_Temporary_Data (
                        user_id, asin, profit,
                        buy_box_current_source, buy_box_current_source_converted,
                        buy_box_current_target,
                        bought_in_past_month_target,
                        buy_box_amazon_30_days_target,
                        buy_box_eligible_offer_count,
                        amazon_availability_offer_target,
                        roi,
                        is_favorited,
                        Image,
                        currency_info,
                        matched_column,
                        matched_value
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                cursor.executemany(insert_query, insert_data)

            if update_data:
                update_query = """
                    UPDATE wls_User_Temporary_Data
                    SET profit = ?,
                        buy_box_current_source = ?,
                        buy_box_current_source_converted = ?,
                        buy_box_current_target = ?,
                        bought_in_past_month_target = ?,
                        buy_box_amazon_30_days_target = ?,
                        buy_box_eligible_offer_count = ?,
                        amazon_availability_offer_target = ?,
                        roi = ?,
                        currency_info = ?,
                        matched_column = ?,
                        matched_value = ?
                    WHERE user_id = ? AND asin = ?
                """
                cursor.executemany(update_query, update_data)

            conn.commit()

        except pyodbc.Error as e:
            conn.rollback()
            logging.error(f"Veritabanına yazma hatası: {e}")
            raise
        finally:
            conn.close()

        db_end_time = time.time()
        db_duration = db_end_time - db_start_time

        logging.info(f"Veritabanına yazma süresi: {db_duration:.2f} saniye")

    end_time = time.time()

    total_duration = end_time - start_time

    logging.info(f"Toplam geçen süre: {total_duration:.2f} saniye")

    return result_df.to_dict(orient='records')
