import pandas as pd
import numpy as np
import warnings
import pyodbc
import logging
import os
import time
import datetime

logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(message)s')

pd.set_option('future.no_silent_downcasting', True)
warnings.filterwarnings("ignore", category=UserWarning, module="openpyxl")
warnings.filterwarnings("ignore", category=pd.errors.PerformanceWarning)
warnings.filterwarnings("ignore", category=pd.errors.SettingWithCopyWarning)
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

def process_files(source_file_path, target_file_path, conversion_rate, current_user_id):
    start_time = time.time()

    try:
        df_source = pd.read_csv(source_file_path)
        df_target = pd.read_csv(target_file_path)
        df_source.columns = df_source.columns.str.replace(' 🚚', '', regex=False)
        df_target.columns = df_target.columns.str.replace(' 🚚', '', regex=False)
    except Exception as e:
        logging.error(f"Excel dosyaları okunurken hata oluştu: {e}")
        raise

    rename_dict = {
        'Buy Box: Current': 'Buy Box: Current',
        'Buy Box: % Amazon 30 days': 'Buy Box: % Amazon 30 days',
        'Buy Box Eligible Offer Count: New FBA': 'Buy Box Eligible Offer Counts: New FBA',
        'FBA Fees:': 'FBA Pick&Pack Fee',
        'Referral Fee based on current Buy Box price': 'Referral Fee based on current Buy Box price'
    }

    try:
        df_source.rename(columns=rename_dict, inplace=True)
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
            df_source[col] = df_source[col].astype(str).str.extract('(\d+\.?\d*)')[0].astype(float)
            df_target[col] = df_target[col].astype(str).str.extract('(\d+\.?\d*)')[0].astype(float)
        logging.info("Belirtilen sütunlar başarıyla float değerine çevrildi.")
    except Exception as e:
        logging.error(f"Sütunları float değerine çevirirken hata oluştu: {e}")
        raise

    df_source_filtered = df_source.dropna(subset=['Buy Box: Current'])
    df_target_filtered = df_target.dropna(subset=['Buy Box: Current'])

    merged_df = pd.merge(df_source_filtered, df_target_filtered, on='ASIN', suffixes=('_source', '_target'))

    logging.info(f"Eşleşen satır sayısı: {merged_df.shape[0]}")

    if merged_df.empty:
        logging.warning("Birleştirilmiş DataFrame boş. İşlem durduruluyor.")
        return pd.DataFrame()

    exchange_rates = {
        'usd': 1.0,    
        'cad': 0.75,   
        'gbp': 1.3    
    }

    source_locale = df_source['Locale'].str.lower().unique()
    target_locale = df_target['Locale'].str.lower().unique()

    def determine_currency(locales):
        for locale in locales:
            if 'ca' in locale:
                return 'cad'
            elif 'com' in locale:
                return 'usd'
            elif 'co.uk' in locale:
                return 'gbp'
        return 'usd'  

    source_currency = determine_currency(source_locale)
    target_currency = determine_currency(target_locale)

    logging.info(f"Kaynak para birimi: {source_currency.upper()}")
    logging.info(f"Hedef para birimi: {target_currency.upper()}")

    try:
        source_rate = exchange_rates[source_currency]
        target_rate = exchange_rates[target_currency]
        conversion_rate = source_rate / target_rate
        logging.info(f"Dönüşüm oranı (Kaynak / Hedef): {conversion_rate}")
    except KeyError as e:
        logging.error(f"Tanımlanmamış para birimi: {e}")
        raise

    merged_df['VAT on Fees'] = (merged_df['FBA Pick&Pack Fee_target'] + merged_df['Referral Fee based on current Buy Box price_target']) * 0.2
    merged_df['Buy Box: Current_source_converted'] = round(merged_df['Buy Box: Current_source'] * conversion_rate, 2)

    merged_df['profit'] = (
        merged_df['Buy Box: Current_target'] - 
        merged_df['FBA Pick&Pack Fee_target'] - 
        merged_df['Referral Fee based on current Buy Box price_target'] - 
        merged_df['VAT on Fees'] - 
        merged_df['Buy Box: Current_source_converted']
    )

    merged_df['roi'] = round((merged_df['profit'] / merged_df['Buy Box: Current_source_converted']) * 100, 2)

    merged_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    merged_df.fillna(0, inplace=True)
    merged_df = merged_df.infer_objects()

    target_images = df_target_filtered.set_index('ASIN')['Image'].to_dict()
    merged_df['Image'] = merged_df['ASIN'].map(target_images)

    result_df = merged_df[['ASIN', 
                           'Buy Box: Current_source', 
                           'Buy Box: Current_source_converted',  
                           'Buy Box: Current_target', 
                           'profit', 
                           'roi',  
                           'Bought in past month_target', 
                           'Buy Box: % Amazon 30 days_target',
                           'Buy Box Eligible Offer Counts: New FBA_target',
                           'Amazon: Availability of the Amazon offer_target',
                           'Image']]

    numeric_columns = ['Buy Box: Current_source', 'Buy Box: Current_source_converted', 
                       'Buy Box: Current_target', 'profit', 'roi']
    for col in numeric_columns:
        result_df[col] = pd.to_numeric(result_df[col], errors='coerce').fillna(0)

    result_df = result_df[result_df['roi'] > 30]

    if result_df.empty:
        logging.warning("ROI filtresinden geçen hiçbir satır yok. Veri tabanına ekleme yapılmayacak.")
    else:
        db_start_time = time.time()

        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.fast_executemany = True

            existing_asins_query = "SELECT asin FROM User_Temporary_Data WHERE user_id = ?"
            cursor.execute(existing_asins_query, (current_user_id,))
            existing_asins = {row[0] for row in cursor.fetchall()}

            insert_data = []
            update_data = []

            for _, row in result_df.iterrows():
                currency_info = f"{source_currency.upper()}/{target_currency.upper()}"  # Kaynak ve hedef para birimlerini yazıyoruz
                if row['ASIN'] not in existing_asins:
                    insert_data.append(( 
                        current_user_id,
                        row['ASIN'],
                        row['profit'],
                        row['Buy Box: Current_source'],
                        row['Buy Box: Current_source_converted'],
                        row['Buy Box: Current_target'],
                        row['Bought in past month_target'],
                        row['Buy Box: % Amazon 30 days_target'],
                        row['Buy Box Eligible Offer Counts: New FBA_target'],
                        row['Amazon: Availability of the Amazon offer_target'],
                        row['roi'],
                        0,
                        row['Image'],
                        currency_info  # Kaynak ve hedef para birimi ekleniyor
                    ))
                else:
                    update_data.append(( 
                        row['profit'],
                        row['Buy Box: Current_source'],
                        row['Buy Box: Current_source_converted'],
                        row['Buy Box: Current_target'],
                        row['Bought in past month_target'],
                        row['Buy Box: % Amazon 30 days_target'],
                        row['Buy Box Eligible Offer Counts: New FBA_target'],
                        row['Amazon: Availability of the Amazon offer_target'],
                        row['roi'],
                        currency_info,  # Güncellenen yeni sütun
                        current_user_id,
                        row['ASIN']
                    ))

            logging.info(f"Yeni eklenmesi gereken satır sayısı: {len(insert_data)}")
            logging.info(f"Güncellenmesi gereken satır sayısı: {len(update_data)}")

            if insert_data:
                insert_query = """ 
                    INSERT INTO User_Temporary_Data (
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
                        currency_info  -- Eklenen yeni sütun
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
                """
                cursor.executemany(insert_query, insert_data)

            if update_data:
                update_query = """ 
                    UPDATE User_Temporary_Data
                    SET profit = ?, 
                        buy_box_current_source = ?, 
                        buy_box_current_source_converted = ?, 
                        buy_box_current_target = ?, 
                        bought_in_past_month_target = ?, 
                        buy_box_amazon_30_days_target = ?, 
                        buy_box_eligible_offer_count = ?, 
                        amazon_availability_offer_target = ?, 
                        roi = ?,
                        currency_info = ?  -- Güncellenen yeni sütun
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

    end_time = time.time()

    processing_duration = db_start_time - start_time if 'db_start_time' in locals() else 0
    total_duration = end_time - start_time

    logging.info(f"Veri işleme süresi: {processing_duration:.2f} saniye")
    logging.info(f"Veritabanına yazma süresi: {db_duration:.2f} saniye" if 'db_duration' in locals() else "Veritabanına yazma süresi hesaplanamadı.")
    logging.info(f"Toplam geçen süre: {total_duration:.2f} saniye")

    central_log_path = os.path.join(os.path.dirname(os.path.dirname(source_file_path)), 'processing_log.txt')
    try:
        with open(central_log_path, 'a') as log_file:
            log_entry = f"{current_user_id}, {total_duration:.2f}, {datetime.datetime.now().isoformat()}\n"
            log_file.write(log_entry)
    except Exception as e:
        logging.error(f"Log dosyasına yazma hatası: {e}")

    for locale in target_locale:
        if 'ca' in locale:
            logging.info("Hedef dosya birimi: CAD")
        elif 'com' in locale:
            logging.info("Hedef dosya birimi: USD")
        elif 'co.uk' in locale:
            logging.info("Hedef dosya birimi: GBP")

    for locale in source_locale:
        if 'ca' in locale:
            logging.info("Kaynak dosya birimi: CAD")
        elif 'com' in locale:
            logging.info("Kaynak dosya birimi: USD")
        elif 'co.uk' in locale:
            logging.info("Kaynak dosya birimi: GBP")

    return result_df
