import pandas as pd
import numpy as np
import warnings
import logging
import os
import time

logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(message)s')

pd.set_option('mode.chained_assignment', None)
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=pd.errors.PerformanceWarning)
warnings.filterwarnings("ignore", category=pd.errors.DtypeWarning)

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
        var_name='code_type',
        value_name='key'
    ).dropna(subset=['key'])

    df_codes_melted['key'] = df_codes_melted['key'].astype(str)

    df_source['key'] = df_source['key'].astype(str)

    merged_df = pd.merge(df_source, df_codes_melted, on='key', how='inner')

    merged_df = pd.merge(merged_df, df_target_filtered, on='ASIN', how='inner', suffixes=('_source', '_target'))

    logging.info(f"Eşleşen satır sayısı: {merged_df.shape[0]}")

    if merged_df.empty:
        logging.warning("Birleştirilmiş DataFrame boş. İşlem durduruluyor.")
        return pd.DataFrame()

    # Kaynak ve hedef para birimlerini belirleme
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

    # Fonksiyona verilen conversion_rate değerini kullanıyoruz
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

    # Sonuç DataFrame'ine eşleşme bilgilerini ekliyoruz ve sütunları yeniden adlandırıyoruz
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
                           'code_type',
                           'key']].rename(columns={'code_type': 'matched_column', 'key': 'matched_value'})

    numeric_columns = ['Buy Box: Current_source', 'Buy Box: Current_source_converted',
                       'Buy Box: Current', 'profit', 'roi']
    for col in numeric_columns:
        result_df[col] = pd.to_numeric(result_df[col], errors='coerce').fillna(0)

    #result_df = result_df[result_df['roi'] > 30]

    if result_df.empty:
        logging.warning("ROI filtresinden geçen hiçbir satır yok.")
    else:
        logging.info(f"ROI filtresinden geçen satır sayısı: {len(result_df)}")

    end_time = time.time()

    total_duration = end_time - start_time

    logging.info(f"Toplam geçen süre: {total_duration:.2f} saniye")

    return result_df.to_dict(orient='records')
