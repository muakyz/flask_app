# process4.py
import pandas as pd
import logging

def get_currency(file_path):
    try:
        if file_path.endswith('.csv'):
            df = pd.read_csv(file_path)
        else:
            df = pd.read_excel(file_path)
        locale = df['Locale'].iloc[0].lower()
        if 'ca' in locale:
            return 'CAD'
        elif 'co.uk' in locale:
            return 'GBP'
        elif 'com' in locale:
            return 'USD'
        else:
            return 'USD'  
    except Exception as e:
        logging.error(f"Locale sütunu okunamadı: {e}")
        raise
