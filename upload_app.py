from flask import Flask, request, jsonify
from flask_cors import CORS
from multiprocessing import Process
import os
import logging
from werkzeug.utils import secure_filename
import process4
from decorators import token_required
import database

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def run_process_files(source_file, target_file, conversion_rate, current_user_id):
    import process3
    process3.process_files(source_file, target_file, conversion_rate, current_user_id)

@app.route('/upload_excel_files', methods=['POST'])
@token_required
def upload_excel_files(current_user_id, user_subscription):
    conversion_rate = request.json.get('conversion_rate', 0.75) 
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user_id))
    
    try:
        source_extensions = ['.csv']
        target_extensions = ['.csv']
        
        source_file = None
        for ext in source_extensions:
            potential_path = os.path.join(user_folder, 'source' + ext)
            if os.path.exists(potential_path):
                source_file = potential_path
                break

        target_file = None
        for ext in target_extensions:
            potential_path = os.path.join(user_folder, 'target' + ext)
            if os.path.exists(potential_path):
                target_file = potential_path
                break

        if not source_file or not target_file:
            return jsonify({'message': 'Source veya target dosyası bulunamadı.'}), 400

        process = Process(target=run_process_files, args=(source_file, target_file, conversion_rate, current_user_id))
        process.start()
        process.join()
    
        conn = database.get_connection()
        cursor = conn.cursor()
        cursor.execute(""" 
            SELECT asin, profit, buy_box_current_source, 
                   buy_box_current_source_converted, 
                   buy_box_current_target, 
                   bought_in_past_month_target, 
                   buy_box_amazon_30_days_target, 
                   buy_box_eligible_offer_count, 
                   amazon_availability_offer_target, 
                   roi, 
                   is_favorited,
                   Image
            FROM User_Temporary_Data 
            WHERE user_id = ?
        """, (current_user_id,))  

        rows = cursor.fetchall()
        data = [
            {
                'asin': row[0],
                'profit': row[1],
                'bb_source': row[2],
                'bb_source_converted': row[3],
                'bb_target': row[4],
                'sold_target': row[5],
                'bb_amazon_percentage': row[6],
                'fba_seller_count': row[7],
                'is_amazon_selling': row[8],
                'roi': row[9],
                'is_favorited': row[10],
                'image': row[11]
            } for row in rows
        ]

        cursor.close()
        conn.close()

        return jsonify(data), 200
    except Exception as e:
        logging.error(f"Dosya işleme hatası: {e}")
        return jsonify({'message': f'Dosya işleme sırasında hata oluştu: {e}'}), 500

if __name__ == '__main__':
    from waitress import serve
    PORT = 5000
    serve(app, host='0.0.0.0', port=PORT, threads=4, connection_limit=200)
