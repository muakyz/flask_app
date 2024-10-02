# app.py

from flask import Flask, request, jsonify
from flask_cors import CORS
import pyodbc
import bcrypt
import jwt
from functools import wraps
from dotenv import load_dotenv
import os
import re
import logging
from datetime import datetime, timedelta
import uuid

load_dotenv()

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)

JWT_SECRET = os.getenv('JWT_SECRET', 'your_jwt_secret_key')  
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
JWT_EXP_DELTA_SECONDS = int(os.getenv('JWT_EXP_DELTA_SECONDS', 3600))  

def get_connection():
    server = os.getenv('DB_SERVER', '45.155.159.142,1433')
    database = os.getenv('DB_DATABASE', 'AMAZINGO')
    driver = os.getenv('DB_DRIVER', 'ODBC Driver 17 for SQL Server')
    username = os.getenv('DB_USERNAME', 'remote2')
    password = os.getenv('DB_PASSWORD', '207933239')
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

try:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 AS test")
    row = cursor.fetchone()
    logging.info(f"Test sorgusu başarılı, sonuç: {row.test}")
except Exception as e:
    logging.error(f"SQL Server Bağlantı Hatası: {e}")

def validate_registration_data(username, email, password, gsm):
    if not all([username, email, password, gsm]):
        return False, 'Tüm alanlar gereklidir.'

    email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(email_regex, email):
        return False, 'Geçerli bir e-posta adresi giriniz.'

    password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$'
    if not re.match(password_regex, password):
        return False, 'Şifre en az 8 karakter, bir büyük harf, bir küçük harf ve bir sayı içermelidir.'

    gsm_regex = r'^\d{10}$'
    if not re.match(gsm_regex, gsm):
        return False, 'Geçerli bir GSM numarası giriniz.'

    return True, ''

def generate_jwt(user_id, email, username, session_id, subscription_type):
    payload = {
        'id': user_id,
        'email': email,
        'username': username,
        'session_id': session_id,
        'subscription_type': subscription_type,  # Abonelik tipi ekleniyor
        'exp': datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header and len(auth_header.split()) == 2:
            token = auth_header.split()[1]
        if not token:
            return jsonify({'message': 'Token gereklidir.'}), 401
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            current_user_id = data['id']
            token_session_id = data.get('session_id')
            token_subscription_type = data.get('subscription_type')  # Token'dan abonelik tipi alınıyor

            cursor = conn.cursor()
            query = "SELECT session_id, subscription_type FROM Users WHERE user_id = ?"
            cursor.execute(query, (current_user_id,))
            user = cursor.fetchone()

            if not user:
                return jsonify({'message': 'Kullanıcı bulunamadı.'}), 404

            db_session_id = user.session_id
            db_subscription_type = user.subscription_type

            if token_session_id != db_session_id:
                return jsonify({'message': 'Geçersiz veya sona ermiş token.'}), 401

            # Token'daki abonelik tipi ile veritabanındaki abonelik tipi karşılaştırılıyor
            if token_subscription_type != db_subscription_type:
                return jsonify({'message': 'Abonelik bilgileriniz güncel değil.'}), 401

            # Kullanıcı bilgileri fonksiyona geçiriliyor
            return f(current_user_id, db_subscription_type, *args, **kwargs)

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token süresi doldu.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Geçersiz token.'}), 401
        except Exception as e:
            logging.error(f"Token doğrulama hatası: {e}")
            return jsonify({'message': 'Token doğrulama sırasında hata oluştu.'}), 500
    return decorated

def subscription_required(required_level):
    """
    Bu dekoratör, kullanıcının abonelik seviyesini kontrol eder.
    required_level: Erişim için gerekli abonelik seviyesi (2 veya 3)
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(current_user_id, user_subscription, *args, **kwargs):
            if user_subscription >= required_level:
                return f(current_user_id, *args, **kwargs)
            else:
                return jsonify({'message': 'Bu endpoint için yeterli abonelik seviyeniz yok.'}), 403
        return decorated_function
    return decorator

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    gsm = data.get('gsm')
    is_valid, message = validate_registration_data(username, email, password, gsm)
    if not is_valid:
        return jsonify({'message': message}), 400

    try:
        cursor = conn.cursor()
        check_query = """
            SELECT * FROM Users 
            WHERE username = ? OR email = ? OR gsm = ?
        """
        cursor.execute(check_query, (username, email, gsm))
        existing_user = cursor.fetchone()

        if existing_user:
            if existing_user.username == username:
                return jsonify({'message': 'Kullanıcı adı zaten kayıtlı.'}), 409
            if existing_user.email == email:
                return jsonify({'message': 'E-posta adresi zaten kayıtlı.'}), 409
            if existing_user.gsm == gsm:
                return jsonify({'message': 'GSM numarası zaten kayıtlı.'}), 409

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Yeni kullanıcı varsayılan olarak abonelik tipi 1 ile oluşturuluyor
        insert_query = """
            INSERT INTO Users (username, email, password, gsm, subscription_type) 
            VALUES (?, ?, ?, ?, ?)
        """
        cursor.execute(insert_query, (username, email, hashed_password, gsm, 1))
        conn.commit()

        return jsonify({'message': 'Kullanıcı başarıyla kaydedildi'}), 201

    except Exception as e:
        logging.error(f"Veritabanı hatası: {e}")
        return jsonify({'message': 'Kullanıcı kaydı sırasında hata oluştu'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not all([email, password]):
        return jsonify({'message': 'E-posta ve şifre gereklidir.'}), 400

    try:
        cursor = conn.cursor()
        query = "SELECT * FROM Users WHERE email = ?"
        cursor.execute(query, (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({'message': 'Kullanıcı bulunamadı'}), 404

        if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            return jsonify({'message': 'Geçersiz şifre'}), 400

        new_session_id = str(uuid.uuid4())

        update_query = "UPDATE Users SET session_id = ? WHERE user_id = ?"
        cursor.execute(update_query, (new_session_id, user.user_id))
        conn.commit()

        # Kullanıcının abonelik tipi alınıyor
        subscription_type = user.subscription_type

        token = generate_jwt(user.user_id, user.email, user.username, new_session_id, subscription_type)

        return jsonify({
            'message': 'Giriş başarılı',
            'token': token,
            'user': {
                'userid': user.user_id,
                'username': user.username,
                'email': user.email,
                'subscription_type': subscription_type  # Abonelik tipi gönderiliyor
            }
        }), 200

    except Exception as e:
        logging.error(f"Giriş hatası: {e}")
        return jsonify({'message': 'Giriş sırasında hata oluştu'}), 500

@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user_id, user_subscription):
    try:
        cursor = conn.cursor()
        update_query = "UPDATE Users SET session_id = NULL WHERE user_id = ?"
        cursor.execute(update_query, (current_user_id,))
        conn.commit()
        return jsonify({'message': 'Çıkış yapıldı.'}), 200
    except Exception as e:
        logging.error(f"Çıkış hatası: {e}")
        return jsonify({'message': 'Çıkış sırasında hata oluştu'}), 500

# Abonelik Tipi 2 Gerektiren Endpoint'ler
@app.route('/get_sellerids_for_user', methods=['GET'])
@token_required
@subscription_required(2)  # Abonelik tipi 2 ve üzeri
def get_sellerids_for_user(current_user_id):
    try:
        cursor = conn.cursor()
        query = "SELECT seller_id FROM Userid_Sellerid WHERE user_id = ?"
        cursor.execute(query, (current_user_id,))
        rows = cursor.fetchall()
        seller_ids = [row.seller_id for row in rows]
        return jsonify({'seller_ids': seller_ids}), 200
    except Exception as e:
        logging.error(f"Veri çekme hatası: {e}")
        return jsonify({'message': 'Veri çekme sırasında bir hata oluştu.'}), 500

@app.route('/add_seller_id_to_tracking', methods=['POST'])
@token_required
@subscription_required(2)  # Abonelik tipi 2 ve üzeri
def add_seller_id_to_tracking(current_user_id):
    data = request.get_json()
    seller_ids = data.get('seller_id')

    if not seller_ids or not isinstance(seller_ids, list):
        return jsonify({'message': 'Seller ID listesi gerekli ve liste formatında olmalı'}), 400

    try:
        cursor = conn.cursor()

        for seller_id in seller_ids:
            check_userid_sellerid_query = """
                SELECT 1 FROM Userid_Sellerid WHERE user_id = ? AND seller_id = ?
            """
            cursor.execute(check_userid_sellerid_query, (current_user_id, seller_id))
            result_userid_sellerid = cursor.fetchone()

            if not result_userid_sellerid:
                insert_query_userid_sellerid = """
                    INSERT INTO Userid_Sellerid (user_id, seller_id) 
                    VALUES (?, ?)
                """
                cursor.execute(insert_query_userid_sellerid, (current_user_id, seller_id))

            check_sellerids_query = """
                SELECT 1 FROM Sellerids WHERE seller_id = ?
            """
            cursor.execute(check_sellerids_query, (seller_id,))
            result_sellerids = cursor.fetchone()

            if not result_sellerids:
                insert_query_sellerids = """
                    INSERT INTO Sellerids (seller_id)
                    VALUES (?)
                """
                cursor.execute(insert_query_sellerids, (seller_id,))

        conn.commit()
        return jsonify({'message': 'Seller ID\'ler başarıyla eklendi'}), 201

    except Exception as e:
        logging.error(f"Veri ekleme hatası: {e}")
        return jsonify({'message': 'Veri ekleme sırasında bir hata oluştu'}), 500

@app.route('/delete_seller_id_from_tracking', methods=['DELETE'])
@token_required
@subscription_required(2)  # Abonelik tipi 2 ve üzeri
def delete_seller_id_from_tracking(current_user_id):
    data = request.get_json()
    seller_ids = data.get('seller_id')
    if not seller_ids or not isinstance(seller_ids, list):
        return jsonify({'message': 'Seller ID listesi gerekli ve liste formatında olmalı'}), 400
    try:
        cursor = conn.cursor()

        for seller_id in seller_ids:
            delete_query_userid_sellerid = """
                DELETE FROM Userid_Sellerid 
                WHERE user_id = ? AND seller_id = ?
            """
            cursor.execute(delete_query_userid_sellerid, (current_user_id, seller_id))

            check_seller_in_userid_sellerid = """
                SELECT 1 FROM Userid_Sellerid WHERE seller_id = ?
            """
            cursor.execute(check_seller_in_userid_sellerid, (seller_id,))
            result = cursor.fetchone()

            if not result:
                delete_query_sellerids = """
                    DELETE FROM Sellerids WHERE seller_id = ?
                """
                cursor.execute(delete_query_sellerids, (seller_id,))

        conn.commit()
        return jsonify({'message': 'Seller ID\'ler başarıyla silindi'}), 200

    except Exception as e:
        logging.error(f"Veri silme hatası: {e}")
        return jsonify({'message': 'Veri silme sırasında bir hata oluştu'}), 500

@app.route('/get_profit_by_user', methods=['GET'])
@token_required
@subscription_required(3)
def get_profit_by_user(current_user_id):
    try:
        cursor = conn.cursor()

        query = """
            SELECT * 
            FROM PROFIT 
            WHERE asins IN (
                SELECT asins 
                FROM nafs 
                WHERE seller_id IN (
                    SELECT seller_id 
                    FROM Userid_Sellerid 
                    WHERE user_id = ? 
                    AND PROFIT.inserted_at > Userid_Sellerid.inserted_at
                )
            )
        """
        cursor.execute(query, (current_user_id,))
        profits = cursor.fetchall()
        if profits:
            profit_list = []
            for row in profits:
                profit_list.append({
                    'asin': row[0],  
                    'profit': row[1],  
                    'inserted_at': row[2],  
                })
            return jsonify(profit_list), 200
        else:
            return jsonify({'message': 'Kayıt bulunamadı.'}), 404

    except Exception as e:
        logging.error(f"Veritabanı hatası: {e}")
        return jsonify({'message': 'Veri çekme sırasında hata oluştu.'}), 500

@app.route('/premium_profit', methods=['GET'])
@token_required
@subscription_required(3)  
def premium_profit(current_user_id):
    try:
        cursor = conn.cursor()
        query = """
            SELECT * 
            FROM PROFIT 
            WHERE past_month_sold IS NOT NULL 
            AND profit_percentage > 20
        """
        cursor.execute(query)
        premium_profits = cursor.fetchall()

        if premium_profits:
            columns = [col[0] for col in cursor.description]
            profit_list = []
            for row in premium_profits:
                profit_list.append(dict(zip(columns, row)))
            return jsonify(profit_list), 200
        else:
            return jsonify({'message': 'Premium kar kaydı bulunamadı.'}), 404

    except Exception as e:
        logging.error(f"Veritabanı hatası: {e}")
        return jsonify({'message': 'Veri çekme sırasında hata oluştu.'}), 500

@app.route('/beta_request_asin_USA', methods=['POST'])
@token_required
@subscription_required(3)  # Abonelik tipi 3 ve üzeri
def beta_request_asin_USA(current_user_id):
    try:
        asins = request.json.get('asins')
        if not asins or not isinstance(asins, list):
            return jsonify({'message': 'Geçerli ASIN listesi sağlamalısınız.'}), 400
        
        placeholders = ','.join(['?'] * len(asins))
        query = f"SELECT * FROM TRACKING WHERE asins IN ({placeholders})"
        
        cursor.execute(query, asins)
        tracking_results = cursor.fetchall()

        if tracking_results:
            columns = [col[0] for col in cursor.description]
            tracking_list = [dict(zip(columns, row)) for row in tracking_results]
            return jsonify(tracking_list), 200
        else:
            return jsonify({'message': 'Veri bulunamadı.'}), 404

    except Exception as e:
        logging.error(f"Veritabanı hatası: {e}")
        return jsonify({'message': 'Veri çekme sırasında hata oluştu.'}), 500

@app.route('/beta_request_asin_UK', methods=['POST'])
@token_required
@subscription_required(3)  # Abonelik tipi 3 ve üzeri
def beta_request_asin_UK(current_user_id):
    try:
        asins = request.json.get('asins')
        if not asins or not isinstance(asins, list):
            return jsonify({'message': 'Geçerli ASIN listesi sağlamalısınız.'}), 400
        
        placeholders = ','.join(['?'] * len(asins))
        query = f"SELECT * FROM TRACKINGUK WHERE asins IN ({placeholders})"
        
        cursor.execute(query, asins)
        tracking_results = cursor.fetchall()

        if tracking_results:
            columns = [col[0] for col in cursor.description]
            tracking_list = [dict(zip(columns, row)) for row in tracking_results]
            return jsonify(tracking_list), 200
        else:
            return jsonify({'message': 'Veri bulunamadı.'}), 404

    except Exception as e:
        logging.error(f"Veritabanı hatası: {e}")
        return jsonify({'message': 'Veri çekme sırasında hata oluştu.'}), 500

if __name__ == '__main__':
    PORT = 5000
    app.run(host='0.0.0.0', port=PORT, debug=True)
