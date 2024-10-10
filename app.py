from flask import Flask, request, jsonify
from flask_cors import CORS
import pyodbc
import bcrypt
import random
import string
from mail_utils import send_email
import jwt
from functools import wraps
from dotenv import load_dotenv
import os
import re
import logging
from datetime import datetime, timedelta, timezone
import uuid
from werkzeug.utils import secure_filename
import pandas as pd
import process4
import process3

load_dotenv()

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)

JWT_SECRET = os.getenv('JWT_SECRET', 'your_jwt_secret_key')
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
JWT_EXP_DELTA_SECONDS = int(os.getenv('JWT_EXP_DELTA_SECONDS', 3600))

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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
        'subscription_type': subscription_type,
        'exp': datetime.now(timezone.utc) + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
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
            logging.warning("Token bulunamadı.")
            return jsonify({'message': 'Token gereklidir.'}), 401
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            current_user_id = data['id']
            token_session_id = data.get('session_id')
            token_subscription_type = data.get('subscription_type')

            logging.info(f"Token verileri: user_id={current_user_id}, session_id={token_session_id}, subscription_type={token_subscription_type}")

            conn = get_connection()
            cursor = conn.cursor()
            query = "SELECT session_id, subscription_type FROM Users WHERE user_id = ?"
            cursor.execute(query, (current_user_id,))
            user = cursor.fetchone()
            conn.close()

            if not user:
                logging.warning(f"Kullanıcı bulunamadı: user_id={current_user_id}")
                return jsonify({'message': 'Kullanıcı bulunamadı.'}), 404

            db_session_id = user.session_id
            db_subscription_type = user.subscription_type

            if token_session_id != db_session_id:
                logging.warning(f"Session ID uyuşmazlığı: token_session_id={token_session_id}, db_session_id={db_session_id}")
                return jsonify({'message': 'Geçersiz veya sona ermiş token.'}), 401

            if db_subscription_type < 1:  
                logging.warning(f"Yetersiz abonelik: subscription_type={db_subscription_type}")
                return jsonify({'message': 'Abonelik bilgileriniz güncel değil.'}), 401

            return f(current_user_id, db_subscription_type, *args, **kwargs)

        except jwt.ExpiredSignatureError:
            logging.warning("Token süresi doldu.")
            return jsonify({'message': 'Token süresi doldu.'}), 401
        except jwt.InvalidTokenError:
            logging.warning("Geçersiz token.")
            return jsonify({'message': 'Geçersiz token.'}), 401
        except Exception as e:
            logging.error(f"Token doğrulama hatası: {e}")
            return jsonify({'message': 'Token doğrulama sırasında hata oluştu.'}), 500
    return decorated

def subscription_required(required_level):
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

    if not all([username, email, password, gsm]):
        return jsonify({'message': 'All fields are required.'}), 400

    try:
        cursor = get_connection().cursor()
        cursor.execute("SELECT * FROM Users WHERE email = ?", (email,))
        if cursor.fetchone():
            return jsonify({'message': 'Email already exists.'}), 409

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        verification_code = ''.join(random.choices(string.digits, k=6))

        insert_query = """
            INSERT INTO Users (username, email, password, gsm, subscription_type, is_verified, verification_code)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        cursor.execute(insert_query, (username, email, hashed_password, gsm, 1, 0, verification_code))
        cursor.connection.commit()

        subject = "Email Verification"
        body = f"Hi {username},\n\nYour verification code is: {verification_code}"
        send_email(email, subject, body)

        return jsonify({'message': 'Verification code sent to email.'}), 200
    except Exception as e:
        logging.error(f"Registration error: {e}")
        return jsonify({'message': 'Registration failed.'}), 500

@app.route('/verify_email', methods=['POST'])
def verify_email():
    data = request.get_json()
    email = data.get('email')
    verification_code = data.get('verification_code')

    try:
        cursor = get_connection().cursor()
        cursor.execute("SELECT * FROM Users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({'message': 'User not found.'}), 404

        if user.verification_code != verification_code:
            return jsonify({'message': 'Invalid verification code.'}), 400

        cursor.execute("UPDATE Users SET is_verified = 1, verification_code = NULL WHERE email = ?", (email,))
        cursor.connection.commit()

        return jsonify({'message': 'Email verified successfully.'}), 200
    except Exception as e:
        logging.error(f"Verification error: {e}")
        return jsonify({'message': 'Verification failed.'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({'message': 'Email and password are required.'}), 400

    try:
        cursor = get_connection().cursor()
        cursor.execute("SELECT * FROM Users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if not user or not user.is_verified:
            return jsonify({'message': 'User not found or not verified.'}), 404

        if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            return jsonify({'message': 'Invalid password.'}), 400

        new_session_id = str(uuid.uuid4())
        cursor.execute("UPDATE Users SET session_id = ? WHERE user_id = ?", (new_session_id, user.user_id))
        cursor.connection.commit()

        token = generate_jwt(user.user_id, user.email, user.username, new_session_id, user.subscription_type)
        return jsonify({'message': 'Login successful', 'token': token}), 200
    except Exception as e:
        logging.error(f"Login error: {e}")
        return jsonify({'message': 'Login failed.'}), 500

@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user_id):
    try:
        cursor = get_connection().cursor()
        cursor.execute("UPDATE Users SET session_id = NULL WHERE user_id = ?", (current_user_id,))
        cursor.connection.commit()
        return jsonify({'message': 'Logged out successfully.'}), 200
    except Exception as e:
        logging.error(f"Logout error: {e}")
        return jsonify({'message': 'Logout failed.'}), 500

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    try:
        cursor = get_connection().cursor()
        cursor.execute("SELECT * FROM Users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({'message': 'User not found.'}), 404

        verification_code = ''.join(random.choices(string.digits, k=6))
        cursor.execute("UPDATE Users SET verification_code = ? WHERE email = ?", (verification_code, email))
        cursor.connection.commit()
        subject = "Password Reset Request"
        body = f"Hi,\n\nYour password reset code is: {verification_code}"
        send_email(email, subject, body)

        return jsonify({'message': 'Password reset code sent to email.'}), 200
    except Exception as e:
        logging.error(f"Forgot password error: {e}")
        return jsonify({'message': 'Password reset failed.'}), 500

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    verification_code = data.get('verification_code')
    new_password = data.get('newPassword')

    try:
        cursor = get_connection().cursor()
        cursor.execute("SELECT * FROM Users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({'message': 'User not found.'}), 404

        if user.verification_code != verification_code:
            return jsonify({'message': 'Invalid verification code.'}), 400

        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute("UPDATE Users SET password = ?, verification_code = NULL WHERE email = ?", (hashed_password, email))
        cursor.connection.commit()

        return jsonify({'message': 'Password reset successfully.'}), 200
    except Exception as e:
        logging.error(f"Reset password error: {e}")
        return jsonify({'message': 'Password reset failed.'}), 500

@app.route('/get_sellerids_for_user', methods=['GET'])
@token_required
@subscription_required(1)
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


@app.route('/get_user_info', methods=['GET'])
@token_required
@subscription_required(1)
def get_user_info(current_user_id):
    try:
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE user_id = ?"
        cursor.execute(query, (current_user_id,))
        row = cursor.fetchone() 
        if row:
            user_info = {
                'user_id': row.user_id,
                'username': row.username,
                'email': row.email,
                'password': row.password,
                'gsm': row.gsm,
                'session_id': row.session_id,
                'subscription_type': row.subscription_type
            }
            return jsonify({'user_info': user_info}), 200
        else:
            return jsonify({'message': 'Kullanıcı bulunamadı.'}), 404

    except Exception as e:
        logging.error(f"Veri çekme hatası: {e}")
        return jsonify({'message': 'Veri çekme sırasında bir hata oluştu.'}), 500


@app.route('/form_sender', methods=['POST'])
def form_sender():
    data = request.get_json()
    subject = data.get('subject')
    message = data.get('message')

    if not subject or not message:
        return jsonify({'success': False, 'message': 'Konu ve mesaj alanları gereklidir.'}), 400

    recipient = 'support@waytbeta.xyz' 

    try:
        success, msg = send_email(recipient, subject, message)
        if success:
            return jsonify({'success': True, 'message': 'Mesajınız başarıyla gönderildi.'}), 200
        else:
            return jsonify({'success': False, 'message': msg}), 500
    except Exception as e:
        logging.error(f"Form gönderimi sırasında hata: {e}")
        return jsonify({'success': False, 'message': 'Mesaj gönderimi sırasında bir hata oluştu.'}), 500







@app.route('/add_seller_id_to_tracking', methods=['POST'])
@token_required
@subscription_required(1)
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
@subscription_required(1)
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
            columns = [col[0] for col in cursor.description]
            
            profit_list = []
            for row in profits:
                profit_list.append(dict(zip(columns, row)))

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
@subscription_required(3)
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
@subscription_required(3)
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

@app.route('/beta_request_asin_AU', methods=['POST'])
@token_required
@subscription_required(3)
def beta_request_asin_AU(current_user_id):
    try:
        asins = request.json.get('asins')
        if not asins or not isinstance(asins, list):
            return jsonify({'message': 'Geçerli ASIN listesi sağlamalısınız.'}), 400
        placeholders = ','.join(['?'] * len(asins))
        query = f"SELECT * FROM TRACKINGAU WHERE asins IN ({placeholders})"
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

@app.route('/delete_asin', methods=['POST'])

@token_required
def delete_asin(current_user_id, user_subscription):
    try:
        data = request.get_json()
        asin = data.get('asin')
        
        if not asin:
            return jsonify({'message': 'ASIN eksik'}), 400

        cursor = conn.cursor()
        cursor.execute(""" 
            DELETE FROM User_Temporary_Data WHERE user_id = ? AND asin = ?
        """, (current_user_id, asin))
        conn.commit()

        return jsonify({'message': 'ASIN başarıyla silindi'}), 200

    except Exception as e:
        logging.error(f"ASIN silme hatası: {e}")
        return jsonify({'message': f'ASIN silme sırasında hata oluştu: {e}'}), 500

# app.py
@app.route('/delete_non_favorited_asin', methods=['POST'])
@token_required
def delete_non_favorited_asin(current_user_id, user_subscription):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        delete_query = """
            DELETE FROM User_Temporary_Data
            WHERE user_id = ? AND is_favorited = 0
        """
        cursor.execute(delete_query, (current_user_id,))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'message': 'Favori olmayan ASIN\'ler başarıyla silindi.'}), 200
    except Exception as e:
        logging.error(f"ASIN silme hatası: {e}")
        return jsonify({'message': f'ASIN silme sırasında hata oluştu: {e}'}), 500


@app.route('/update_favorited_asin', methods=['POST'])
@token_required
def update_favorited_asin(current_user_id, user_subscription):
    try:
        data = request.get_json()
        asin = data.get('asin')
        is_favorited = data.get('is_favorited', 0)

        if not asin:
            return jsonify({'message': 'ASIN eksik'}), 400

        cursor = conn.cursor()
        cursor.execute(""" 
            UPDATE User_Temporary_Data 
            SET is_favorited = ? 
            WHERE user_id = ? AND asin = ?
        """, (is_favorited, current_user_id, asin))
        conn.commit()

        return jsonify({'message': 'Favori durumu güncellendi.'}), 200

    except Exception as e:
        logging.error(f"Favori durumu güncelleme hatası: {e}")
        return jsonify({'message': f'Favori durumu güncelleme sırasında hata oluştu: {e}'}), 500

@app.route('/get_favorite_asins', methods=['GET'])
@token_required
@subscription_required(1)
def get_favorite_asins(current_user_id, *args, **kwargs):
    try:
        cursor = conn.cursor()
        query = """
            SELECT 
                asin AS "ASIN", 
                amazon_availability_offer_target AS "Is Amazon Offer Exist?",
                buy_box_current_source AS "Cost", 
                buy_box_current_target AS "BuyBox Price",
                Image, 
                profit AS "PROFIT", 
                bought_in_past_month_target AS "Past Month Sold", 
                buy_box_eligible_offer_count AS "Total Sellers(FBA)", 
                buy_box_amazon_30_days_target AS "Amazon BB %", 
                roi AS "ROI %", 
                is_favorited AS "Favori",
                currency_info AS "Currency Info"  -- New column added
            FROM User_Temporary_Data 
            WHERE user_id = ? 
              AND is_favorited = 1
        """
        cursor.execute(query, (current_user_id,))
        favorite_asins = cursor.fetchall()

        if favorite_asins:
            columns = [col[0] for col in cursor.description]
            favorite_asins_list = []
            for row in favorite_asins:
                favorite_asins_list.append(dict(zip(columns, row)))

            return jsonify(favorite_asins_list), 200
        else:
            return jsonify({'message': 'Favori ASIN bulunamadı.'}), 404

    except Exception as e:
        logging.error(f"Veritabanı hatası: {e}")
        return jsonify({'message': 'Favori ASIN\'ler alınırken hata oluştu.'}), 500




@app.route('/upload_excel_files', methods=['POST'])
@token_required
def upload_excel_files(current_user_id, user_subscription):
    conversion_rate = request.json.get('conversion_rate', 0.75) 
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user_id))
    
    try:
        source_extensions = ['.csv', '.xlsx', '.xls']
        target_extensions = ['.csv', '.xlsx', '.xls']
        
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

        result_df = process3.process_files(source_file, target_file, conversion_rate, current_user_id)
        
        os.remove(source_file)
        os.remove(target_file)

        conn = get_connection()
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
            WHERE user_id = ? and is_favorited = '0'
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



@app.route('/upload_files', methods=['POST'])
@token_required 
def upload_files(current_user_id, user_subscription):
    if 'file' not in request.files or 'file_type' not in request.form:
        return jsonify({'message': 'Dosya veya dosya tipi eksik'}), 400

    file = request.files['file']
    file_type = request.form['file_type']

    if file.filename == '':
        return jsonify({'message': 'Dosya adı boş'}), 400

    allowed_extensions = {'.xlsx', '.xls', '.csv'}
    if not any(file.filename.endswith(ext) for ext in allowed_extensions):
        return jsonify({'message': 'Geçersiz dosya türü. Sadece .xlsx, .xls ve .csv dosyalarına izin verilir.'}), 400

    filename = secure_filename(file.filename)
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user_id))
    os.makedirs(user_folder, exist_ok=True)

    if file_type == 'source':
        filename = 'source' + os.path.splitext(filename)[1]
    elif file_type == 'target':
        filename = 'target' + os.path.splitext(filename)[1]
    else:
        return jsonify({'message': 'Geçersiz dosya tipi.'}), 400

    file_path = os.path.join(user_folder, filename)
    file.save(file_path)

    try:
        currency = process4.get_currency(file_path)
        return jsonify({'message': 'Dosya başarıyla yüklendi.', 'currency': currency}), 200
    except Exception as e:
        logging.error(f"Dosya işleme hatası: {e}")
        return jsonify({'message': f'Dosya işlenirken hata oluştu: {e}'}), 500


@app.route('/check_favorited_count', methods=['GET'])
@token_required
@subscription_required(1)
def check_favorited_count(current_user_id, *args, **kwargs):
    try:
        cursor = conn.cursor()
        query = """
            SELECT 
                u.subscription_type,
                COUNT(ud.is_favorited) AS favorited_count
            FROM Users u
            LEFT JOIN User_Temporary_Data ud ON u.user_id = ud.user_id AND ud.is_favorited = 1
            WHERE u.user_id = ?
            GROUP BY u.subscription_type
        """
        cursor.execute(query, (current_user_id,))
        result = cursor.fetchone()

        if result:
            subscription_type, favorited_count = result
            return jsonify({
                'user_id': current_user_id,
                'subscription_type': subscription_type,
                'favorited_count': favorited_count
            }), 200
        else:
            return jsonify({'message': 'User not found.'}), 404

    except Exception as e:
        logging.error(f"Database error: {e}")
        return jsonify({'message': 'Error checking favorite count.'}), 500






if __name__ == '__main__':
    PORT = 5000
    app.run(host='0.0.0.0', port=PORT, debug=True)
