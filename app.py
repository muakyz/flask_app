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

# Ortam değişkenlerini yükle
load_dotenv()

app = Flask(__name__)
CORS(app)

# Logger Ayarları
logging.basicConfig(level=logging.INFO)

# JWT Ayarları
JWT_SECRET = os.getenv('JWT_SECRET', 'your_jwt_secret_key')  # .env dosyasında tanımlı
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
JWT_EXP_DELTA_SECONDS = int(os.getenv('JWT_EXP_DELTA_SECONDS', 3600))  # 1 saat

# Veritabanı Bağlantı Dizesi Fonksiyonu
def get_connection():
    """
    Veritabanına bağlanmak için kullanılan fonksiyon.
    Bağlantı bilgileri çevresel değişkenlerden alınmalıdır.
    """
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

# Bağlantıyı test etmek için
try:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 AS test")
    row = cursor.fetchone()
    logging.info(f"Test sorgusu başarılı, sonuç: {row.test}")
except Exception as e:
    logging.error(f"SQL Server Bağlantı Hatası: {e}")

# Kullanıcı Kayıt Verisi Doğrulama Fonksiyonu
def validate_registration_data(username, email, password, gsm):
    # Boş alan kontrolü
    if not all([username, email, password, gsm]):
        return False, 'Tüm alanlar gereklidir.'

    # E-posta doğrulama
    email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(email_regex, email):
        return False, 'Geçerli bir e-posta adresi giriniz.'

    # Şifre doğrulama: En az 8 karakter, bir büyük harf, bir küçük harf, bir sayı
    password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$'
    if not re.match(password_regex, password):
        return False, 'Şifre en az 8 karakter, bir büyük harf, bir küçük harf ve bir sayı içermelidir.'

    # GSM numarası doğrulama (sadece 10 basamaklı rakamlar)
    gsm_regex = r'^\d{10}$'
    if not re.match(gsm_regex, gsm):
        return False, 'Geçerli bir GSM numarası giriniz.'

    return True, ''

# JWT Token Oluşturma Fonksiyonu
def generate_jwt(user_id, email, username):
    payload = {
        'id': user_id,
        'email': email,
        'username': username,
        'exp': datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

# JWT Token Doğrulama Dekoratörü
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Token, Authorization header içinde "Bearer <token>" formatında olmalı
        auth_header = request.headers.get('Authorization')
        if auth_header and len(auth_header.split()) == 2:
            token = auth_header.split()[1]
        if not token:
            return jsonify({'message': 'Token gereklidir.'}), 401
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            current_user_id = data['id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token süresi doldu.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Geçersiz token.'}), 401
        return f(current_user_id, *args, **kwargs)
    return decorated

# Kullanıcı Kayıt Endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    gsm = data.get('gsm')

    # 1. Boş alan kontrolü ve doğrulama
    is_valid, message = validate_registration_data(username, email, password, gsm)
    if not is_valid:
        return jsonify({'message': message}), 400

    try:
        cursor = conn.cursor()

        # 2. Kullanıcı adı, e-posta ve GSM'in veritabanında olup olmadığını kontrol et
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

        # 3. Şifreyi hashleyelim
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # 4. Kullanıcıyı veritabanına ekle
        insert_query = """
            INSERT INTO Users (username, email, password, gsm) 
            VALUES (?, ?, ?, ?)
        """
        cursor.execute(insert_query, (username, email, hashed_password, gsm))
        conn.commit()

        return jsonify({'message': 'Kullanıcı başarıyla kaydedildi'}), 201

    except Exception as e:
        logging.error(f"Veritabanı hatası: {e}")
        return jsonify({'message': 'Kullanıcı kaydı sırasında hata oluştu'}), 500

# Kullanıcı Giriş Endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # 1. Boş alan kontrolü
    if not all([email, password]):
        return jsonify({'message': 'E-posta ve şifre gereklidir.'}), 400

    try:
        cursor = conn.cursor()

        # 2. Kullanıcıyı e-posta ile bulma
        query = "SELECT * FROM Users WHERE email = ?"
        cursor.execute(query, (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({'message': 'Kullanıcı bulunamadı'}), 404

        # 3. Şifre doğrulama
        if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            return jsonify({'message': 'Geçersiz şifre'}), 400

        # 4. JWT Token oluşturma
        token = generate_jwt(user.user_id, user.email, user.username)

        # Giriş başarılı yanıtı
        return jsonify({
            'message': 'Giriş başarılı',
            'token': token,
            'user': {
                'userid': user.user_id,
                'username': user.username,
                'email': user.email
            }
        }), 200

    except Exception as e:
        logging.error(f"Giriş hatası: {e}")
        return jsonify({'message': 'Giriş sırasında hata oluştu'}), 500

# Veri Ekleme Endpoint
@app.route('/data', methods=['POST'])
@token_required
def add_data(current_user_id):
    data = request.get_json()
    data_field1 = data.get('dataField1')
    data_field2 = data.get('dataField2')

    # GSM numarası doğrulama (isteğe bağlı)
    # Ek doğrulamalar ekleyebilirsiniz

    try:
        cursor = conn.cursor()
        insert_query = """
            INSERT INTO UserData (user_id, data_field1, data_field2) 
            VALUES (?, ?, ?)
        """
        cursor.execute(insert_query, (current_user_id, data_field1, data_field2))
        conn.commit()
        return jsonify({'message': 'Veri başarıyla eklendi'}), 201

    except Exception as e:
        logging.error(f"Veri ekleme hatası: {e}")
        return jsonify({'message': 'Veri ekleme sırasında bir hata oluştu'}), 500

# Veri Getirme Endpoint
@app.route('/data', methods=['GET'])
@token_required
def get_data(current_user_id):
    try:
        cursor = conn.cursor()
        query = "SELECT * FROM UserData WHERE user_id = ?"
        cursor.execute(query, (current_user_id,))
        rows = cursor.fetchall()
        # Sütun adlarını almak için
        columns = [column[0] for column in cursor.description]
        result = []
        for row in rows:
            row_dict = {}
            for idx, value in enumerate(row):
                row_dict[columns[idx]] = value
            result.append(row_dict)
        return jsonify(result), 200

    except Exception as e:
        logging.error(f"Veri getirme hatası: {e}")
        return jsonify({'message': 'Veri getirme sırasında bir hata oluştu'}), 500


# Seller ID Ekleme Endpoint
@app.route('/add_seller_id_to_tracking', methods=['POST'])
@token_required
def add_seller_id_to_tracking(current_user_id):
    data = request.get_json()
    seller_ids = data.get('seller_id')

    if not seller_ids or not isinstance(seller_ids, list):
        return jsonify({'message': 'Seller ID listesi gerekli ve liste formatında olmalı'}), 400

    try:
        cursor = conn.cursor()

        for seller_id in seller_ids:
            insert_query_userid_sellerid = """
                INSERT INTO Userid_Sellerid (user_id, seller_id) 
                VALUES (?, ?)
            """
            cursor.execute(insert_query_userid_sellerid, (current_user_id, seller_id))

            insert_query_sellerids = """
                INSERT INTO Sellerids (seller_id)
                SELECT ? WHERE NOT EXISTS (SELECT 1 FROM Sellerids WHERE seller_id = ?)
            """
            cursor.execute(insert_query_sellerids, (seller_id, seller_id))

        conn.commit()
        return jsonify({'message': 'Seller ID\'ler başarıyla eklendi'}), 201

    except Exception as e:
        logging.error(f"Veri ekleme hatası: {e}")
        return jsonify({'message': 'Veri ekleme sırasında bir hata oluştu'}), 500







# Uygulamanın Başlatılması
if __name__ == '__main__':
    PORT = 5000
    app.run(host='0.0.0.0', port=PORT, debug=True)
