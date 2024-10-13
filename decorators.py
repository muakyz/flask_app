from functools import wraps
from flask import request, jsonify
import jwt
import os
import logging
from database import get_connection
from datetime import datetime, timezone, timedelta

JWT_SECRET = os.getenv('JWT_SECRET', 'your_jwt_secret_key')
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
JWT_EXP_DELTA_SECONDS = int(os.getenv('JWT_EXP_DELTA_SECONDS', 3600))

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
