import base64
import datetime
import io
import os
import sqlite3

import jwt
import pyotp
import qrcode
from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

# Base de datos y clave secreta
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_NAME = os.path.join(BASE_DIR, 'main_database.db')
SECRET_KEY = 'jkhfcjkdhsclhjsafjchlkrhfkhjfkñqj'

# Inicializar app Flask
app = Flask(__name__)

# Crear tabla si no existe
def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                birthdate TEXT,
                secret_question TEXT,
                secret_answer TEXT,
                mfa_secret TEXT,
                status TEXT DEFAULT 'active'
            )
        ''')

# Registro de usuario con MFA
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    required_fields = ['username', 'password', 'email', 'birthdate', 'secret_question', 'secret_answer']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Faltan campos'}), 400

    hashed_password = generate_password_hash(data['password'])
    mfa_secret = pyotp.random_base32()

    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (
                    username, password, email, birthdate,
                    secret_question, secret_answer, mfa_secret
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                data['username'],
                hashed_password,
                data['email'],
                data['birthdate'],
                data['secret_question'],
                data['secret_answer'],
                mfa_secret
            ))
            conn.commit()
            user_id = cursor.lastrowid

        # Generar URL OTP
        otp_url = pyotp.TOTP(mfa_secret).provisioning_uri(
            name=data['username'], issuer_name="MiAppSegura"
        )

        buffer = io.BytesIO()
        qrcode.make(otp_url).save(buffer)
        img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

        return jsonify({
            'message': 'Usuario registrado correctamente',
            'qrCodeUrl': f"data:image/png;base64,{img_base64}",
            'user_id': user_id
        }), 201

    except sqlite3.IntegrityError:
        return jsonify({'error': 'Nombre de usuario ya existe'}), 409
    except Exception as e:
        print(f"❌ Error inesperado en /register: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500


# Login inicial: usuario y contraseña
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    # Validación mejorada
    if not data:
        return jsonify({'error': 'No se recibieron datos'}), 400
    
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Usuario y contraseña son requeridos'}), 400

    print(f"🔍 Intentando login para usuario: {username}")
    
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            
        if not user:
            print(f"❌ Usuario {username} no encontrado")
            return jsonify({'error': 'Credenciales incorrectas'}), 401
            
        if not check_password_hash(user[2], password):
            print(f"❌ Contraseña incorrecta para usuario {username}")
            return jsonify({'error': 'Credenciales incorrectas'}), 401
            
        print(f"✅ Credenciales válidas para usuario {username}")
        
        # Crear token temporal con tiempo de expiración correcto
        temp_token = jwt.encode({
            'id': user[0],
            'username': user[1],
            'temp': True,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        }, SECRET_KEY, algorithm='HS256')

        print(f"🕒 Token temporal generado para usuario {username}")
        
        return jsonify({
            'message': 'OTP requerido',
            'tempToken': temp_token
        }), 200

    except Exception as e:
        print(f"❌ Error en login: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500


# Validación del OTP - Versión actualizada y limpia
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({'error': 'Token temporal requerido'}), 401
    token = auth_header.split(" ")[1]
    try:
        # ✅ Añadido leeway de 30 segundos para tolerancia en tiempo
        data_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'], leeway=30)
        if not data_token.get('temp'):
            return jsonify({'error': 'Token inválido'}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Token inválido'}), 401
    otp_code = request.json.get('otp')
    user_id = data_token['id']
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT mfa_secret FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
    if row:
        mfa_secret = row[0]
        totp = pyotp.TOTP(mfa_secret)
        if totp.verify(otp_code):
            full_token = jwt.encode({
                'id': user_id,
                'username': data_token['username'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }, SECRET_KEY, algorithm='HS256')
            return jsonify({'token': full_token})
    return jsonify({'error': 'OTP inválido'}), 401


# Ruta para obtener el código OTP actual (solo para desarrollo/debug)
@app.route('/debug-otp', methods=['POST'])
def debug_otp():
    """Endpoint para debug - NO usar en producción"""
    data = request.get_json()
    username = data.get('username')
    
    if not username:
        return jsonify({'error': 'Username requerido'}), 400
    
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT mfa_secret FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
    
    if row:
        mfa_secret = row[0]
        totp = pyotp.TOTP(mfa_secret)
        current_otp = totp.now()
        return jsonify({'current_otp': current_otp})
    
    return jsonify({'error': 'Usuario no encontrado'}), 404


# Inicializar app
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get("PORT", 5001))
    app.run(host='0.0.0.0', port=port)
