import base64
import io
import os
import sqlite3

import jwt
import pyotp
import qrcode
from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash
from flask_cors import CORS
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_NAME = os.path.join(BASE_DIR, 'main_database.db')
SECRET_KEY = 'jkhfcjkdhsclhjsafjchlkrhfkhjfkñqj'


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


@app.route('/')
def home():
    return jsonify({"status": "Auth service activo"}), 200


@app.route('/health')
def health_check():
    return jsonify({"status": "ok"}), 200


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


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

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

        temp_token = jwt.encode({
            'id': user[0],
            'username': user[1],
            'temp': True,
            'exp': datetime.utcnow() + timedelta(minutes=5)
        }, SECRET_KEY, algorithm='HS256')

        print(f"🕒 Token temporal generado para usuario {username}")

        return jsonify({
            'message': 'OTP requerido',
            'tempToken': temp_token
        }), 200

    except Exception as e:
        print(f"❌ Error en login: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/server-time', methods=['GET'])
def server_time():
    return jsonify({"server_utc": datetime.utcnow().isoformat()})


init_db()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5001))
    app.run(host='0.0.0.0', port=port)
