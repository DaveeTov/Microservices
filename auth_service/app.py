import base64
import io
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone

import jwt
import pyotp
import qrcode
from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# ✅ CONFIGURACIÓN DE BASE DE DATOS
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SHARED_DB_DIR = os.path.join(BASE_DIR, '..', 'shared_data')
os.makedirs(SHARED_DB_DIR, exist_ok=True)
DB_NAME = os.path.join(SHARED_DB_DIR, 'main_database.db')
SECRET_KEY = 'jkhfcjkdhsclhjsafjchlkrhfkhjfkñqj'

def init_db():
    """Inicializa la base de datos compartida con todas las tablas necesarias"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            
            # Tabla de usuarios
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    birthdate TEXT,
                    secret_question TEXT,
                    secret_answer TEXT,
                    mfa_secret TEXT,
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabla de tareas
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    create_at TIMESTAMP NOT NULL,
                    deadline TIMESTAMP,
                    status TEXT CHECK(status IN ('InProgress', 'Revision', 'Completed', 'Paused')) NOT NULL DEFAULT 'InProgress',
                    isAlive INTEGER NOT NULL DEFAULT 1,
                    created_by INTEGER NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    priority TEXT CHECK(priority IN ('Low', 'Medium', 'High', 'Critical')) DEFAULT 'Medium',
                    FOREIGN KEY (created_by) REFERENCES users(id)
                )
            ''')
            
            conn.commit()
            print(f"✅ Auth Service: Base de datos inicializada en {DB_NAME}")
            
    except Exception as e:
        print(f"❌ Error inicializando BD: {e}")

def get_utc_now():
    """Obtiene el tiempo actual en UTC"""
    return datetime.now(timezone.utc)

def handle_db_error(operation, error):
    """Manejo centralizado de errores de base de datos"""
    print(f"❌ Error en {operation}: {error}")
    if "database is locked" in str(error).lower():
        return {"error": "Database temporarily unavailable, please try again"}, 503
    elif "constraint" in str(error).lower():
        return {"error": "Data constraint violation"}, 400
    else:
        return {"error": "Internal server error"}, 500

# RUTAS DE LA API

@app.route('/')
def home():
    return jsonify({
        "status": "Auth service activo",
        "timestamp": get_utc_now().isoformat(),
        "version": "1.0.0"
    }), 200

@app.route('/health')
def health_check():
    try:
        # Verificar conexión a la base de datos
        with sqlite3.connect(DB_NAME, timeout=5) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
        
        return jsonify({
            "status": "healthy",
            "database": "connected",
            "timestamp": get_utc_now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "database": "error",
            "error": str(e),
            "timestamp": get_utc_now().isoformat()
        }), 503

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No se recibieron datos'}), 400

        # Validar campos requeridos
        required_fields = ['username', 'password', 'email', 'birthdate', 'secret_question', 'secret_answer']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return jsonify({
                'error': 'Faltan campos requeridos',
                'missing_fields': missing_fields
            }), 400

        # Validaciones adicionales
        if len(data['password']) < 6:
            return jsonify({'error': 'La contraseña debe tener al menos 6 caracteres'}), 400

        if '@' not in data['email']:
            return jsonify({'error': 'Email inválido'}), 400

        # Procesar datos
        hashed_password = generate_password_hash(data['password'])
        mfa_secret = pyotp.random_base32()
        current_time = get_utc_now().isoformat()

        # Insertar en base de datos con timeout
        with sqlite3.connect(DB_NAME, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (
                    username, password, email, birthdate,
                    secret_question, secret_answer, mfa_secret,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data['username'].strip(),
                hashed_password,
                data['email'].strip().lower(),
                data['birthdate'],
                data['secret_question'].strip(),
                data['secret_answer'].strip(),
                mfa_secret,
                current_time,
                current_time
            ))
            conn.commit()
            user_id = cursor.lastrowid

        # Generar QR para MFA
        otp_url = pyotp.TOTP(mfa_secret).provisioning_uri(
            name=data['username'],
            issuer_name="TaskManager"
        )
        
        buffer = io.BytesIO()
        qrcode.make(otp_url).save(buffer, format='PNG')
        img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

        return jsonify({
            'success': True,
            'message': 'Usuario registrado correctamente',
            'data': {
                'user_id': user_id,
                'username': data['username'],
                'email': data['email'],
                'qrCodeUrl': f"data:image/png;base64,{img_base64}"
            },
            'server_time': current_time
        }), 201

    except sqlite3.IntegrityError as e:
        if "username" in str(e).lower():
            return jsonify({'error': 'El nombre de usuario ya existe'}), 409
        elif "email" in str(e).lower():
            return jsonify({'error': 'El email ya está registrado'}), 409
        else:
            return jsonify({'error': 'Datos duplicados'}), 409
    
    except sqlite3.Error as e:
        error_response = handle_db_error("register", e)
        return jsonify(error_response[0]), error_response[1]
    
    except Exception as e:
        print(f"❌ Error inesperado en register: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No se recibieron datos'}), 400

        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': 'Usuario y contraseña son requeridos'}), 400

        print(f"🔍 Intento de login para: {username}")

        # Buscar usuario
        with sqlite3.connect(DB_NAME, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, password, email, status FROM users WHERE username = ?", 
                (username,)
            )
            user = cursor.fetchone()

        if not user:
            print(f"❌ Usuario {username} no encontrado")
            time.sleep(1)  # Prevenir timing attacks
            return jsonify({'error': 'Credenciales incorrectas'}), 401

        user_id, db_username, db_password, email, status = user

        if status != 'active':
            return jsonify({'error': 'Usuario inactivo'}), 403

        if not check_password_hash(db_password, password):
            print(f"❌ Contraseña incorrecta para {username}")
            time.sleep(1)  # Prevenir timing attacks
            return jsonify({'error': 'Credenciales incorrectas'}), 401

        print(f"✅ Credenciales válidas para {username}")

        # Generar token temporal
        current_utc = get_utc_now()
        temp_token = jwt.encode({
            'id': user_id,
            'username': db_username,
            'email': email,
            'temp': True,
            'exp': int((current_utc + timedelta(minutes=10)).timestamp()),
            'iat': int(current_utc.timestamp())
        }, SECRET_KEY, algorithm='HS256')

        return jsonify({
            'success': True,
            'message': 'Credenciales válidas - se requiere código OTP',
            'data': {
                'tempToken': temp_token,
                'requires_otp': True,
                'user': {
                    'id': user_id,
                    'username': db_username,
                    'email': email
                }
            },
            'server_time': current_utc.isoformat()
        }), 200

    except sqlite3.Error as e:
        error_response = handle_db_error("login", e)
        return jsonify(error_response[0]), error_response[1]
    
    except Exception as e:
        print(f"❌ Error en login: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No se recibieron datos'}), 400
        
        temp_token = data.get('tempToken')
        otp_code = data.get('otpCode', '').strip()
        
        if not temp_token or not otp_code:
            return jsonify({'error': 'Token temporal y código OTP son requeridos'}), 400

        # Validar formato del código OTP
        if not otp_code.isdigit() or len(otp_code) != 6:
            return jsonify({'error': 'El código OTP debe ser de 6 dígitos'}), 400

        # Decodificar token temporal
        try:
            decoded_token = jwt.decode(temp_token, SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token temporal expirado. Vuelve a iniciar sesión'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token temporal inválido'}), 401
        
        if not decoded_token.get('temp'):
            return jsonify({'error': 'Token inválido'}), 401
        
        user_id = decoded_token['id']
        username = decoded_token['username']
        
        # Obtener secreto MFA
        with sqlite3.connect(DB_NAME, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT mfa_secret, status FROM users WHERE id = ?", 
                (user_id,)
            )
            user = cursor.fetchone()
        
        if not user or not user[0]:
            return jsonify({'error': 'Usuario no encontrado o sin MFA configurado'}), 404
            
        if user[1] != 'active':
            return jsonify({'error': 'Usuario inactivo'}), 403
        
        mfa_secret = user[0]
        
        # Verificar OTP con tolerancia de tiempo
        totp = pyotp.TOTP(mfa_secret)
        current_time = int(get_utc_now().timestamp())
        
        is_valid = False
        # Probar con ventana de tolerancia (±2 intervalos = ±60 segundos)
        for window in range(-2, 3):
            test_time = current_time + (window * 30)
            expected_code = totp.at(test_time)
            if expected_code == otp_code:
                is_valid = True
                print(f"✅ Código OTP válido en ventana {window} para {username}")
                break
        
        if not is_valid:
            print(f"❌ Código OTP inválido para {username}. Código: {otp_code}")
            return jsonify({
                'error': 'Código OTP inválido',
                'message': 'Verifica que tu dispositivo tenga la hora correcta'
            }), 401
        
        # Actualizar último acceso
        current_utc = get_utc_now()
        with sqlite3.connect(DB_NAME, timeout=5) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET updated_at = ? WHERE id = ?", 
                (current_utc.isoformat(), user_id)
            )
            conn.commit()
        
        # Generar token JWT final
        final_token = jwt.encode({
            'id': user_id,
            'username': username,
            'email': decoded_token.get('email'),
            'exp': int((current_utc + timedelta(hours=24)).timestamp()),
            'iat': int(current_utc.timestamp())
        }, SECRET_KEY, algorithm='HS256')
        
        print(f"✅ Login exitoso para {username}")
        
        return jsonify({
            'success': True,
            'message': 'Autenticación exitosa',
            'data': {
                'token': final_token,
                'user': {
                    'id': user_id,
                    'username': username,
                    'email': decoded_token.get('email')
                },
                'expires_in': 86400  # 24 horas en segundos
            },
            'server_time': current_utc.isoformat()
        }), 200
        
    except sqlite3.Error as e:
        error_response = handle_db_error("verify-otp", e)
        return jsonify(error_response[0]), error_response[1]
    
    except Exception as e:
        print(f"❌ Error en verify-otp: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/server-time', methods=['GET'])
def server_time():
    """Devuelve el tiempo actual del servidor para sincronización"""
    current_utc = get_utc_now()
    
    return jsonify({
        "server_utc": current_utc.isoformat(),
        "unix_timestamp": int(current_utc.timestamp()),
        "timezone": "UTC"
    }), 200

@app.route('/validate-token', methods=['POST'])
def validate_token():
    """Valida un token JWT"""
    try:
        data = request.get_json()
        token = data.get('token') if data else None
        
        if not token:
            # Intentar obtener del header Authorization
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Token requerido'}), 400
        
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            
            # Verificar que no sea un token temporal
            if decoded.get('temp'):
                return jsonify({'error': 'Token temporal no válido para esta operación'}), 401
            
            return jsonify({
                'success': True,
                'valid': True,
                'data': {
                    'user_id': decoded.get('id'),
                    'username': decoded.get('username'),
                    'email': decoded.get('email'),
                    'exp': decoded.get('exp'),
                    'iat': decoded.get('iat')
                }
            }), 200
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido'}), 401
            
    except Exception as e:
        print(f"❌ Error validando token: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/db-status', methods=['GET'])
def db_status():
    """Información sobre el estado de la base de datos"""
    try:
        with sqlite3.connect(DB_NAME, timeout=5) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
        
        return jsonify({
            'success': True,
            'data': {
                'database_path': DB_NAME,
                'database_exists': os.path.exists(DB_NAME),
                'user_count': user_count,
                'tables': tables
            },
            'server_time': get_utc_now().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'database_path': DB_NAME,
            'database_exists': os.path.exists(DB_NAME)
        }), 500

# Manejo de errores global
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'path': request.path,
        'method': request.method
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'error': 'Internal server error'
    }), 500

# Inicialización
print(f"🚀 Iniciando Auth Service...")
print(f"📁 Directorio base: {BASE_DIR}")
print(f"🗃️ Base de datos: {DB_NAME}")

init_db()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5001))
    print(f"🌐 Auth Service corriendo en puerto {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
