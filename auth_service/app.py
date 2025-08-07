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
CORS(app, resources={r"/*": {"origins": "*"}})

# ✅ CORRIGIENDO PATHS - Base de datos compartida entre servicios
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# Subir un nivel para compartir BD entre todos los servicios
SHARED_DB_DIR = os.path.join(BASE_DIR, '..', 'shared_data')
os.makedirs(SHARED_DB_DIR, exist_ok=True)  # Crear directorio si no existe
DB_NAME = os.path.join(SHARED_DB_DIR, 'main_database.db')
SECRET_KEY = 'jkhfcjkdhsclhjsafjchlkrhfkhjfkñqj'

# ✅ FUNCIÓN MEJORADA DE INICIALIZACIÓN DE BD COMPARTIDA
def init_db():
    """Inicializa la base de datos compartida con todas las tablas necesarias"""
    # Verificar si la BD ya existe
    db_exists = os.path.exists(DB_NAME)
    
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            
            # ✅ TABLA DE USUARIOS
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
            
            # ✅ TABLA DE TAREAS (para el task service)
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
            
            # Verificar si hay datos
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM tasks")
            task_count = cursor.fetchone()[0]
            
            if not db_exists:
                print(f"✅ Base de datos compartida creada: {DB_NAME}")
            else:
                print(f"✅ Base de datos compartida encontrada: {DB_NAME}")
                print(f"   - Usuarios: {user_count}")
                print(f"   - Tareas: {task_count}")
                
            conn.commit()
    except Exception as e:
        print(f"❌ Error inicializando BD compartida: {e}")


# ✅ FUNCIÓN PARA OBTENER TIEMPO UTC CONSISTENTE
def get_utc_now():
    """Obtiene el tiempo actual en UTC de forma consistente"""
    return datetime.now(timezone.utc)


# ✅ FUNCIÓN PARA CONVERTIR TIMESTAMP DE CLIENTE
def parse_client_time(client_timestamp):
    """
    Convierte timestamp del cliente a UTC
    Acepta tanto timestamps Unix como strings ISO
    """
    try:
        if isinstance(client_timestamp, (int, float)):
            # Timestamp Unix
            return datetime.fromtimestamp(client_timestamp, tz=timezone.utc)
        elif isinstance(client_timestamp, str):
            # String ISO con timezone
            if client_timestamp.endswith('Z'):
                return datetime.fromisoformat(client_timestamp.replace('Z', '+00:00'))
            else:
                return datetime.fromisoformat(client_timestamp)
        else:
            return get_utc_now()
    except:
        return get_utc_now()


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
        return jsonify({'error': 'Faltan campos requeridos'}), 400

    if len(data['password']) < 6:
        return jsonify({'error': 'La contraseña debe tener al menos 6 caracteres'}), 400

    hashed_password = generate_password_hash(data['password'])
    mfa_secret = pyotp.random_base32()
    current_time = get_utc_now().isoformat()

    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (
                    username, password, email, birthdate,
                    secret_question, secret_answer, mfa_secret,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data['username'],
                hashed_password,
                data['email'],
                data['birthdate'],
                data['secret_question'],
                data['secret_answer'],
                mfa_secret,
                current_time,
                current_time
            ))
            conn.commit()
            user_id = cursor.lastrowid

        # Generar QR para MFA (¡correcto!)
        otp_url = pyotp.TOTP(mfa_secret).provisioning_uri(
            name=data['username'],
            issuer_name="MiAppSegura"
        )
        buffer = io.BytesIO()
        qrcode.make(otp_url).save(buffer)
        img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

        # 🚩 🚩 SOLO ESTO: siempre devuelve un dict
        return jsonify({
            'message': 'Usuario registrado correctamente',
            'qrCodeUrl': f"data:image/png;base64,{img_base64}",
            'user_id': user_id,
            'server_time': get_utc_now().isoformat()
        }), 201

    except sqlite3.IntegrityError as e:
        if "username" in str(e):
            return jsonify({'error': 'Nombre de usuario ya existe'}), 409
        elif "email" in str(e):
            return jsonify({'error': 'Email ya existe'}), 409
        else:
            return jsonify({'error': 'Datos duplicados'}), 409
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
    client_time = data.get('client_time')  # Tiempo del cliente para sincronización

    if not username or not password:
        return jsonify({'error': 'Usuario y contraseña son requeridos'}), 400

    print(f"🔍 Intentando login para usuario: {username}")

    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ? AND status = 'active'", (username,))
            user = cursor.fetchone()

        if not user:
            print(f"❌ Usuario {username} no encontrado o inactivo")
            return jsonify({'error': 'Credenciales incorrectas'}), 401

        if not check_password_hash(user[2], password):
            print(f"❌ Contraseña incorrecta para usuario {username}")
            return jsonify({'error': 'Credenciales incorrectas'}), 401

        print(f"✅ Credenciales válidas para usuario {username}")

        current_utc = get_utc_now()
        temp_token = jwt.encode({
            'id': user[0],
            'username': user[1],
            'temp': True,
            'exp': int((current_utc + timedelta(minutes=10)).timestamp())
          
        }, SECRET_KEY, algorithm='HS256')

        print(f"🕒 Token temporal generado para usuario {username}")

        return jsonify({
            'message': 'OTP requerido',
            'tempToken': temp_token,
            'server_time': current_utc.isoformat(),
            'sync_info': {
                'server_utc': current_utc.isoformat(),
                'unix_timestamp': int(current_utc.timestamp())
            }
        }), 200

    except Exception as e:
        print(f"❌ Error en login: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/server-time', methods=['GET'])
def server_time():
    """
    Devuelve el tiempo actual del servidor en UTC para sincronización
    """
    current_utc = get_utc_now()
    unix_timestamp = int(current_utc.timestamp())
    
    return jsonify({
        "server_utc": current_utc.isoformat(),
        "unix_timestamp": unix_timestamp,
        "timezone": "UTC",
        "iso_format": current_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    }), 200


@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    """
    Verifica el código OTP con tolerancia de tiempo mejorada
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No se recibieron datos'}), 400
    
    temp_token = data.get('tempToken')
    otp_code = data.get('otpCode')
    client_time = data.get('client_time')
    
    if not temp_token or not otp_code:
        return jsonify({'error': 'Token temporal y código OTP son requeridos'}), 400
    
    try:
        # Decodificar token temporal
        decoded_token = jwt.decode(temp_token, SECRET_KEY, algorithms=['HS256'])
        
        if not decoded_token.get('temp'):
            return jsonify({'error': 'Token inválido'}), 401
        
        user_id = decoded_token['id']
        username = decoded_token['username']
        
        # Obtener el secreto MFA del usuario
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT mfa_secret, status FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
        
        if not user or not user[0]:
            return jsonify({'error': 'Usuario no encontrado o sin MFA configurado'}), 404
            
        if user[1] != 'active':
            return jsonify({'error': 'Usuario inactivo'}), 403
        
        mfa_secret = user[0]
        totp = pyotp.TOTP(mfa_secret)
        
        # ✅ VALIDACIÓN MEJORADA CON TOLERANCIA AMPLIA
        current_time = int(get_utc_now().timestamp())
        
        # Probar con ventana de tolerancia amplia (±2 ventanas = ±60 segundos)
        is_valid = False
        for window in range(-2, 3):  # -2, -1, 0, 1, 2
            test_time = current_time + (window * 30)  # Cada ventana son 30 segundos
            expected_code = pyotp.TOTP(mfa_secret).at(test_time)
            if expected_code == otp_code:
                is_valid = True
                print(f"✅ Código OTP válido en ventana {window} para usuario {username}")
                break
        
        if not is_valid:
            # Información de debug (remover en producción)
            current_code = totp.now()
            print(f"❌ Código OTP inválido para usuario {username}")
            print(f"Código recibido: {otp_code}, Código actual: {current_code}")
            return jsonify({
                'error': 'Código OTP inválido',
                'debug_info': {
                    'server_time': get_utc_now().isoformat(),
                    'current_code': current_code  # Solo para debugging
                }
            }), 401
        
        # Actualizar último acceso
        current_utc = get_utc_now()
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET updated_at = ? WHERE id = ?", 
                (current_utc.isoformat(), user_id)
            )
            conn.commit()
        
        # Generar token JWT final (válido por 24 horas)
        final_token = jwt.encode({
            'id': user_id,
            'username': username,
            'exp': current_utc + timedelta(hours=24),
            'issued_at': current_utc.isoformat()
        }, SECRET_KEY, algorithm='HS256')
        
        print(f"✅ Login exitoso para usuario {username}")
        
        return jsonify({
            'message': 'Autenticación exitosa',
            'token': final_token,
            'user': {
                'id': user_id,
                'username': username
            },
            'server_time': current_utc.isoformat()
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token temporal expirado. Vuelve a iniciar sesión'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Token temporal inválido'}), 401
    except Exception as e:
        print(f"❌ Error en verify-otp: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/generate-test-otp', methods=['POST'])
def generate_test_otp():
    """
    Genera un código OTP para el usuario (solo para testing/debug)
    REMOVER EN PRODUCCIÓN
    """
    data = request.get_json()
    username = data.get('username')
    
    if not username:
        return jsonify({'error': 'Username requerido'}), 400
    
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT mfa_secret FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
        
        if not user or not user[0]:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        mfa_secret = user[0]
        totp = pyotp.TOTP(mfa_secret)
        current_utc = get_utc_now()
        current_otp = totp.now()
        
        return jsonify({
            'current_otp': current_otp,
            'server_time': current_utc.isoformat(),
            'unix_timestamp': int(current_utc.timestamp()),
            'message': 'Código generado (solo para testing)',
            'warning': 'REMOVER EN PRODUCCIÓN'
        }), 200
        
    except Exception as e:
        print(f"❌ Error generando OTP de prueba: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500


# ✅ NUEVA RUTA: Verificar estado de la base de datos
@app.route('/db-status', methods=['GET'])
def db_status():
    """Información sobre el estado de la base de datos"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
        
        return jsonify({
            'database_path': DB_NAME,
            'database_exists': os.path.exists(DB_NAME),
            'user_count': user_count,
            'tables': tables,
            'server_time': get_utc_now().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'database_path': DB_NAME,
            'database_exists': os.path.exists(DB_NAME)
        }), 500


# ✅ INICIALIZACIÓN AL ARRANCAR
print(f"🚀 Iniciando Auth Service...")
print(f"📁 Directorio base: {BASE_DIR}")
print(f"🗃️ Base de datos: {DB_NAME}")

# Inicializar BD al arrancar
init_db()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5001))
    print(f"🌐 Servidor corriendo en puerto {port}")
    app.run(host='0.0.0.0', port=port, debug=False)





