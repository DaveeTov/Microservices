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

# =========================
# 🔐 Configuración general
# =========================
SECRET_KEY = os.environ.get("SECRET_KEY", "jkhfcjkdhsclhjsafjchlkrhfkhjfkñqj")

# Asegurar JSON UTF-8 siempre
app.config["JSON_AS_ASCII"] = False
app.config["JSONIFY_MIMETYPE"] = "application/json"

# CORS
FRONTEND_ORIGINS = os.environ.get("FRONTEND_ORIGINS", "*")
origins_list = [o.strip() for o in FRONTEND_ORIGINS.split(",") if o.strip()]
CORS(
    app,
    resources={r"/*": {"origins": origins_list if origins_list != ["*"] else "*"}},
    supports_credentials=(origins_list != ["*"])
)

# Normalizar todas las respuestas JSON a "application/json; charset=utf-8"
@app.after_request
def normalize_json_response(response):
    ct = (response.headers.get("Content-Type") or "").lower()
    if "application/json" in ct:
        response.headers["Content-Type"] = "application/json; charset=utf-8"
    return response

# =========================
# 🗃️ Base de datos SQLite
# =========================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SHARED_DB_DIR = os.path.join(BASE_DIR, '..', 'shared_data')
os.makedirs(SHARED_DB_DIR, exist_ok=True)
DB_NAME = os.path.join(SHARED_DB_DIR, 'main_database.db')


def get_conn(timeout=10):
    """
    Conexión SQLite robusta:
    - WAL para concurrencia
    - foreign_keys ON
    - busy_timeout para contención
    - autocommit (isolation_level=None)
    """
    conn = sqlite3.connect(DB_NAME, timeout=timeout, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


def init_db():
    """Inicializa la base de datos con las tablas necesarias"""
    try:
        with get_conn() as conn:
            cursor = conn.cursor()

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

            print(f"✅ Auth Service: Base de datos inicializada en {DB_NAME}")

    except Exception as e:
        print(f"❌ Error inicializando BD: {e}")


def get_utc_now():
    return datetime.now(timezone.utc)


def handle_db_error(operation, error):
    print(f"❌ Error en {operation}: {error}")
    s = str(error).lower()
    if "database is locked" in s:
        return {"error": "Database temporarily unavailable, please try again"}, 503
    elif "constraint" in s or "unique" in s:
        return {"error": "Data constraint violation"}, 400
    else:
        return {"error": "Internal server error"}, 500


# =========================
#        RUTAS API
# =========================
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
        with get_conn(timeout=5) as conn:
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
        # include_qr en query o body (default: True)
        include_qr_qs = request.args.get("include_qr")
        data = request.get_json(silent=True) or {}
        include_qr_body = data.get("include_qr")
        include_qr = True
        if isinstance(include_qr_body, bool):
            include_qr = include_qr_body
        elif isinstance(include_qr_qs, str):
            include_qr = include_qr_qs.lower() not in ("0", "false", "no")

        if not data or not isinstance(data, dict):
            return jsonify({'error': 'No se recibieron datos'}), 400

        # Validar campos requeridos
        required_fields = ['username', 'password', 'email', 'birthdate', 'secret_question', 'secret_answer']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return jsonify({
                'error': 'Faltan campos requeridos',
                'missing_fields': missing_fields
            }), 400

        if len(data['password']) < 6:
            return jsonify({'error': 'La contraseña debe tener al menos 6 caracteres'}), 400
        if '@' not in data['email']:
            return jsonify({'error': 'Email inválido'}), 400

        # Procesar datos
        hashed_password = generate_password_hash(data['password'])
        mfa_secret = pyotp.random_base32()
        current_time = get_utc_now().isoformat()

        # Insertar en base
        with get_conn(timeout=10) as conn:
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
            user_id = cursor.lastrowid

        # Respuesta base
        resp_data = {
            'user_id': user_id,
            'username': data['username'],
            'email': data['email']
        }

        # Incluir QR si corresponde
        if include_qr:
            totp = pyotp.TOTP(mfa_secret)
            otp_url = totp.provisioning_uri(name=data['username'], issuer_name="TaskManager")

            buffer = io.BytesIO()
            qrcode.make(otp_url).save(buffer, format='PNG')
            img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

            # Compatibilidad + campos “JSON puros”
            resp_data['qrCodeUrl'] = f"data:image/png;base64,{img_base64}"
            resp_data['qrPngBase64'] = img_base64
            resp_data['otpauthUrl'] = otp_url

        return jsonify({
            'success': True,
            'message': 'Usuario registrado correctamente',
            'data': resp_data,
            'server_time': current_time
        }), 201

    except sqlite3.IntegrityError as e:
        s = str(e).lower()
        if "username" in s:
            return jsonify({'error': 'El nombre de usuario ya existe'}), 409
        elif "email" in s:
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

        # Buscar usuario
        with get_conn(timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, password, email, status FROM users WHERE username = ?",
                (username,)
            )
            user = cursor.fetchone()

        if not user:
            time.sleep(1)
            return jsonify({'error': 'Credenciales incorrectas'}), 401

        user_id, db_username, db_password, email, status = user

        if status != 'active':
            return jsonify({'error': 'Usuario inactivo'}), 403

        if not check_password_hash(db_password, password):
            time.sleep(1)
            return jsonify({'error': 'Credenciales incorrectas'}), 401

        # Token temporal (10 min)
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
        with get_conn(timeout=10) as conn:
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

        # Verificar OTP con tolerancia de tiempo ±60s
        totp = pyotp.TOTP(mfa_secret)
        current_time = int(get_utc_now().timestamp())

        is_valid = False
        for window in range(-2, 3):  # -60s a +60s
            test_time = current_time + (window * 30)
            if totp.at(test_time) == otp_code:
                is_valid = True
                break

        if not is_valid:
            return jsonify({
                'error': 'Código OTP inválido',
                'message': 'Verifica que tu dispositivo tenga la hora correcta'
            }), 401

        # Actualizar último acceso
        current_utc = get_utc_now()
        with get_conn(timeout=5) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET updated_at = ? WHERE id = ?",
                (current_utc.isoformat(), user_id)
            )

        # Generar token JWT final (24h)
        final_token = jwt.encode({
            'id': user_id,
            'username': username,
            'email': decoded_token.get('email'),
            'exp': int((current_utc + timedelta(hours=24)).timestamp()),
            'iat': int(current_utc.timestamp())
        }, SECRET_KEY, algorithm='HS256')

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
                'expires_in': 86400
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
    current_utc = get_utc_now()
    return jsonify({
        "server_utc": current_utc.isoformat(),
        "unix_timestamp": int(current_utc.timestamp()),
        "timezone": "UTC"
    }), 200


@app.route('/validate-token', methods=['POST'])
def validate_token():
    try:
        data = request.get_json()
        token = data.get('token') if data else None

        if not token:
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

        if not token:
            return jsonify({'error': 'Token requerido'}), 400

        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
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
    try:
        with get_conn(timeout=5) as conn:
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


# =========================
#   Manejo de errores
# =========================
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


# =========================
#     Inicialización
# =========================
print("🚀 Iniciando Auth Service...")
print(f"📁 Directorio base: {BASE_DIR}")
print(f"🗃️ Base de datos: {DB_NAME}")

init_db()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5001))
    print(f"🌐 Auth Service corriendo en puerto {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
