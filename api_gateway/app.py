import json
import time
import os
import logging
from datetime import datetime

import jwt
import requests
from flask import Flask, make_response, request, Response
from flask_cors import CORS

# Configuración de logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
CORS(app,
     origins=["*"],
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

SECRET_KEY = 'jkhfcjkdhsclhjsafjchlkrhfkhjfkñqj'
JWT_ALGORITHM = 'HS256'

# Guardar logs de peticiones
def save_log(data):
    try:
        log_line = json.dumps(data, ensure_ascii=False)
        with open("gateway_logs.jsonl", "a", encoding="utf-8") as log_file:
            log_file.write(log_line + "\n")
    except Exception as e:
        logging.error(f"Error saving log: {e}")

# Middleware para registrar la petición
@app.before_request
def log_request():
    request.start_time = time.time()
    json_payload = request.get_json(silent=True)
    usuario = None
    token = request.headers.get("Authorization")
    
    if token and token.startswith("Bearer "):
        try:
            decoded = jwt.decode(token[7:], SECRET_KEY, algorithms=[JWT_ALGORITHM])
            usuario = decoded.get("username") or decoded.get("email") or "desconocido"
        except jwt.ExpiredSignatureError:
            usuario = "token expirado"
        except jwt.InvalidTokenError:
            usuario = "token inválido"
    elif isinstance(json_payload, dict) and 'email' in json_payload:
        usuario = json_payload['email']

    path_parts = request.path.strip("/").split("/")
    servicio = path_parts[0] if path_parts else "desconocido"
    request.log_data = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "method": request.method,
        "path": request.path,
        "servicio": servicio,
        "usuario": usuario,
        "ip": request.remote_addr,
    }

@app.after_request
def log_response(response):
    try:
        duration = time.time() - getattr(request, 'start_time', time.time())
        log_data = getattr(request, 'log_data', {})
        log_data.update({
            "status_code": response.status_code,
            "response_time_seconds": round(duration, 3)
        })
        save_log(log_data)
    except Exception as e:
        logging.error(f"Error in after_request: {e}")
    return response

# URLs de los servicios
AUTH_SERVICE_URL = os.environ.get("AUTH_SERVICE_URL", "https://auth-service-75ux.onrender.com")
USER_SERVICE_URL = os.environ.get("USER_SERVICE_URL", "https://user-service-6hc6.onrender.com")
TASK_SERVICE_URL = os.environ.get("TASK_SERVICE_URL", "https://task-service-v5ke.onrender.com")

@app.route('/')
def home():
    return {'status': 'API Gateway activo', 'timestamp': datetime.utcnow().isoformat()}, 200

@app.route('/health', methods=['GET'])
def health():
    return {'status': 'OK', 'message': 'Proxy server running', 'timestamp': datetime.utcnow().isoformat()}, 200

# Manejo de preflight requests
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "*")
        response.headers.add('Access-Control-Allow-Methods', "*")
        return response

# RUTAS DE AUTENTICACIÓN
@app.route('/auth/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def auth_proxy(path):
    return forward_request(AUTH_SERVICE_URL, 'auth', path)

# RUTAS DE USUARIO
@app.route('/user/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def user_proxy(path):
    return forward_request(USER_SERVICE_URL, 'user', path)

# RUTAS DE TAREAS - Específicas primero
@app.route('/tasks/stats', methods=['GET', 'OPTIONS'])
def tasks_stats_proxy():
    return forward_request(TASK_SERVICE_URL, 'tasks', 'tasks/stats')

@app.route('/tasks/<int:task_id>', methods=['GET', 'PUT', 'DELETE', 'OPTIONS'])
def tasks_by_id_proxy(task_id):
    path = f'tasks/{task_id}'
    return forward_request(TASK_SERVICE_URL, 'tasks', path)

@app.route('/tasks', methods=['GET', 'POST', 'OPTIONS'])
def tasks_proxy():
    return forward_request(TASK_SERVICE_URL, 'tasks', 'tasks')

# RUTA GENÉRICA DE TAREAS (debe ir al final)
@app.route('/task/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def task_proxy(path):
    return forward_request(TASK_SERVICE_URL, 'task', path)

def forward_request(service_url, prefix, path, max_retries=3, delay=2):
    """Función mejorada para reenviar peticiones"""
    url = f'{service_url}/{path}'
    
    # Preparar headers - filtrar headers problemáticos
    headers_to_forward = {}
    for key, value in request.headers:
        # Excluir headers que pueden causar problemas
        if key.lower() not in ['host', 'content-length', 'connection']:
            headers_to_forward[key] = value
    
    # Asegurar que el Content-Type esté presente para requests con body
    if request.method in ['POST', 'PUT'] and request.get_json(silent=True):
        headers_to_forward['Content-Type'] = 'application/json'
    
    for attempt in range(max_retries):
        try:
            logging.info(f"➡️  Forwarding {request.method} {url} (intento {attempt + 1})")
            
            # Preparar datos del request
            request_data = None
            if request.method in ['POST', 'PUT']:
                request_data = request.get_json(silent=True)
            
            # Preparar parámetros de query
            query_params = dict(request.args) if request.args else None
            
            # Hacer la petición
            resp = requests.request(
                method=request.method,
                url=url,
                json=request_data,
                headers=headers_to_forward,
                params=query_params,
                timeout=30,
                allow_redirects=False
            )
            
            logging.info(f"✅ Response {resp.status_code} from {url}")
            
            # Manejar la respuesta
            if resp.status_code != 503:
                content_type = resp.headers.get('Content-Type', '').lower()
                
                # Crear respuesta con los headers apropiados
                response_headers = {}
                for key, value in resp.headers.items():
                    # Excluir headers que Flask maneja automáticamente
                    if key.lower() not in ['content-length', 'content-encoding', 'transfer-encoding', 'connection']:
                        response_headers[key] = value
                
                # MANEJO MEJORADO DE RESPUESTAS JSON
                if 'application/json' in content_type:
                    try:
                        # Verificar si es JSON válido
                        json.loads(resp.text)
                        response = Response(
                            resp.text,
                            status=resp.status_code,
                            content_type='application/json; charset=utf-8'
                        )
                    except json.JSONDecodeError:
                        # Si no es JSON válido, devolver como texto
                        logging.warning(f"Invalid JSON response from {url}: {resp.text[:200]}")
                        response = Response(
                            resp.text,
                            status=resp.status_code,
                            content_type='text/plain; charset=utf-8'
                        )
                elif content_type.startswith('text/'):
                    response = Response(
                        resp.text,
                        status=resp.status_code,
                        content_type=content_type
                    )
                else:
                    # Respuestas binarias
                    response = Response(
                        resp.content,
                        status=resp.status_code,
                        content_type=content_type or 'application/octet-stream'
                    )
                
                # Agregar headers de la respuesta original
                for key, value in response_headers.items():
                    response.headers[key] = value
                
                return response
            else:
                logging.warning(f"⚠️  Service 503 unavailable: {url}")
                if attempt < max_retries - 1:
                    time.sleep(delay)
                    
        except requests.exceptions.Timeout:
            logging.error(f"⏱️  Timeout en {url}")
            if attempt == max_retries - 1:
                return make_response({
                    'error': 'Service timeout',
                    'service': prefix,
                    'timestamp': datetime.utcnow().isoformat()
                }, 504)
        except requests.exceptions.ConnectionError:
            logging.error(f"🔌 Connection error to {url}")
            if attempt == max_retries - 1:
                return make_response({
                    'error': 'Service unavailable - connection failed',
                    'service': prefix,
                    'timestamp': datetime.utcnow().isoformat()
                }, 503)
        except Exception as e:
            logging.error(f"❌ Error forwarding request to {url}: {e}")
            if attempt == max_retries - 1:
                # Guardar log del error
                if hasattr(request, 'log_data'):
                    log_data = request.log_data.copy()
                    log_data.update({
                        "status_code": 503,
                        "response_time_seconds": round(time.time() - request.start_time, 3),
                        "error": str(e),
                        "target_url": url
                    })
                    save_log(log_data)
                
                return make_response({
                    'error': 'Internal server error',
                    'message': 'Service temporarily unavailable',
                    'service': prefix,
                    'timestamp': datetime.utcnow().isoformat()
                }, 503)
        
        if attempt < max_retries - 1:
            time.sleep(delay)
    
    return make_response({
        'error': 'Service unavailable after retries',
        'service': prefix,
        'attempts': max_retries,
        'timestamp': datetime.utcnow().isoformat()
    }, 503)

# Manejo de errores global
@app.errorhandler(404)
def not_found(error):
    return make_response({
        'error': 'Endpoint not found',
        'path': request.path,
        'method': request.method,
        'timestamp': datetime.utcnow().isoformat()
    }, 404)

@app.errorhandler(500)
def internal_error(error):
    return make_response({
        'error': 'Internal server error',
        'timestamp': datetime.utcnow().isoformat()
    }, 500)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Starting API Gateway on port {port}")
    print(f"📡 Auth Service: {AUTH_SERVICE_URL}")
    print(f"👤 User Service: {USER_SERVICE_URL}")
    print(f"📋 Task Service: {TASK_SERVICE_URL}")
    app.run(host='0.0.0.0', port=port, debug=False)
