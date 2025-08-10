import json
import time
import os
import logging
from datetime import datetime

import jwt
import requests
from flask import Flask, make_response, request, Response

# =========================
#         Logging
# =========================
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# =========================
#        C O R S
# =========================
ALLOWED_ORIGINS = {
    "http://localhost:4200",
    "https://gui-angular.vercel.app",
}

SECRET_KEY = os.environ.get("SECRET_KEY", "jkhfcjkdhsclhjsafjchlkrhfkñqj")
JWT_ALGORITHM = 'HS256'

# =========================
#       Persistencia logs
# =========================
def save_log(data):
    try:
        log_line = json.dumps(data, ensure_ascii=False)
        with open("gateway_logs.jsonl", "a", encoding="utf-8") as log_file:
            log_file.write(log_line + "\n")
    except Exception as e:
        logging.error(f"Error saving log: {e}")

# =========================
#   Helpers CORS
# =========================
def _build_allow_headers():
    """Une los headers pedidos por el navegador + los obligatorios."""
    requested = (request.headers.get("Access-Control-Request-Headers", "") or "").lower()
    requested_set = {h.strip() for h in requested.split(",") if h.strip()}
    required = {"authorization", "content-type", "x-requested-with"}
    allowed = sorted(requested_set.union(required))
    return ", ".join(allowed) if allowed else "authorization, content-type, x-requested-with"

def _preflight_response():
    origin = request.headers.get("Origin", "")
    resp = make_response("", 204)
    if origin in ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = _build_allow_headers()
        resp.headers["Access-Control-Max-Age"] = "86400"
        resp.headers["Vary"] = "Origin, Access-Control-Request-Headers, Access-Control-Request-Method"
    return resp

# =========================
#   Preflight global
# =========================
@app.before_request
def intercept_all_preflights():
    # No logueamos ni dejamos que Flask genere el OPTIONS automático
    if request.method == "OPTIONS":
        return _preflight_response()

# =========================
#   Middleware de logging
# =========================
@app.before_request
def log_request():
    if request.method == "OPTIONS":
        return  # ya atendido arriba

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
    # Refuerzo CORS para respuestas no-OPTIONS
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        existing_vary = response.headers.get("Vary", "")
        response.headers["Vary"] = ("Origin" if not existing_vary else f"{existing_vary}, Origin")

    if request.method == "OPTIONS":
        return response  # nada de logs

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

# =========================
#   URLs de los servicios
# =========================
AUTH_SERVICE_URL = os.environ.get("AUTH_SERVICE_URL", "https://auth-service-75ux.onrender.com")
USER_SERVICE_URL = os.environ.get("USER_SERVICE_URL", "https://user-service-6hc6.onrender.com")
TASK_SERVICE_URL = os.environ.get("TASK_SERVICE_URL", "https://task-service-v5ke.onrender.com")

# =========================
#        Rutas base
# =========================
@app.route('/')
def home():
    return {'status': 'API Gateway activo', 'timestamp': datetime.utcnow().isoformat()}, 200

@app.route('/health', methods=['GET'])
def health():
    return {'status': 'OK', 'message': 'Proxy server running', 'timestamp': datetime.utcnow().isoformat()}, 200

# =========================
#      Rutas proxy
# =========================
@app.route('/auth/<path:path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
def auth_proxy(path):
    return forward_request(AUTH_SERVICE_URL, 'auth', path)

@app.route('/user/<path:path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
def user_proxy(path):
    return forward_request(USER_SERVICE_URL, 'user', path)

# ✅ RUTAS ESPECÍFICAS DE TASKS (orden importa)
@app.route('/tasks/stats', methods=['GET'])
def tasks_stats_proxy():
    return forward_request(TASK_SERVICE_URL, 'tasks', 'tasks/stats')

@app.route('/tasks/<int:task_id>/status', methods=['PUT'])
def tasks_status_proxy(task_id):
    path = f'tasks/{task_id}/status'
    return forward_request(TASK_SERVICE_URL, 'tasks', path)

@app.route('/tasks/<int:task_id>', methods=['GET', 'PUT', 'DELETE'])
def tasks_by_id_proxy(task_id):
    path = f'tasks/{task_id}'
    return forward_request(TASK_SERVICE_URL, 'tasks', path)

@app.route('/tasks', methods=['GET', 'POST'])
def tasks_proxy():
    return forward_request(TASK_SERVICE_URL, 'tasks', 'tasks')

# Genérica (al final)
@app.route('/task/<path:path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
def task_proxy(path):
    return forward_request(TASK_SERVICE_URL, 'task', path)

def forward_request(service_url, prefix, path, max_retries=3, delay=2):
    """Reenvía la petición al microservicio destino con JSON normalizado."""
    # Nota: OPTIONS ya fue atendido en @before_request

    url = f'{service_url}/{path}'

    # Filtrar headers problemáticos
    headers_to_forward = {}
    for key, value in request.headers:
        if key.lower() not in ['host', 'content-length', 'connection', 'origin']:
            headers_to_forward[key] = value

    # Evitar compresión hacia upstream (para no devolver gzip crudo)
    headers_to_forward['Accept-Encoding'] = 'identity'

    # Asegurar content-type para POST/PUT/PATCH con JSON
    if request.method in ['POST', 'PUT', 'PATCH'] and request.get_json(silent=True) is not None:
        headers_to_forward['Content-Type'] = 'application/json'

    for attempt in range(max_retries):
        try:
            logging.info(f"➡️  Forwarding {request.method} {url} (intento {attempt + 1})")

            request_data = None
            if request.method in ['POST', 'PUT', 'PATCH']:
                request_data = request.get_json(silent=True)

            query_params = dict(request.args) if request.args else None

            resp = requests.request(
                method=request.method,
                url=url,
                json=request_data,
                headers=headers_to_forward,
                params=query_params,
                timeout=60,
                allow_redirects=False,
                verify=True
            )

            logging.info(f"✅ Response {resp.status_code} from {url}")

            if resp.status_code != 503:
                upstream_ct = (resp.headers.get('Content-Type') or '').lower()
                is_json = 'application/json' in upstream_ct

                # Copia de headers saneados
                response_headers = {}
                for key, value in resp.headers.items():
                    k = key.lower()
                    if k in ['content-length', 'content-encoding', 'transfer-encoding', 'connection']:
                        continue
                    response_headers[key] = value

                # Cuerpo
                if is_json:
                    body_text = resp.text
                    try:
                        json.loads(body_text)
                        response_obj = Response(
                            body_text,
                            status=resp.status_code,
                            content_type='application/json; charset=utf-8'
                        )
                    except json.JSONDecodeError:
                        logging.warning("Upstream dijo JSON pero no lo es. Se devuelve como texto.")
                        response_obj = Response(
                            body_text,
                            status=resp.status_code,
                            content_type='text/plain; charset=utf-8'
                        )
                elif upstream_ct.startswith('text/'):
                    response_obj = Response(
                        resp.text,
                        status=resp.status_code,
                        content_type=upstream_ct or 'text/plain; charset=utf-8'
                    )
                else:
                    response_obj = Response(
                        resp.content,
                        status=resp.status_code,
                        content_type=upstream_ct or 'application/octet-stream'
                    )

                # Headers del upstream
                for key, value in response_headers.items():
                    response_obj.headers[key] = value

                # Refuerzo CORS por si acaso
                origin = request.headers.get("Origin", "")
                if origin in ALLOWED_ORIGINS:
                    response_obj.headers["Access-Control-Allow-Origin"] = origin
                    response_obj.headers["Vary"] = "Origin"
                    response_obj.headers["Access-Control-Allow-Credentials"] = "true"

                return response_obj

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
                    'url': url,
                    'timestamp': datetime.utcnow().isoformat()
                }, 504)
        except requests.exceptions.ConnectionError as e:
            logging.error(f"🔌 Connection error to {url}: {str(e)}")
            if attempt == max_retries - 1:
                return make_response({
                    'error': 'Service unavailable - connection failed',
                    'service': prefix,
                    'url': url,
                    'details': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                }, 503)
        except requests.exceptions.RequestException as e:
            logging.error(f"📡 Request error to {url}: {str(e)}")
            if attempt == max_retries - 1:
                return make_response({
                    'error': 'Request failed',
                    'service': prefix,
                    'url': url,
                    'details': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                }, 502)
        except Exception as e:
            logging.error(f"❌ Error forwarding request to {url}: {e}")
            if attempt == max_retries - 1:
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
                    'url': url,
                    'timestamp': datetime.utcnow().isoformat()
                }, 503)

        if attempt < max_retries - 1:
            logging.info(f"🔄 Retrying {url} in {delay} seconds...")
            time.sleep(delay)

    return make_response({
        'error': 'Service unavailable after retries',
        'service': prefix,
        'attempts': max_retries,
        'url': url,
        'timestamp': datetime.utcnow().isoformat()
    }, 503)

# =========================
#   Service health checks
# =========================
@app.route('/health/services', methods=['GET'])
def health_services():
    services = {
        'auth': AUTH_SERVICE_URL,
        'user': USER_SERVICE_URL,
        'task': TASK_SERVICE_URL
    }

    health_status = {}
    overall_healthy = True

    for service_name, service_url in services.items():
        try:
            response = requests.get(f"{service_url}/health", timeout=10)
            health_status[service_name] = {
                'status': 'healthy' if response.status_code == 200 else 'unhealthy',
                'status_code': response.status_code,
                'url': service_url
            }
            if response.status_code != 200:
                overall_healthy = False
        except Exception as e:
            health_status[service_name] = {
                'status': 'unhealthy',
                'error': str(e),
                'url': service_url
            }
            overall_healthy = False

    return make_response({
        'gateway_status': 'healthy',
        'services': health_status,
        'overall_healthy': overall_healthy,
        'timestamp': datetime.utcnow().isoformat()
    }, 200 if overall_healthy else 503)

# =========================
#   Manejo de errores
# =========================
@app.errorhandler(404)
def not_found(error):
    response = make_response({
        'error': 'Endpoint not found',
        'path': request.path,
        'method': request.method,
        'available_endpoints': [
            '/auth/<path>',
            '/user/<path>',
            '/tasks',
            '/tasks/<id>',
            '/tasks/<id>/status',
            '/tasks/stats',
            '/health',
            '/health/services'
        ],
        'timestamp': datetime.utcnow().isoformat()
    }, 404)

    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        existing_vary = response.headers.get("Vary", "")
        response.headers["Vary"] = ("Origin" if not existing_vary else f"{existing_vary}, Origin")

    return response

@app.errorhandler(500)
def internal_error(error):
    response = make_response({
        'error': 'Internal server error',
        'timestamp': datetime.utcnow().isoformat()
    }, 500)

    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        existing_vary = response.headers.get("Vary", "")
        response.headers["Vary"] = ("Origin" if not existing_vary else f"{existing_vary}, Origin")

    return response

# =========================
#      Arranque
# =========================
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Starting API Gateway on port {port}")
    print(f"📡 Auth Service: {AUTH_SERVICE_URL}")
    print(f"👤 User Service: {USER_SERVICE_URL}")
    print(f"📋 Task Service: {TASK_SERVICE_URL}")

    # Test service connectivity on startup
    print("\n🔍 Testing service connectivity...")
    for service_name, service_url in [
        ('Auth', AUTH_SERVICE_URL),
        ('User', USER_SERVICE_URL),
        ('Task', TASK_SERVICE_URL)
    ]:
        try:
            response = requests.get(f"{service_url}/health", timeout=10)
            status = "✅ OK" if response.status_code == 200 else f"⚠️  Status {response.status_code}"
            print(f"  {service_name} Service: {status}")
        except Exception as e:
            print(f"  {service_name} Service: ❌ Error - {str(e)}")

    print(f"\n🌐 Gateway available at: http://localhost:{port}")
    app.run(host='0.0.0.0', port=port, debug=False)
