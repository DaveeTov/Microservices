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
    log_line = json.dumps(data, ensure_ascii=False)
    with open("gateway_logs.jsonl", "a", encoding="utf-8") as log_file:
        log_file.write(log_line + "\n")

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
    duration = time.time() - getattr(request, 'start_time', time.time())
    log_data = getattr(request, 'log_data', {})
    log_data.update({
        "status_code": response.status_code,
        "response_time_seconds": round(duration, 3)
    })
    save_log(log_data)
    return response

# 🔗 URLs de los servicios (puedes cambiarlas por variables de entorno en Render)
AUTH_SERVICE_URL = os.environ.get("AUTH_SERVICE_URL", "https://auth-service-75ux.onrender.com")
USER_SERVICE_URL = os.environ.get("USER_SERVICE_URL", "https://user-service-6hc6.onrender.com")
TASK_SERVICE_URL = os.environ.get("TASK_SERVICE_URL", "https://task-service-v5ke.onrender.com")

@app.route('/')
def home():
    return {'status': 'API Gateway activo'}, 200

@app.route('/health', methods=['GET'])
def health():
    return {'status': 'OK', 'message': 'Proxy server running'}, 200

@app.route('/auth/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def auth_proxy(path):
    return forward_request(AUTH_SERVICE_URL, 'auth', path)

@app.route('/user/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def user_proxy(path):
    return forward_request(USER_SERVICE_URL, 'user', path)

@app.route('/task/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def task_proxy(path):
    return forward_request(TASK_SERVICE_URL, 'task', path)

@app.route('/tasks', methods=['GET', 'POST'])
@app.route('/tasks/<int:task_id>', methods=['GET', 'PUT', 'DELETE'])
def tasks_direct_proxy(task_id=None):
    path = f'tasks/{task_id}' if task_id is not None else 'tasks'
    return forward_request(TASK_SERVICE_URL, 'tasks', path)

def forward_request(service_url, prefix, path, max_retries=3, delay=3):
    url = f'{service_url}/{path}'
    for attempt in range(max_retries):
        try:
            logging.info(f"➡️ Intentando {url} (intento {attempt + 1})")
            resp = requests.request(
                method=request.method,
                url=url,
                json=request.get_json(silent=True),
                headers={k: v for k, v in request.headers if k.lower() != 'host'},
                timeout=30
            )
            content_type = resp.headers.get('Content-Type', '').lower()

            # ✅ Maneja JSON puro como texto, no binario
            if resp.status_code != 503:
                if 'application/json' in content_type:
                    # Usa resp.text para JSON, NO resp.content
                    return Response(resp.text, status=resp.status_code, content_type='application/json')
                else:
                    # Otros tipos de contenido
                    return Response(resp.content, status=resp.status_code, content_type=content_type or 'application/octet-stream')
            else:
                logging.warning(f"⚠️ Servicio 503: {url}")
                time.sleep(delay)
        except requests.exceptions.RequestException as e:
            logging.error(f"❌ Error: {e}")
            if attempt == max_retries - 1:
                log_data = getattr(request, 'log_data', {})
                log_data.update({
                    "status_code": 503,
                    "response_time_seconds": round(time.time() - request.start_time, 3),
                    "error": str(e)
                })
                save_log(log_data)
                return make_response({'error': 'Service unavailable'}, 503)
            time.sleep(delay)
    return make_response({'error': 'Service unavailable after retries'}, 503)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
