import json
import time
import os
from datetime import datetime

import jwt
import requests
from flask import Flask, make_response, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app,
     origins=["*"],  # Reemplaza con tu frontend real si aplica
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

SECRET_KEY = 'jkhfcjkdhsclhjsafjchlkrhfkhjfkñqj'
JWT_ALGORITHM = 'HS256'

def save_log(data):
    log_line = json.dumps(data, ensure_ascii=False)
    with open("gateway_logs.jsonl", "a", encoding="utf-8") as log_file:
        log_file.write(log_line + "\n")

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

AUTH_SERVICE_URL = os.environ.get("AUTH_SERVICE_URL", "http://localhost:5001")
USER_SERVICE_URL = os.environ.get("USER_SERVICE_URL", "http://localhost:5002")
TASK_SERVICE_URL = os.environ.get("TASK_SERVICE_URL", "http://localhost:5003")

@app.route('/health', methods=['GET'])
def health():
    return {'status': 'OK', 'message': 'Proxy server running'}

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
            resp = requests.request(
                method=request.method,
                url=url,
                json=request.get_json(silent=True),
                headers={k: v for k, v in request.headers if k.lower() != 'host'},
                timeout=10
            )
            if resp.status_code != 503:
                response = make_response(resp.content, resp.status_code)
                response.headers['Content-Type'] = resp.headers.get('Content-Type', 'application/json')
                return response
            else:
                time.sleep(delay)  # Espera antes de reintentar
        except requests.exceptions.RequestException as e:
            if attempt == max_retries - 1:
                log_data = getattr(request, 'log_data', {})
                log_data.update({
                    "status_code": 503,
                    "response_time_seconds": round(time.time() - request.start_time, 3),
                    "error": str(e)
                })
                save_log(log_data)
                return make_response({'error': 'Service unavailable'}, 503)
            else:
                time.sleep(delay)  # Espera antes de reintentar

    # Si después de reintentos sigue fallando
    return make_response({'error': 'Service unavailable after retries'}, 503)


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

