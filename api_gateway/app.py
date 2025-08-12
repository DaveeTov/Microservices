import json
import time
import os
import logging
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional

import jwt
import requests
from flask import Flask, make_response, request, Response, jsonify

# Firebase Admin SDK
from firebase_admin import credentials, initialize_app, db as fb_db, firestore as fb_fs
import json as pyjson
import base64

# ---- Rate Limiting ----
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)

ALLOWED_ORIGINS = {
    "http://localhost:4200",
    "https://gui-angular.vercel.app",
    "https://taskapp-zeta-bice.vercel.app/",
    "https://taskapp-zeta-bice.vercel.app"

}

SECRET_KEY = os.environ.get("SECRET_KEY", "jkhfcjkdhsclhjsafjchlkrhfkñqj")
JWT_ALGORITHM = 'HS256'

# ====== Firebase init ======
FIREBASE_DB_URL = os.environ.get(
    "FIREBASE_DB_URL",
    "https://logsmicroservices-default-rtdb.firebaseio.com/"
)
FIREBASE_ENABLE_FIRESTORE = os.environ.get("FIREBASE_ENABLE_FIRESTORE", "false").lower() == "true"

firebase_app = None
firestore_client = None

def _init_firebase():
    """Inicializa Firebase Admin SDK usando FILE o JSON/base64 en env vars."""
    global firebase_app, firestore_client
    if firebase_app:
        return

    cred = None
    cred_path = os.environ.get("FIREBASE_CREDENTIALS_FILE")
    cred_json = os.environ.get("FIREBASE_CREDENTIALS_JSON")

    try:
        if cred_path and os.path.exists(cred_path):
            cred = credentials.Certificate(cred_path)
        elif cred_json:
            try:
                data = pyjson.loads(cred_json)  # JSON plano
            except Exception:
                data = pyjson.loads(base64.b64decode(cred_json).decode("utf-8"))  # base64
            cred = credentials.Certificate(data)

        if cred:
            firebase_app = initialize_app(cred, {"databaseURL": FIREBASE_DB_URL})
            if FIREBASE_ENABLE_FIRESTORE:
                firestore_client = fb_fs.client()
            app.logger.info("✅ Firebase inicializado")
        else:
            app.logger.warning("⚠️  No hay credenciales Firebase; se omite envío a Firebase.")
    except Exception as e:
        app.logger.error(f"❌ Error inicializando Firebase: {e}")

_init_firebase()

def push_log_to_realtime_db(data: dict):
    """Envía un log a Realtime Database en ruta gateway_logs/YYYY/MM/DD/autoKey"""
    if not firebase_app:
        return
    try:
        date_path = datetime.utcnow().strftime("%Y/%m/%d")
        ref = fb_db.reference(f"gateway_logs/{date_path}", app=firebase_app)
        ref.push(data)
    except Exception as e:
        app.logger.error(f"Error enviando log a Realtime DB: {e}")

def push_log_to_firestore(data: dict):
    """(Opcional) Envía un log a Firestore en gateway_logs/{YYYY-MM-DD}/entries/*"""
    if not firestore_client:
        return
    try:
        date_key = datetime.utcnow().strftime("%Y-%m-%d")
        firestore_client.collection("gateway_logs").document(date_key)\
            .collection("entries").add(data)
    except Exception as e:
        app.logger.error(f"Error enviando log a Firestore: {e}")

# Pool para envío no bloqueante
_log_executor = ThreadPoolExecutor(max_workers=4)

def save_log(data):
    """Guarda en archivo .jsonl y manda a Firebase (async)"""
    try:
        log_line = json.dumps(data, ensure_ascii=False)
        with open("gateway_logs.jsonl", "a", encoding="utf-8") as log_file:
            log_file.write(log_line + "\n")
    except Exception as e:
        logging.error(f"Error saving log (file): {e}")

    # Enviar a Firebase en background (no bloquea la respuesta al cliente)
    def _send():
        try:
            push_log_to_realtime_db(data)
            if FIREBASE_ENABLE_FIRESTORE:
                push_log_to_firestore(data)
        except Exception as _e:
            logging.error(f"Error saving log (firebase): {_e}")

    _log_executor.submit(_send)

def _build_allow_headers():
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

# ====== Identificadores para Rate Limiting ======
def _client_ip() -> str:
    # Respeta proxies/reverse proxies
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

def _user_or_ip() -> str:
    # Usa el usuario (JWT/email) si viene, si no la IP
    token = request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        try:
            decoded = jwt.decode(token[7:], SECRET_KEY, algorithms=[JWT_ALGORITHM])
            uid = decoded.get("sub") or decoded.get("username") or decoded.get("email")
            if uid:
                return f"user:{uid}"
        except Exception:
            pass
    return f"ip:{_client_ip()}"

# ====== Rate Limiter ======
_storage_uri = (
    os.environ.get("RATELIMIT_STORAGE_URL")
    or os.environ.get("REDIS_URL")
    or "memory://"
)
_strategy = "moving-window" if _storage_uri.startswith(("redis://", "rediss://")) else "fixed-window"

limiter = Limiter(
    key_func=_user_or_ip,                 # clave por usuario o IP
    storage_uri=_storage_uri,             # redis://... ó memory://
    strategy=_strategy,
    default_limits=[                      # límite por defecto para TODO el gateway
        "300 per minute"                  # ajusta a tu tráfico
    ],
    headers_enabled=True                  # añade Retry-After/X-RateLimit-* autom.
)

@app.errorhandler(429)
def ratelimit_handler(e):
    # Respuesta uniforme cuando se excede el límite
    retry_after = getattr(e, "retry_after", None)
    data = {
        "error": "rate_limited",
        "message": "Demasiadas solicitudes. Inténtalo más tarde.",
        "retry_after_seconds": retry_after if isinstance(retry_after, int) else None,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    # Log al archivo/Firebase
    try:
        duration = time.time() - getattr(request, 'start_time', time.time())
        save_log({
            "timestamp": data["timestamp"],
            "method": request.method,
            "path": request.path,
            "servicio": (request.path.strip("/").split("/") or ["desconocido"])[0],
            "usuario": None,
            "ip": _client_ip(),
            "status_code": 429,
            "response_time_seconds": round(duration, 3),
            "rate_limited": True
        })
    except Exception:
        pass
    resp = jsonify(data)
    resp.status_code = 429
    # Flask-Limiter ya setea cabeceras, no las pisamos.
    return resp

@app.before_request
def intercept_all_preflights():
    if request.method == "OPTIONS":
        return _preflight_response()

@app.before_request
def log_request():
    if request.method == "OPTIONS":
        return
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
        "ip": _client_ip(),
    }

@app.after_request
def log_response(response):
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        existing_vary = response.headers.get("Vary", "")
        response.headers["Vary"] = ("Origin" if not existing_vary else f"{existing_vary}, Origin")

    if request.method == "OPTIONS":
        return response

    try:
        duration = time.time() - getattr(request, 'start_time', time.time())
        log_data = getattr(request, 'log_data', {}).copy()
        log_data.update({
            "status_code": response.status_code,
            "response_time_seconds": round(duration, 3)
        })
        save_log(log_data)
    except Exception as e:
        logging.error(f"Error in after_request: {e}")
    return response

# ====== Helpers Logs Firebase ======
def _date_iter(start: datetime, end: datetime):
    d = start
    while d <= end:
        yield d
        d += timedelta(days=1)

def _fetch_logs_from_rtdb_for_date(d: datetime) -> List[dict]:
    """Lee todos los logs del día d (UTC) desde gateway_logs/YYYY/MM/DD/*"""
    if not firebase_app:
        return []
    try:
        path = d.strftime("gateway_logs/%Y/%m/%d")
        ref = fb_db.reference(path, app=firebase_app)
        raw = ref.get() or {}
        return [v for _, v in raw.items() if isinstance(v, dict)]
    except Exception as e:
        app.logger.error(f"Error leyendo logs RTDB {d.date()}: {e}")
        return []

def _fetch_logs_range(start_date: datetime, end_date: datetime, limit: Optional[int]=None) -> List[dict]:
    """Une logs de varios días (RTDB no filtra por rango de fecha)."""
    all_logs: List[dict] = []
    for d in _date_iter(start_date, end_date):
        day_logs = _fetch_logs_from_rtdb_for_date(d)
        all_logs.extend(day_logs)
        if limit and len(all_logs) >= limit:
            break
    try:
        all_logs.sort(key=lambda x: x.get("timestamp",""))
    except Exception:
        pass
    return all_logs if not limit else all_logs[:limit]

def _summarize_logs(logs: List[dict]) -> dict:
    total = len(logs)
    status_counts: Dict[str, int] = {}
    family_counts: Dict[str, int] = {"2xx":0, "3xx":0, "4xx":0, "5xx":0, "other":0}
    by_service: Dict[str, Dict[str, Any]] = {}
    sum_rt = 0.0
    min_rt = None
    max_rt = None

    for log in logs:
        status = str(log.get("status_code", ""))
        try:
            rt = float(log.get("response_time_seconds", 0) or 0)
        except Exception:
            rt = 0.0
        svc = log.get("servicio") or "desconocido"

        status_counts[status] = status_counts.get(status, 0) + 1

        family = "other"
        if status.isdigit():
            s = int(status)
            if 200 <= s <= 299: family = "2xx"
            elif 300 <= s <= 399: family = "3xx"
            elif 400 <= s <= 499: family = "4xx"
            elif 500 <= s <= 599: family = "5xx"
        family_counts[family] = family_counts.get(family, 0) + 1

        sum_rt += rt
        min_rt = rt if min_rt is None else min(min_rt, rt)
        max_rt = rt if max_rt is None else max(max_rt, rt)

        bucket = by_service.setdefault(svc, {"count":0, "sum_rt":0.0, "min_rt":None, "max_rt":None})
        bucket["count"] += 1
        bucket["sum_rt"] += rt
        bucket["min_rt"] = rt if bucket["min_rt"] is None else min(bucket["min_rt"], rt)
        bucket["max_rt"] = rt if bucket["max_rt"] is None else max(bucket["max_rt"], rt)

    avg_rt = (sum_rt / total) if total else 0.0

    for svc, b in by_service.items():
        c = b["count"] or 1
        b["avg_rt"] = round(b["sum_rt"]/c, 3)
        b["min_rt"] = round(b["min_rt"] or 0, 3)
        b["max_rt"] = round(b["max_rt"] or 0, 3)
        del b["sum_rt"]

    most_used = max(by_service.items(), key=lambda kv: kv[1]["count"]) if by_service else None
    least_used = min(by_service.items(), key=lambda kv: kv[1]["count"]) if by_service else None
    fastest = min(by_service.items(), key=lambda kv: kv[1]["avg_rt"]) if by_service else None
    slowest = max(by_service.items(), key=lambda kv: kv[1]["avg_rt"]) if by_service else None

    return {
        "total_logs": total,
        "status_counts": status_counts,
        "status_families": family_counts,
        "response_time": {
            "avg": round(avg_rt, 3),
            "min": round(min_rt or 0, 3),
            "max": round(max_rt or 0, 3),
        },
        "by_service": by_service,
        "most_used_api": {"servicio": most_used[0], **most_used[1]} if most_used else None,
        "least_used_api": {"servicio": least_used[0], **least_used[1]} if least_used else None,
        "fastest_api": {"servicio": fastest[0], **fastest[1]} if fastest else None,
        "slowest_api": {"servicio": slowest[0], **slowest[1]} if slowest else None,
    }

# ====== Endpoints Logs para DashLogs ======
@app.route("/logs/summary", methods=["GET"])
@limiter.limit("60 per minute", key_func=_user_or_ip)   # límite específico del endpoint
def logs_summary():
    """
    GET /logs/summary?date=YYYY-MM-DD
    o    /logs/summary?start=YYYY-MM-DD&end=YYYY-MM-DD
    """
    if not firebase_app:
        return jsonify({"error":"Firebase no inicializado"}), 503

    date_str = request.args.get("date")
    start_str = request.args.get("start")
    end_str = request.args.get("end")

    try:
        if date_str:
            d = datetime.strptime(date_str, "%Y-%m-%d")
            logs = _fetch_logs_from_rtdb_for_date(d)
        else:
            if not start_str and not end_str:
                d = datetime.utcnow()
                logs = _fetch_logs_from_rtdb_for_date(d)
            else:
                start = datetime.strptime(start_str, "%Y-%m-%d") if start_str else datetime.utcnow()
                end = datetime.strptime(end_str, "%Y-%m-%d") if end_str else start
                if end < start:
                    start, end = end, start
                logs = _fetch_logs_range(start, end)
    except ValueError:
        return jsonify({"error":"Formato de fecha inválido. Usa YYYY-MM-DD"}), 400

    return jsonify(_summarize_logs(logs)), 200

@app.route("/logs/recent", methods=["GET"])
@limiter.limit("60 per minute", key_func=_user_or_ip)
def logs_recent():
    """
    GET /logs/recent?date=YYYY-MM-DD&limit=200
    Retorna los últimos N logs del día (ordenados por timestamp).
    """
    if not firebase_app:
        return jsonify({"error":"Firebase no inicializado"}), 503

    limit = int(request.args.get("limit", 200))
    date_str = request.args.get("date")
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d") if date_str else datetime.utcnow()
    except ValueError:
        return jsonify({"error":"Formato de fecha inválido. Usa YYYY-MM-DD"}), 400

    logs = _fetch_logs_from_rtdb_for_date(d)
    try:
        logs.sort(key=lambda x: x.get("timestamp",""))
    except Exception:
        pass
    logs = logs[-limit:] if limit and len(logs) > limit else logs
    return jsonify({"logs": logs, "count": len(logs)}), 200

# ====== Servicios destino ======
AUTH_SERVICE_URL = os.environ.get("AUTH_SERVICE_URL", "https://auth-service-75ux.onrender.com")
USER_SERVICE_URL = os.environ.get("USER_SERVICE_URL", "https://user-service-6hc6.onrender.com")
TASK_SERVICE_URL = os.environ.get("TASK_SERVICE_URL", "https://task-service-v5ke.onrender.com")

# ====== Rutas base ======
@app.route('/')
@limiter.exempt
def home():
    return {'status': 'API Gateway activo', 'timestamp': datetime.utcnow().isoformat()}, 200

@app.route('/health', methods=['GET'])
@limiter.exempt
def health():
    return {'status': 'OK', 'message': 'Proxy server running', 'timestamp': datetime.utcnow().isoformat()}, 200

# ====== Límites dinámicos para proxies ======
def _proxy_limits():
    """
    Límites según ruta:
      - /auth/*  :  20/min por usuario/IP (ej: login, register)
      - /tasks*  : 120/min por usuario/IP
      - default  : 300/min (hereda del default si no retornamos nada)
    """
    p = (request.path or "").lower()
    if p.startswith("/auth/"):
        return "20 per minute"
    if p.startswith("/tasks"):
        return "120 per minute"
    # None => usa default_limits
    return None

# ====== Proxies ======
@app.route('/auth/<path:path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
@limiter.limit(_proxy_limits, key_func=_user_or_ip)
def auth_proxy(path):
    return forward_request(AUTH_SERVICE_URL, 'auth', path)

@app.route('/user/<path:path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
@limiter.limit("200 per minute", key_func=_user_or_ip)
def user_proxy(path):
    return forward_request(USER_SERVICE_URL, 'user', path)

@app.route('/tasks/stats', methods=['GET'])
@limiter.limit("120 per minute", key_func=_user_or_ip)
def tasks_stats_proxy():
    return forward_request(TASK_SERVICE_URL, 'tasks', 'tasks/stats')

@app.route('/tasks/<int:task_id>/status', methods=['PUT'])
@limiter.limit("120 per minute", key_func=_user_or_ip)
def tasks_status_proxy(task_id):
    path = f'tasks/{task_id}/status'
    return forward_request(TASK_SERVICE_URL, 'tasks', path)

@app.route('/tasks/<int:task_id>', methods=['GET', 'PUT', 'DELETE'])
@limiter.limit("120 per minute", key_func=_user_or_ip)
def tasks_by_id_proxy(task_id):
    path = f'tasks/{task_id}'
    return forward_request(TASK_SERVICE_URL, 'tasks', path)

@app.route('/tasks', methods=['GET', 'POST'])
@limiter.limit("120 per minute", key_func=_user_or_ip)
def tasks_proxy():
    return forward_request(TASK_SERVICE_URL, 'tasks', 'tasks')

@app.route('/task/<path:path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
@limiter.limit("120 per minute", key_func=_user_or_ip)
def task_proxy(path):
    return forward_request(TASK_SERVICE_URL, 'task', path)

def forward_request(service_url, prefix, path, max_retries=3, delay=2):
    url = f'{service_url}/{path}'
    headers_to_forward = {}
    for key, value in request.headers:
        if key.lower() not in ['host', 'content-length', 'connection', 'origin']:
            headers_to_forward[key] = value

    headers_to_forward['Accept-Encoding'] = 'identity'

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

                response_headers = {}
                for key, value in resp.headers.items():
                    k = key.lower()
                    if k in ['content-length', 'content-encoding', 'transfer-encoding', 'connection']:
                        continue
                    response_headers[key] = value

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

                for key, value in response_headers.items():
                    response_obj.headers[key] = value

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

@app.route('/health/services', methods=['GET'])
@limiter.exempt
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
            '/logs/summary',
            '/logs/recent',
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

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Starting API Gateway on port {port}")
    print(f"📡 Auth Service: {AUTH_SERVICE_URL}")
    print(f"👤 User Service: {USER_SERVICE_URL}")
    print(f"📋 Task Service: {TASK_SERVICE_URL}")

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



