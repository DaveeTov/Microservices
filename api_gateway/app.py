import requests
from flask import Flask, jsonify, request

# Crear una instancia de la aplicación Flask
app = Flask(__name__)

# URLs base de los microservicios que se van a consumir
AUTH_SERVICE_URL = 'http://localhost:5001'   # Servicio de autenticación
USER_SERVICE_URL = 'http://localhost:5002'   # Servicio de usuario
TASK_SERVICE_URL = 'http://localhost:5003'   # Servicio de tareas

# Función genérica para reenviar (proxy) la solicitud HTTP al microservicio correspondiente
def proxy_request(service_url, path):
    method = request.method  # Obtener el método HTTP (GET, POST, etc.) de la solicitud entrante
    url = f'{service_url}/{path}'  # Construir la URL completa hacia el microservicio

    # Hacer la petición HTTP hacia el microservicio usando la librería requests
    resp = requests.request(
        method=method,  # Método HTTP
        url=url,        # URL destino
        json=request.get_json(silent=True),  # Datos JSON recibidos, si hay
        # Copiar los headers de la solicitud original, excepto el 'host' que puede interferir
        headers={key: value for key, value in request.headers if key.lower() != 'host'}
    )

    # Intentar devolver la respuesta JSON del microservicio con el código de estado HTTP
    try:
        return jsonify(resp.json()), resp.status_code
    except ValueError:
        # Si la respuesta no es JSON, devolver el texto plano y el código de estado
        return resp.text, resp.status_code

# Ruta que proxy para las solicitudes que van al servicio de autenticación
@app.route('/auth/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy_auth(path):
    return proxy_request(AUTH_SERVICE_URL, path)

# Ruta que proxy para las solicitudes que van al servicio de usuario
@app.route('/user/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy_user(path):
    return proxy_request(USER_SERVICE_URL, path)

# Rutas para el servicio de tareas
# Cuando no se pasa un id específico (solo /tasks), se permiten GET y POST
@app.route('/tasks', methods=['GET', 'POST'])
# Cuando se pasa un path/id, se permiten GET, PUT y DELETE
@app.route('/tasks/<path:path>', methods=['GET', 'PUT', 'DELETE'])
def proxy_tasks(path=''):
    # Asegura que siempre redirige a /tasks o /tasks/<id>
    fixed_path = 'tasks' if path == '' else f'tasks/{path}'
    return proxy_request(TASK_SERVICE_URL, fixed_path)

# Ejecutar la app Flask en el puerto 5000 en modo debug (útil para desarrollo)
if __name__ == '__main__':
    app.run(port=5000, debug=True)
