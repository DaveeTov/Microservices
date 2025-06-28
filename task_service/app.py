import datetime
import os
import sqlite3
from functools import wraps

import jwt
from flask import Flask, jsonify, request

# Crear la aplicación Flask
app = Flask(__name__)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Nombre del archivo de base de datos SQLite
DB_NAME = os.path.join(BASE_DIR, 'main_database.db')

# Clave secreta para verificar tokens JWT (debe ser la misma que en auth_service)
SECRET_KEY = 'jkhfcjkdhsclhjsafjchlkrhfkhjfkñqj'

# Decorador para validar token JWT en los headers Authorization
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Obtener el token del header 'Authorization'
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token requerido'}), 401
        
        try:
            # Quitar el prefijo 'Bearer ' si existe
            token = token.replace('Bearer ', '')
            # Decodificar el token usando la clave secreta y HS256
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            # Guardar la info del usuario en el objeto request para usarla en la ruta
            request.user = data
        except jwt.ExpiredSignatureError:
            # El token ha expirado
            return jsonify({'error': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            # El token es inválido o no válido
            return jsonify({'error': 'Token inválido'}), 401
        
        # Ejecutar la función protegida si el token es válido
        return f(*args, **kwargs)
    return decorated

# Función para crear la tabla 'tasks' en la base de datos si no existe
def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                create_at TEXT NOT NULL,
                deadline TEXT,
                status TEXT CHECK(status IN ('InProgress', 'Revision', 'Completed', 'Paused')) NOT NULL DEFAULT 'InProgress',
                isAlive INTEGER NOT NULL DEFAULT 1,
                created_by INTEGER NOT NULL,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        ''')
        conn.commit()

# Ruta para crear una nueva tarea (requiere token)
@app.route('/tasks', methods=['POST'])
@token_required
def create_task():
    data = request.get_json()
    required_fields = ['name', 'description', 'deadline']

    # Verificar que todos los campos obligatorios estén presentes
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Faltan campos obligatorios'}), 400

    created_by = request.user['id']  # Obtener id del usuario del token
    create_at = datetime.datetime.utcnow().isoformat()  # Fecha actual en formato ISO
    deadline = data['deadline']
    status = 'InProgress'  # Estado inicial
    isAlive = 1  # Estado activo (para borrado lógico)

    # Insertar la nueva tarea en la base de datos
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO tasks (name, description, create_at, deadline, status, isAlive, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (data['name'], data['description'], create_at, deadline, status, isAlive, created_by))
        conn.commit()
        task_id = cursor.lastrowid  # ID de la tarea creada

    return jsonify({'message': 'Tarea creada', 'task_id': task_id}), 201

# Ruta para obtener todas las tareas del usuario autenticado
@app.route('/tasks', methods=['GET'])
@token_required
def get_tasks():
    created_by = request.user['id']  # Id usuario del token
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        # Seleccionar tareas activas del usuario
        cursor.execute('SELECT id, name, description, create_at, deadline, status, isAlive FROM tasks WHERE created_by = ? AND isAlive = 1', (created_by,))
        tasks = cursor.fetchall()
    # Construir la lista de tareas en formato JSON
    tasks_list = []
    for t in tasks:
        tasks_list.append({
            'id': t[0],
            'name': t[1],
            'description': t[2],
            'create_at': t[3],
            'deadline': t[4],
            'status': t[5],
            'isAlive': bool(t[6])
        })
    return jsonify({'tasks': tasks_list})

# Ruta para obtener una tarea específica por id
@app.route('/tasks/<int:task_id>', methods=['GET'])
@token_required
def get_task(task_id):
    created_by = request.user['id']
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        # Buscar tarea por id, usuario y que esté activa
        cursor.execute('SELECT id, name, description, create_at, deadline, status, isAlive FROM tasks WHERE id = ? AND created_by = ? AND isAlive = 1', (task_id, created_by))
        t = cursor.fetchone()
    if not t:
        return jsonify({'error': 'Tarea no encontrada'}), 404
    task = {
        'id': t[0],
        'name': t[1],
        'description': t[2],
        'create_at': t[3],
        'deadline': t[4],
        'status': t[5],
        'isAlive': bool(t[6])
    }
    return jsonify({'task': task})

# Ruta para actualizar una tarea existente
@app.route('/tasks/<int:task_id>', methods=['PUT'])
@token_required
def update_task(task_id):
    data = request.get_json()
    created_by = request.user['id']

    # Campos que se permiten actualizar
    fields = ['name', 'description', 'deadline', 'status', 'isAlive']
    # Filtrar solo los campos presentes en la petición
    update_fields = {field: data[field] for field in fields if field in data}

    # Validar que el estado sea válido si se está actualizando
    if 'status' in update_fields and update_fields['status'] not in ['InProgress', 'Revision', 'Completed', 'Paused']:
        return jsonify({'error': 'Estado inválido'}), 400

    # Crear el fragmento dinámico para la consulta UPDATE
    set_clause = ', '.join(f"{field} = ?" for field in update_fields.keys())
    values = list(update_fields.values())
    values.append(task_id)
    values.append(created_by)

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute(f'''
            UPDATE tasks SET {set_clause}
            WHERE id = ? AND created_by = ?
        ''', values)
        conn.commit()

        # Verificar si se actualizó alguna fila
        if cursor.rowcount == 0:
            return jsonify({'error': 'Tarea no encontrada o no autorizada'}), 404

    return jsonify({'message': 'Tarea actualizada'})

# Ruta para eliminar (borrado lógico) una tarea
@app.route('/tasks/<int:task_id>', methods=['DELETE'])
@token_required
def delete_task(task_id):
    created_by = request.user['id']
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        # Actualizar el campo isAlive a 0 para marcar la tarea como eliminada
        cursor.execute('''
            UPDATE tasks SET isAlive = 0
            WHERE id = ? AND created_by = ?
        ''', (task_id, created_by))
        conn.commit()
        # Verificar que la tarea haya existido y sido actualizada
        if cursor.rowcount == 0:
            return jsonify({'error': 'Tarea no encontrada o no autorizada'}), 404
    return jsonify({'message': 'Tarea eliminada (borrado lógico)'})

# Inicializar la base de datos y ejecutar la aplicación
if __name__ == '__main__':
    init_db()  # Crear tabla tasks si no existe
    app.run(port=5003, debug=True)  # Ejecutar en puerto 5003 con debug activado
