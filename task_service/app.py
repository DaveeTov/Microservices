import datetime
import os
import sqlite3
from functools import wraps

import jwt
from flask import Flask, jsonify, request
from flask_cors import CORS

# Crear la aplicación Flask
app = Flask(__name__)
CORS(app, origins=['*'], supports_credentials=True)

# ✅ CORRIGIENDO PATHS - Base de datos compartida entre servicios
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# Subir un nivel para acceder a la BD compartida
SHARED_DB_DIR = os.path.join(BASE_DIR, '..', 'shared_data')
os.makedirs(SHARED_DB_DIR, exist_ok=True)  # Crear directorio si no existe
DB_NAME = os.path.join(SHARED_DB_DIR, 'main_database.db')
SECRET_KEY = 'jkhfcjkdhsclhjsafjchlkrhfkhjfkñqj'

# Decorador para requerir token JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token requerido'}), 401
        try:
            token = token.replace('Bearer ', '')
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            request.user = data
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido'}), 401
        return f(*args, **kwargs)
    return decorated

# ✅ INICIALIZACIÓN DE LA BASE DE DATOS COMPARTIDA
def init_db():
    """Verifica e inicializa las tablas necesarias en la BD compartida"""
    db_exists = os.path.exists(DB_NAME)
    
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            
            # ✅ VERIFICAR QUE EXISTAN LAS TABLAS NECESARIAS
            # Tabla de usuarios (debería existir si auth service se ejecutó primero)
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
            
            # Verificar datos existentes
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM tasks")
            task_count = cursor.fetchone()[0]
            
            conn.commit()
            
            if not db_exists:
                print(f"✅ Task Service: Base de datos compartida inicializada: {DB_NAME}")
            else:
                print(f"✅ Task Service: Conectado a BD compartida: {DB_NAME}")
                print(f"   - Usuarios disponibles: {user_count}")
                print(f"   - Tareas existentes: {task_count}")
                
    except Exception as e:
        print(f"❌ Task Service: Error inicializando BD compartida: {e}")

# ✅ FUNCIÓN PARA OBTENER TIEMPO UTC CONSISTENTE
def get_utc_now():
    """Obtiene el tiempo actual en UTC de forma consistente"""
    return datetime.datetime.utcnow()

# Ruta raíz para evitar 404
@app.route('/')
def home():
    return {'status': 'Task service activo'}, 200

# Ruta de salud para Render/UptimeRobot
@app.route('/health', methods=['GET'])
def health():
    return {'status': 'OK', 'message': 'Task microservice running'}, 200

# ✅ CREAR TAREA MEJORADA
@app.route('/tasks', methods=['POST'])
@token_required
def create_task():
    data = request.get_json()
    
    # Validar campos requeridos
    required_fields = ['name', 'description', 'deadline']
    missing_fields = [field for field in required_fields if field not in data or not data[field]]
    
    if missing_fields:
        return jsonify({
            'error': 'Faltan campos obligatorios',
            'missing_fields': missing_fields
        }), 400

    try:
        created_by = request.user['id']
        create_at = get_utc_now().isoformat()
        
        # Validar y parsear deadline
        deadline = data['deadline']
        if isinstance(deadline, str):
            try:
                # Intentar parsear la fecha
                deadline_dt = datetime.datetime.fromisoformat(deadline.replace('Z', '+00:00'))
                deadline = deadline_dt.isoformat()
            except ValueError:
                return jsonify({'error': 'Formato de fecha deadline inválido. Use ISO format.'}), 400
        
        status = data.get('status', 'InProgress')
        priority = data.get('priority', 'Medium')
        
        # Validar status
        valid_statuses = ['InProgress', 'Revision', 'Completed', 'Paused']
        if status not in valid_statuses:
            return jsonify({
                'error': 'Estado inválido',
                'valid_statuses': valid_statuses
            }), 400
        
        # Validar prioridad
        valid_priorities = ['Low', 'Medium', 'High', 'Critical']
        if priority not in valid_priorities:
            return jsonify({
                'error': 'Prioridad inválida',
                'valid_priorities': valid_priorities
            }), 400

        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO tasks (name, description, create_at, deadline, status, isAlive, created_by, updated_at, priority)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data['name'].strip(),
                data['description'].strip(),
                create_at,
                deadline,
                status,
                1,  # isAlive
                created_by,
                create_at,  # updated_at
                priority
            ))
            conn.commit()
            task_id = cursor.lastrowid

        return jsonify({
            'message': 'Tarea creada exitosamente',
            'task_id': task_id,
            'created_at': create_at
        }), 201
        
    except Exception as e:
        print(f"❌ Error creando tarea: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

# ✅ OBTENER TAREAS MEJORADO CON FILTROS
@app.route('/tasks', methods=['GET'])
@token_required
def get_tasks():
    try:
        created_by = request.user['id']
        
        # Parámetros de filtrado opcionales
        status_filter = request.args.get('status')
        priority_filter = request.args.get('priority')
        limit = request.args.get('limit', type=int)
        offset = request.args.get('offset', default=0, type=int)
        
        # Construir query base
        query = '''
            SELECT id, name, description, create_at, deadline, status, isAlive, priority, updated_at 
            FROM tasks 
            WHERE created_by = ? AND isAlive = 1
        '''
        params = [created_by]
        
        # Aplicar filtros
        if status_filter:
            query += ' AND status = ?'
            params.append(status_filter)
            
        if priority_filter:
            query += ' AND priority = ?'
            params.append(priority_filter)
        
        # Ordenar por fecha de creación (más recientes primero)
        query += ' ORDER BY create_at DESC'
        
        # Aplicar paginación
        if limit:
            query += ' LIMIT ? OFFSET ?'
            params.extend([limit, offset])
        
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            tasks = cursor.fetchall()
            
            # Contar total de tareas para paginación
            count_query = '''
                SELECT COUNT(*) FROM tasks 
                WHERE created_by = ? AND isAlive = 1
            '''
            count_params = [created_by]
            
            if status_filter:
                count_query += ' AND status = ?'
                count_params.append(status_filter)
                
            if priority_filter:
                count_query += ' AND priority = ?'
                count_params.append(priority_filter)
            
            cursor.execute(count_query, count_params)
            total_count = cursor.fetchone()[0]

        tasks_list = [{
            'id': t[0],
            'name': t[1],
            'description': t[2],
            'create_at': t[3],
            'deadline': t[4],
            'status': t[5],
            'isAlive': bool(t[6]),
            'priority': t[7],
            'updated_at': t[8]
        } for t in tasks]

        return jsonify({
            'tasks': tasks_list,
            'total_count': total_count,
            'returned_count': len(tasks_list),
            'filters_applied': {
                'status': status_filter,
                'priority': priority_filter,
                'limit': limit,
                'offset': offset
            }
        }), 200
        
    except Exception as e:
        print(f"❌ Error obteniendo tareas: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

# Obtener tarea individual
@app.route('/tasks/<int:task_id>', methods=['GET'])
@token_required
def get_task(task_id):
    try:
        created_by = request.user['id']
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, name, description, create_at, deadline, status, isAlive, priority, updated_at 
                FROM tasks 
                WHERE id = ? AND created_by = ? AND isAlive = 1
            ''', (task_id, created_by))
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
            'isAlive': bool(t[6]),
            'priority': t[7],
            'updated_at': t[8]
        }
        return jsonify({'task': task}), 200
        
    except Exception as e:
        print(f"❌ Error obteniendo tarea {task_id}: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

# ✅ ACTUALIZAR TAREA MEJORADA
@app.route('/tasks/<int:task_id>', methods=['PUT'])
@token_required
def update_task(task_id):
    try:
        data = request.get_json()
        created_by = request.user['id']
        
        if not data:
            return jsonify({'error': 'No se recibieron datos para actualizar'}), 400
        
        # Campos permitidos para actualización
        allowed_fields = ['name', 'description', 'deadline', 'status', 'priority']
        update_fields = {field: data[field] for field in allowed_fields if field in data}

        if not update_fields:
            return jsonify({
                'error': 'No se recibieron campos válidos para actualizar',
                'allowed_fields': allowed_fields
            }), 400
        
        # Validaciones
        if 'status' in update_fields:
            valid_statuses = ['InProgress', 'Revision', 'Completed', 'Paused']
            if update_fields['status'] not in valid_statuses:
                return jsonify({
                    'error': 'Estado inválido',
                    'valid_statuses': valid_statuses
                }), 400
        
        if 'priority' in update_fields:
            valid_priorities = ['Low', 'Medium', 'High', 'Critical']
            if update_fields['priority'] not in valid_priorities:
                return jsonify({
                    'error': 'Prioridad inválida',
                    'valid_priorities': valid_priorities
                }), 400
        
        if 'deadline' in update_fields:
            deadline = update_fields['deadline']
            if isinstance(deadline, str):
                try:
                    deadline_dt = datetime.datetime.fromisoformat(deadline.replace('Z', '+00:00'))
                    update_fields['deadline'] = deadline_dt.isoformat()
                except ValueError:
                    return jsonify({'error': 'Formato de fecha deadline inválido'}), 400

        # Agregar timestamp de actualización
        update_fields['updated_at'] = get_utc_now().isoformat()
        
        # Construir query de actualización
