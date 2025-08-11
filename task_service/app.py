import datetime
import os
import sqlite3
import traceback
from functools import wraps

import jwt
from flask import Flask, jsonify, request

app = Flask(__name__)

# ====== Paths / DB ======
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SHARED_DB_DIR = os.path.join(BASE_DIR, '..', 'shared_data')
os.makedirs(SHARED_DB_DIR, exist_ok=True)
DB_NAME = os.path.join(SHARED_DB_DIR, 'main_database.db')

# Debe coincidir con el SECRET del Auth Service/Gateway
SECRET_KEY = 'jkhfcjkdhsclhjsafjchlkrhfkhjfkñqj'

# ====== Helpers ======
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

def _ensure_user_and_get_id():
    """
    Asegura que exista un registro en users y devuelve su id.
    - Si el JWT trae id numérico y NO existe en users -> lo inserta con ese id.
    - Si trae email/username -> busca e inserta si falta.
    """
    user_payload = getattr(request, "user", {}) or {}
    raw_id = user_payload.get('id') or user_payload.get('user_id') or user_payload.get('sub')
    email = (user_payload.get('email') or "").strip() or None
    username = (user_payload.get('username') or "").strip() or None

    # Normaliza id numérico si existe
    numeric_id = None
    try:
        if raw_id is not None:
            numeric_id = int(raw_id)
    except (TypeError, ValueError):
        numeric_id = None

    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("PRAGMA foreign_keys = ON;")

        # 1) Si trae id numérico, verifica existencia
        if numeric_id is not None:
            c.execute("SELECT id FROM users WHERE id = ?", (numeric_id,))
            row = c.fetchone()
            if row:
                return numeric_id
            # Insertar forzado con id
            ins_username = username or f"user_{numeric_id}"
            ins_email = email or f"user_{numeric_id}@example.local"
            c.execute("""
                INSERT INTO users (id, username, password, email, status)
                VALUES (?, ?, ?, ?, 'active')
            """, (numeric_id, ins_username, '!', ins_email))
            conn.commit()
            return numeric_id

        # 2) Si no hay id, probar por email
        if email:
            c.execute("SELECT id FROM users WHERE email = ?", (email,))
            row = c.fetchone()
            if row:
                return int(row[0])
            ins_username = username or email.split('@')[0]
            c.execute("""
                INSERT INTO users (username, password, email, status)
                VALUES (?, '!', ?, 'active')
            """, (ins_username, email))
            conn.commit()
            return int(c.lastrowid)

        # 3) Si no hay email, probar username
        if username:
            c.execute("SELECT id FROM users WHERE username = ?", (username,))
            row = c.fetchone()
            if row:
                return int(row[0])
            c.execute("""
                INSERT INTO users (username, password, email, status)
                VALUES (?, '!', ?, 'active')
            """, (username, f"{username}@example.local"))
            conn.commit()
            return int(c.lastrowid)

    # Si no hay forma de identificarlo, devuelve None
    return None

def init_db():
    """Inicializa tablas si no existen."""
    db_exists = os.path.exists(DB_NAME)
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys = ON;")

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

            conn.commit()

        print(f"✅ Task Service DB: {DB_NAME} ({'new' if not db_exists else 'existing'})")

    except Exception as e:
        print(f"❌ Task Service: Error inicializando BD: {e}")
        traceback.print_exc()

init_db()

def get_utc_now():
    return datetime.datetime.utcnow()

# ====== Rutas ======
@app.route('/')
def home():
    return {'status': 'Task service activo'}, 200

@app.route('/health', methods=['GET'])
def health():
    return {'status': 'OK', 'message': 'Task microservice running'}, 200

# --- DEBUG: info rápida
@app.route('/tasks/debug', methods=['GET'])
@token_required
def tasks_debug():
    try:
        resolved_uid = _ensure_user_and_get_id()
        user_payload = getattr(request, 'user', {})
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM tasks")
            total = c.fetchone()[0]
            c.execute("""
                SELECT id, name, created_by, status, isAlive, create_at, deadline
                FROM tasks
                ORDER BY id DESC
                LIMIT 10
            """)
            rows = c.fetchall()
        return jsonify({
            'resolved_user_id': resolved_uid,
            'jwt_payload': user_payload,
            'total_tasks_in_db': total,
            'last_10_tasks_raw': [
                {
                    'id': r[0], 'name': r[1], 'created_by': r[2],
                    'status': r[3], 'isAlive': r[4],
                    'create_at': r[5], 'deadline': r[6]
                } for r in rows
            ]
        }), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# --- Crear tarea
@app.route('/tasks', methods=['POST'])
@token_required
def create_task():
    data = request.get_json() or {}
    required_fields = ['name', 'description', 'deadline']
    missing = [f for f in required_fields if not data.get(f)]
    if missing:
        return jsonify({'error': 'Faltan campos obligatorios', 'missing_fields': missing}), 400

    try:
        created_by = _ensure_user_and_get_id()
        print(f"[DEBUG] POST /tasks resolved_user_id={created_by} payload={getattr(request,'user',{})}")

        if not created_by:
            return jsonify({'error': 'Token inválido: no se pudo resolver el id de usuario'}), 401

        create_at = get_utc_now().isoformat()

        deadline = data['deadline']
        if isinstance(deadline, str):
            try:
                deadline_dt = datetime.datetime.fromisoformat(deadline.replace('Z', '+00:00'))
                deadline = deadline_dt.isoformat()
            except ValueError:
                return jsonify({'error': 'Formato de fecha deadline inválido. Use ISO 8601.'}), 400

        status = data.get('status', 'InProgress')
        priority = data.get('priority', 'Medium')

        valid_statuses = ['InProgress', 'Revision', 'Completed', 'Paused']
        if status not in valid_statuses:
            return jsonify({'error': 'Estado inválido', 'valid_statuses': valid_statuses}), 400

        valid_priorities = ['Low', 'Medium', 'High', 'Critical']
        if priority not in valid_priorities:
            return jsonify({'error': 'Prioridad inválida', 'valid_priorities': valid_priorities}), 400

        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("PRAGMA foreign_keys = ON;")
            c.execute('''
                INSERT INTO tasks (name, description, create_at, deadline, status, isAlive, created_by, updated_at, priority)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data['name'].strip(),
                data['description'].strip(),
                create_at,
                deadline,
                status,
                1,
                created_by,
                create_at,
                priority
            ))
            conn.commit()
            task_id = c.lastrowid

        print(f"[DEBUG] INSERT OK id={task_id} created_by={created_by}")

        return jsonify({
            'message': 'Tarea creada exitosamente',
            'task': {
                'id': task_id,
                'name': data['name'].strip(),
                'description': data['description'].strip(),
                'create_at': create_at,
                'deadline': deadline,
                'status': status,
                'isAlive': True,
                'priority': priority,
                'updated_at': create_at
            }
        }), 201

    except sqlite3.IntegrityError as e:
        # Errores de FK/constraints más claros
        print(f"❌ IntegrityError creando tarea: {e}")
        return jsonify({'error': 'Violación de integridad (FK/constraints)', 'details': str(e)}), 400
    except Exception as e:
        print(f"❌ Error creando tarea: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Error interno del servidor'}), 500

# --- Listar tareas del usuario
@app.route('/tasks', methods=['GET'])
@token_required
def get_tasks():
    try:
        created_by = _ensure_user_and_get_id()
        print(f"[DEBUG] GET /tasks resolved_user_id={created_by} payload={getattr(request,'user',{})}")

        if not created_by:
            return jsonify({'error': 'Token inválido: no se pudo resolver el id de usuario'}), 401

        status_filter = request.args.get('status')
        priority_filter = request.args.get('priority')
        limit = request.args.get('limit', type=int)
        offset = request.args.get('offset', default=0, type=int)

        query = '''
            SELECT id, name, description, create_at, deadline, status, isAlive, priority, updated_at 
            FROM tasks 
            WHERE created_by = ? AND isAlive = 1
        '''
        params = [created_by]

        if status_filter:
            query += ' AND status = ?'
            params.append(status_filter)
        if priority_filter:
            query += ' AND priority = ?'
            params.append(priority_filter)

        query += ' ORDER BY create_at DESC'

        if limit is not None:
            query += ' LIMIT ? OFFSET ?'
            params.extend([limit, offset])

        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute(query, params)
            tasks = c.fetchall()

            count_query = 'SELECT COUNT(*) FROM tasks WHERE created_by = ? AND isAlive = 1'
            count_params = [created_by]
            if status_filter:
                count_query += ' AND status = ?'
                count_params.append(status_filter)
            if priority_filter:
                count_query += ' AND priority = ?'
                count_params.append(priority_filter)
            c.execute(count_query, count_params)
            total_count = c.fetchone()[0]

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

        print(f"[DEBUG] GET /tasks returned_count={len(tasks_list)} total_for_user={total_count}")

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
        traceback.print_exc()
        return jsonify({'error': 'Error interno del servidor'}), 500

# --- Obtener tarea individual
@app.route('/tasks/<int:task_id>', methods=['GET'])
@token_required
def get_task(task_id):
    try:
        created_by = _ensure_user_and_get_id()
        print(f"[DEBUG] GET /tasks/{task_id} resolved_user_id={created_by}")
        if not created_by:
            return jsonify({'error': 'Token inválido: no se pudo resolver el id de usuario'}), 401

        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('''
                SELECT id, name, description, create_at, deadline, status, isAlive, priority, updated_at 
                FROM tasks 
                WHERE id = ? AND created_by = ? AND isAlive = 1
            ''', (task_id, created_by))
            t = c.fetchone()

        if not t:
            return jsonify({'error': 'Tarea no encontrada'}), 404

        task = {
            'id': t[0], 'name': t[1], 'description': t[2],
            'create_at': t[3], 'deadline': t[4], 'status': t[5],
            'isAlive': bool(t[6]), 'priority': t[7], 'updated_at': t[8]
        }
        return jsonify({'task': task}), 200

    except Exception as e:
        print(f"❌ Error obteniendo tarea {task_id}: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Error interno del servidor'}), 500

# --- Actualizar tarea completa
@app.route('/tasks/<int:task_id>', methods=['PUT'])
@token_required
def update_task(task_id):
    try:
        created_by = _ensure_user_and_get_id()
        print(f"[DEBUG] PUT /tasks/{task_id} resolved_user_id={created_by}")
        if not created_by:
            return jsonify({'error': 'Token inválido: no se pudo resolver el id de usuario'}), 401

        data = request.get_json() or {}
        allowed_fields = ['name', 'description', 'deadline', 'status', 'priority']
        update_fields = {f: data[f] for f in allowed_fields if f in data}
        if not update_fields:
            return jsonify({'error': 'No se recibieron campos válidos para actualizar', 'allowed_fields': allowed_fields}), 400

        if 'status' in update_fields:
            valid_statuses = ['InProgress', 'Revision', 'Completed', 'Paused']
            if update_fields['status'] not in valid_statuses:
                return jsonify({'error': 'Estado inválido', 'valid_statuses': valid_statuses}), 400

        if 'priority' in update_fields:
            valid_priorities = ['Low', 'Medium', 'High', 'Critical']
            if update_fields['priority'] not in valid_priorities:
                return jsonify({'error': 'Prioridad inválida', 'valid_priorities': valid_priorities}), 400

        if 'deadline' in update_fields and isinstance(update_fields['deadline'], str):
            try:
                deadline_dt = datetime.datetime.fromisoformat(update_fields['deadline'].replace('Z', '+00:00'))
                update_fields['deadline'] = deadline_dt.isoformat()
            except ValueError:
                return jsonify({'error': 'Formato de fecha deadline inválido'}), 400

        update_fields['updated_at'] = get_utc_now().isoformat()

        set_clause = ', '.join(f"{field} = ?" for field in update_fields.keys())
        values = list(update_fields.values()) + [task_id, created_by]

        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute(f'''
                UPDATE tasks SET {set_clause}
                WHERE id = ? AND created_by = ? AND isAlive = 1
            ''', values)
            conn.commit()

            if c.rowcount == 0:
                return jsonify({'error': 'Tarea no encontrada o no autorizada'}), 404

        return jsonify({
            'message': 'Tarea actualizada exitosamente',
            'task_id': task_id,
            'updated_fields': list(update_fields.keys()),
            'updated_at': update_fields['updated_at']
        }), 200

    except Exception as e:
        print(f"❌ Error actualizando tarea {task_id}: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Error interno del servidor'}), 500

# --- Actualizar SOLO el estado (drag & drop)
@app.route('/tasks/<int:task_id>/status', methods=['PUT'])
@token_required
def update_task_status(task_id):
    try:
        created_by = _ensure_user_and_get_id()
        print(f"[DEBUG] PUT /tasks/{task_id}/status resolved_user_id={created_by}")
        if not created_by:
            return jsonify({'error': 'Token inválido: no se pudo resolver id de usuario'}), 401

        data = request.get_json() or {}
        new_status = data.get('status')
        valid_statuses = ['InProgress', 'Revision', 'Completed', 'Paused']
        if new_status not in valid_statuses:
            return jsonify({'error': 'Estado inválido', 'valid_statuses': valid_statuses}), 400

        updated_at = get_utc_now().isoformat()
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('''
                UPDATE tasks
                SET status = ?, updated_at = ?
                WHERE id = ? AND created_by = ? AND isAlive = 1
            ''', (new_status, updated_at, task_id, created_by))
            conn.commit()

            if c.rowcount == 0:
                return jsonify({'error': 'Tarea no encontrada o no autorizada'}), 404

        return jsonify({'message': 'Estado actualizado', 'task_id': task_id, 'status': new_status, 'updated_at': updated_at}), 200

    except Exception as e:
        print(f"❌ Error actualizando estado de tarea {task_id}: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Error interno del servidor'}), 500

# --- Borrado lógico
@app.route('/tasks/<int:task_id>', methods=['DELETE'])
@token_required
def delete_task(task_id):
    try:
        created_by = _ensure_user_and_get_id()
        print(f"[DEBUG] DELETE /tasks/{task_id} resolved_user_id={created_by}")
        if not created_by:
            return jsonify({'error': 'Token inválido: no se pudo resolver el id de usuario'}), 401

        current_time = get_utc_now().isoformat()
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('''
                UPDATE tasks SET isAlive = 0, updated_at = ?
                WHERE id = ? AND created_by = ? AND isAlive = 1
            ''', (current_time, task_id, created_by))
            conn.commit()

            if c.rowcount == 0:
                return jsonify({'error': 'Tarea no encontrada o no autorizada'}), 404

        return jsonify({
            'message': 'Tarea eliminada exitosamente (borrado lógico)',
            'task_id': task_id,
            'deleted_at': current_time
        }), 200

    except Exception as e:
        print(f"❌ Error eliminando tarea {task_id}: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Error interno del servidor'}), 500

# --- Estadísticas
@app.route('/tasks/stats', methods=['GET'])
@token_required
def get_task_stats():
    try:
        created_by = _ensure_user_and_get_id()
        print(f"[DEBUG] GET /tasks/stats resolved_user_id={created_by}")
        if not created_by:
            return jsonify({'error': 'Token inválido: no se pudo resolver el id de usuario'}), 401

        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()

            c.execute('''
                SELECT status, COUNT(*) as count
                FROM tasks 
                WHERE created_by = ? AND isAlive = 1
                GROUP BY status
            ''', (created_by,))
            status_stats = {row[0]: row[1] for row in c.fetchall()}

            c.execute('''
                SELECT priority, COUNT(*) as count
                FROM tasks 
                WHERE created_by = ? AND isAlive = 1
                GROUP BY priority
            ''', (created_by,))
            priority_stats = {row[0]: row[1] for row in c.fetchall()}

            c.execute('''
                SELECT COUNT(*) FROM tasks 
                WHERE created_by = ? AND isAlive = 1
            ''', (created_by,))
            total_tasks = c.fetchone()[0]

            c.execute('''
                SELECT COUNT(*) FROM tasks 
                WHERE created_by = ? AND isAlive = 1 
                AND deadline < ? AND status != 'Completed'
            ''', (created_by, get_utc_now().isoformat()))
            overdue_tasks = c.fetchone()[0]

        return jsonify({
            'total_tasks': total_tasks,
            'overdue_tasks': overdue_tasks,
            'status_distribution': status_stats,
            'priority_distribution': priority_stats,
            'generated_at': get_utc_now().isoformat()
        }), 200

    except Exception as e:
        print(f"❌ Error obteniendo estadísticas: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Error interno del servidor'}), 500

# --- Info BD
@app.route('/db-info', methods=['GET'])
def db_info():
    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in c.fetchall()]

            c.execute("SELECT COUNT(*) FROM users")
            user_count = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM tasks WHERE isAlive = 1")
            active_tasks = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM tasks WHERE isAlive = 0")
            deleted_tasks = c.fetchone()[0]

        return jsonify({
            'service': 'task_service',
            'database_path': DB_NAME,
            'database_exists': os.path.exists(DB_NAME),
            'tables': tables,
            'counts': {
                'users': user_count,
                'active_tasks': active_tasks,
                'deleted_tasks': deleted_tasks
            },
            'server_time': get_utc_now().isoformat()
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({
            'error': str(e),
            'database_path': DB_NAME,
            'database_exists': os.path.exists(DB_NAME)
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5002))
    print(f"🚀 Task Service on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
