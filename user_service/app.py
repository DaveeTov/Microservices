from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3
import os

# Crear la aplicación Flask
app = Flask(__name__)
CORS(app, origins=["*"], supports_credentials=True)

# Nombre de la base de datos SQLite compartida
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_NAME = os.path.join(BASE_DIR, 'main_database.db')

# Ruta raíz
@app.route('/')
def home():
    return {'status': 'User service activo'}, 200

# Ruta de salud
@app.route('/health', methods=['GET'])
def health():
    return {'status': 'OK', 'message': 'User microservice running'}, 200

# Ruta para obtener la lista de todos los usuarios
@app.route('/users', methods=['GET'])
def get_users():
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email, status FROM users")
            users = cursor.fetchall()
        return jsonify({'users': [
            {'id': u[0], 'username': u[1], 'email': u[2], 'status': u[3]} for u in users
        ]}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Ruta para obtener un usuario específico por su ID
@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email, status FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
        if user:
            return jsonify({'user': {'id': user[0], 'username': user[1], 'email': user[2], 'status': user[3]}}), 200
        return jsonify({'error': 'Usuario no encontrado'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Ruta para actualizar datos de un usuario específico
@app.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Datos no proporcionados'}), 400

    username = data.get('username')
    email = data.get('email')

    if not username or not email:
        return jsonify({'error': 'Username y email son obligatorios'}), 400

    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET username = ?, email = ? WHERE id = ?", (username, email, user_id))
            conn.commit()
            if cursor.rowcount == 0:
                return jsonify({'error': 'Usuario no encontrado'}), 404
        return jsonify({'message': 'Usuario actualizado'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Ruta para desactivar un usuario (borrado lógico)
@app.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET status = 'inactive' WHERE id = ?", (user_id,))
            conn.commit()
            if cursor.rowcount == 0:
                return jsonify({'error': 'Usuario no encontrado'}), 404
        return jsonify({'message': 'Usuario desactivado'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Ejecutar la app Flask en el puerto 5002
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5002))
    app.run(host='0.0.0.0', port=port)
