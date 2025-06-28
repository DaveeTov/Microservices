# user_service.py
from flask import Flask, jsonify, request
import sqlite3

# Crear la aplicación Flask
app = Flask(__name__)

# Nombre de la base de datos SQLite compartida
DB_NAME = 'main_database.db'

# Ruta para obtener la lista de todos los usuarios
@app.route('/users', methods=['GET'])
def get_users():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        # Seleccionar campos id, username, email y status de todos los usuarios
        cursor.execute("SELECT id, username, email, status FROM users")
        users = cursor.fetchall()
    # Construir lista de usuarios en formato JSON
    return jsonify({'users': [
        {'id': u[0], 'username': u[1], 'email': u[2], 'status': u[3]} for u in users
    ]})

# Ruta para obtener un usuario específico por su id
@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        # Buscar el usuario con el id indicado
        cursor.execute("SELECT id, username, email, status FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
    if user:
        # Si se encuentra, devolver datos del usuario
        return jsonify({'user': {'id': user[0], 'username': user[1], 'email': user[2], 'status': user[3]}})
    # Si no se encuentra, devolver error 404
    return jsonify({'error': 'Usuario no encontrado'}), 404

# Ruta para actualizar datos de un usuario específico
@app.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    data = request.get_json()  # Obtener datos enviados (JSON)
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        # Actualizar username y email del usuario con id dado
        cursor.execute("UPDATE users SET username = ?, email = ? WHERE id = ?",
                       (data.get('username'), data.get('email'), user_id))
        conn.commit()
    return jsonify({'message': 'Usuario actualizado'})

# Ruta para desactivar un usuario (cambia status a 'inactive')
@app.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        # Actualizar status a 'inactive' (borrado lógico)
        cursor.execute("UPDATE users SET status = 'inactive' WHERE id = ?", (user_id,))
        conn.commit()
    return jsonify({'message': 'Usuario desactivado'})

# Ejecutar la app Flask en el puerto 5002 con debug activado
if __name__ == '__main__':
    app.run(port=5002, debug=True)
