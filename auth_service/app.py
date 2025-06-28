# auth_service.py
from flask import Flask, request, jsonify
import sqlite3
import os
import jwt
import datetime
import requests
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Crear la aplicación Flask
app = Flask(__name__)

# Clave secreta para firmar los tokens JWT
SECRET_KEY = 'jkhfcjkdhsclhjsafjchlkrhfkhjfkñqj'

# Nombre del archivo de base de datos SQLite
DB_NAME = os.path.join(BASE_DIR, 'main_database.db')

# Función para inicializar la base de datos y crear la tabla de usuarios si no existe
def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                status TEXT DEFAULT 'active'
            )
        ''')

# Ruta para registrar un nuevo usuario (método POST)
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()  # Obtener datos JSON enviados en la solicitud

    # Validar que se reciban los campos requeridos
    if not data or 'username' not in data or 'password' not in data or 'email' not in data:
        return jsonify({'error': 'Faltan campos'}), 400  # Responder con error si falta algún campo

    # Hashear la contraseña para guardar de forma segura en la base de datos
    hashed_password = generate_password_hash(data['password'])

    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            # Insertar nuevo usuario en la tabla users
            cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                           (data['username'], hashed_password, data['email']))
            conn.commit()  # Guardar cambios en la base de datos
            user_id = cursor.lastrowid  # Obtener ID del usuario recién creado

        # Responder con mensaje de éxito y el ID del usuario creado
        return jsonify({'message': 'Usuario registrado correctamente', 'user_id': user_id}), 201
    except sqlite3.IntegrityError:
        # Si el nombre de usuario ya existe (restricción UNIQUE), devolver error 409 (conflicto)
        return jsonify({'error': 'Nombre de usuario ya existe'}), 409

# Ruta para login de usuarios (método POST)
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()  # Obtener datos JSON de la solicitud

    # Validar que estén los campos requeridos
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Faltan campos'}), 400

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        # Buscar usuario en la base de datos por username
        cursor.execute("SELECT * FROM users WHERE username = ?", (data['username'],))
        user = cursor.fetchone()

    # user[2] es la contraseña hasheada almacenada
    # Verificar que exista el usuario y que la contraseña ingresada coincida con el hash
    if user and check_password_hash(user[2], data['password']):
        # Crear un token JWT que incluye id, username y expiración a 1 hora
        token = jwt.encode({
            'id': user[0],
            'username': user[1],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, SECRET_KEY, algorithm='HS256')

        # Devolver token JWT al cliente
        return jsonify({'token': token})

    # Si usuario no existe o contraseña no coincide, devolver error 401
    return jsonify({'error': 'Credenciales incorrectas'}), 401

# Ejecutar la aplicación Flask
if __name__ == '__main__':
    init_db()  # Crear la base de datos y tabla si no existen
    app.run(port=5001, debug=True)  # Ejecutar en puerto 5001 con debug activado (modo desarrollo)
