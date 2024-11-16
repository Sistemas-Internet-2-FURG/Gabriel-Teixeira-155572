from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'sua_secret_key'
app.config['JWT_SECRET_KEY'] = 'seu_jwt_secret_key'  # Chave secreta para gerar tokens
jwt = JWTManager(app)

# Função para gerar hash de senha
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Função para validar login
def authenticate_user(email, password):
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    hashed_password = hash_password(password)
    cur.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, hashed_password))
    user = cur.fetchone()
    conn.close()
    return user

# Rota para renderizar a página de login
@app.route('/')
def index():
    return render_template('login.html')  # Serve o HTML de login

# Rota para renderizar a página de registro
@app.route('/register')
def register_page():
    return render_template('register.html')  # Serve o HTML de registro

@app.route('/register', methods=['POST'])
def register():
    email = request.json.get('email')
    password = request.json.get('password')

    # Verificar se o usuário já existe
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cur.fetchone()

    if user:
        return jsonify(message="Email já registrado"), 400  # Caso o email já exista

    # Criar o novo usuário
    hashed_password = hash_password(password)
    cur.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
    conn.commit()
    conn.close()

    return jsonify(message="Usuário registrado com sucesso"), 201

# Rota de Login que gera o token JWT
@app.route('/login', methods=['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')

    user = authenticate_user(email, password)

    if user:
        access_token = create_access_token(identity=user[0])  # Gera o token com o ID do usuário
        return jsonify(access_token=access_token), 200
    else:
        return jsonify(message="Credenciais inválidas"), 401

# Rota protegida que requer o token JWT
@app.route('/turmas', methods=['GET'])
@jwt_required()
def listar_turmas():
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("SELECT * FROM turmas")
    turmas = cur.fetchall()
    conn.close()
    return jsonify(turmas)

# Rota protegida que requer o token JWT
@app.route('/alunos', methods=['GET'])
@jwt_required()
def listar_alunos():
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("SELECT alunos.id, alunos.nome, turmas.nome FROM alunos JOIN turmas ON alunos.turma_id = turmas.id")
    alunos = cur.fetchall()
    conn.close()
 
    return jsonify(alunos)

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# Função para inicializar o banco de dados
def init_sqlite_db():
    conn = sqlite3.connect('database.db')
    print("Database criada")
    conn.execute('CREATE TABLE IF NOT EXISTS turmas (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT)')
    conn.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, password TEXT NOT NULL)''')
    conn.close()

if __name__ == '__main__':
    init_sqlite_db()
    app.run(debug=True)
