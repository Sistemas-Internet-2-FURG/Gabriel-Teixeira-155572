# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, redirect, url_for
import sqlite3

app = Flask(__name__)

def init_sqlite_db():
    conn = sqlite3.connect('database.db')
    print("Database opened successfully")

    conn.execute('CREATE TABLE IF NOT EXISTS turmas (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT)')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS alunos (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            nome TEXT, 
            turma_id INTEGER, 
            FOREIGN KEY (turma_id) REFERENCES turmas (id)
        )
    ''')
    print("Tabela feita")
    conn.close()

init_sqlite_db()

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/turmas')
def listar_turmas():
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("SELECT * FROM turmas")
    turmas = cur.fetchall()
    conn.close()
    return render_template('listar_turmas.html', turmas=turmas)

@app.route('/turmas/add', methods=['POST'])
def adicionar_turma():
    if request.method == 'POST':
        try:
            nome = request.form['nome']
            conn = sqlite3.connect('database.db')
            cur = conn.cursor()
            cur.execute("INSERT INTO turmas (nome) VALUES (?)", (nome,))
            conn.commit()
            conn.close()
            return redirect(url_for('listar_turmas'))
        except Exception as e:
            return str(e)

@app.route('/alunos')
def listar_alunos():
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("SELECT alunos.id, alunos.nome, turmas.nome FROM alunos JOIN turmas ON alunos.turma_id = turmas.id")
    alunos = cur.fetchall()
    conn.close()
    return render_template('listar_alunos.html', alunos=alunos)

@app.route('/alunos/add', methods=['GET', 'POST'])
def adicionar_aluno():
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()

    if request.method == 'POST':
        try:
            nome = request.form['nome']
            turma_id = request.form['turma_id']
            cur.execute("INSERT INTO alunos (nome, turma_id) VALUES (?, ?)", (nome, turma_id))
            conn.commit()
            return redirect(url_for('listar_alunos'))
        except Exception as e:
            return str(e)
    else:
      
        cur.execute("SELECT * FROM turmas")
        turmas = cur.fetchall()
        conn.close()
        return render_template('listar_alunos.html', turmas=turmas)



@app.route('/turmas/edit/<int:id>', methods=['GET', 'POST'])
def editar_turma(id):
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()

    if request.method == 'POST':
        nome = request.form['nome']
        cur.execute("UPDATE turmas SET nome = ? WHERE id = ?", (nome, id))
        conn.commit()
        conn.close()
        return redirect(url_for('listar_turmas'))

    cur.execute("SELECT * FROM turmas WHERE id = ?", (id,))
    turma = cur.fetchone()
    conn.close()
    return render_template('editar_turma.html', turma=turma)

@app.route('/alunos/edit/<int:id>', methods=['GET', 'POST'])
def editar_aluno(id):
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()

    if request.method == 'POST':
        nome = request.form['nome']
        turma_id = request.form['turma_id']
        cur.execute("UPDATE alunos SET nome = ?, turma_id = ? WHERE id = ?", (nome, turma_id, id))
        conn.commit()
        conn.close()
        return redirect(url_for('listar_alunos'))

    cur.execute("SELECT * FROM alunos WHERE id = ?", (id,))
    aluno = cur.fetchone()
    cur.execute("SELECT * FROM turmas")
    turmas = cur.fetchall()
    conn.close()
    return render_template('editar_aluno.html', aluno=aluno, turmas=turmas)

@app.route('/turmas/delete/<int:id>', methods=['GET'])
def deletar_turma(id):
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("DELETE FROM turmas WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('listar_turmas'))

@app.route('/alunos/delete/<int:id>', methods=['GET'])
def deletar_aluno(id):
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("DELETE FROM alunos WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('listar_alunos'))

if __name__ == '__main__':
    app.run(debug=True)

