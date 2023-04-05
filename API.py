from flask import Flask, request, jsonify
import sqlite3
import hashlib
import uuid

app = Flask(__name__)
app.secret_key = 'supersecretkey'

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = data['password']
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()

    if user is not None:
        conn.close()
        return jsonify({'error': 'User already exists'}), 400

    token = str(uuid.uuid4())

    c.execute('INSERT INTO users (username, password_hash, token) VALUES (?, ?, ?)', (username, password_hash, token))

    conn.commit()
    conn.close()

    return jsonify({'token': token}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute('SELECT * FROM users WHERE username = ? AND password_hash = ?', (username, password_hash))
    user = c.fetchone()

    if user is None:
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401

    token = str(uuid.uuid4())

    c.execute('UPDATE users SET token = ? WHERE username = ?', (token, username))

    conn.commit()
    conn.close()

    return jsonify({'token': token}), 200

@app.route('/submit-request', methods=['POST'])
def submit_request():
    data = request.json
    token = request.headers.get('Authorization')
    fio = data['fio']
    date = data['date-from']
    info = data['info']
    department = data['department']
    department_fio = data["dep_fio"]
    phone = data['phone']
    email = data['email']
    passport = data['passport']

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute('SELECT * FROM users WHERE token = ?', (token,))
    user = c.fetchone()

    if user is None:
        conn.close()
        return jsonify({'error': 'Unauthorized'}), 401

    c.execute('INSERT INTO requests (user_id, fio, date, department, phone, email, passport) VALUES (?, ?, ?, ?, ?, ?, ?)', (user[0], fio, date, department, phone, email, passport))

    conn.commit()
    conn.close()

    return jsonify({'message': 'Request submitted successfully'}), 201

if __name__ == '__main__':
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, token TEXT)')
    c.execute('CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, fio TEXT, date TEXT, department TEXT, phone TEXT, email TEXT, passport TEXT)')
    conn.commit()
    conn.close()
    app.run(debug=True)
