from flask import Flask, request, jsonify,render_template
import sqlite3
import hashlib
import uuid

app = Flask(__name__)
app.secret_key = 'supersecretkey'




# Основной маршрут приложения
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/personal')
def personal():
    return render_template('personal.html')


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
    try:
        data = request.json
        fio = data['visitorFullName']
        date_ = data['dateFrom']
        info = data['visitPurpose']
        department = data['subdivision']
        department_fio = data["fullName"]
        phone = data['visitorPhone']
        email = data['visitorEmail']
        passport = data['visitorPassport']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('INSERT INTO requests (fio,date_,info,department,department_fio,phone,email,passport) VALUES (?,?,?,?,?,?,?,?)', (fio,date_,info,department,department_fio,phone,email,passport))

        conn.commit()
        conn.close()
        return "ok"
       # return jsonify({'message': 'Request submitted successfully'}), 201
    except Exception as e:
        print(str(e))
        return str(e)
        print(e)


# Обработка страницы 404
@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(401)
def page_not_found(error):
    return render_template('401.html'), 401


if __name__ == '__main__':
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, token TEXT)')
    c.execute('CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, fio TEXT, date TEXT, department TEXT, phone TEXT, email TEXT, passport TEXT)')
    conn.commit()
    conn.close()
    app.run(host='0.0.0.0', port=80, debug=True)
