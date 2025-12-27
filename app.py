# =============================================
# WORLD CHAT WEBSITE (PYTHON + FLASK)
# WITH ADMIN CREATION, LOGIN & DASHBOARD UI
# =============================================
# Features:
# - User registration (unique username + name)
# - User login
# - Admin creation & login
# - World chat
# - Private chat
# - User search
# - Admin dashboard (ban users, delete messages)

# ---------- INSTALL ----------
# pip install flask flask_sqlalchemy flask_login werkzeug

from flask import Flask, request, redirect, url_for, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------- DATABASE MODELS ----------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), default='user')  # admin/user
    banned = db.Column(db.Boolean, default=False)

class WorldMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500))
    username = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PrivateMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(50))
    receiver = db.Column(db.String(50))
    text = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------- ROUTES ----------

@app.route('/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        name = request.form['name']
        password = generate_password_hash(request.form['password'])

        if User.query.filter_by(username=username).first():
            return 'Username already exists'

        user = User(username=username, name=name, password=password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect('/world')

    return render_template_string('''
    <h2>User Register</h2>
    <form method="post">
      Username <input name="username"><br>
      Name <input name="name"><br>
      Password <input type="password" name="password"><br>
      <button>Register</button>
    </form>
    <a href="/login">Login</a> | <a href="/admin_create">Create Admin</a>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect('/world')
        return 'Invalid login'

    return render_template_string('''
    <h2>Login</h2>
    <form method="post">
      Username <input name="username"><br>
      Password <input type="password" name="password"><br>
      <button>Login</button>
    </form>
    ''')

@app.route('/admin_create', methods=['GET', 'POST'])
def admin_create():
    if request.method == 'POST':
        user = User(
            username=request.form['username'],
            name=request.form['name'],
            password=generate_password_hash(request.form['password']),
            role='admin'
        )
        db.session.add(user)
        db.session.commit()
        return 'Admin created successfully. Go to login.'

    return render_template_string('''
    <h2>Create Admin</h2>
    <form method="post">
      Username <input name="username"><br>
      Name <input name="name"><br>
      Password <input type="password" name="password"><br>
      <button>Create Admin</button>
    </form>
    ''')

@app.route('/world', methods=['GET', 'POST'])
@login_required
def world():
    if current_user.banned:
        return 'You are banned'

    if request.method == 'POST':
        db.session.add(WorldMessage(text=request.form['msg'], username=current_user.username))
        db.session.commit()

    msgs = WorldMessage.query.all()
    return render_template_string('''
    <h2>World Chat</h2>
    {% for m in msgs %}
      <p><b>{{m.username}}</b>: {{m.text}}
      {% if current_user.role=='admin' %}
        <a href="/delete/{{m.id}}">[delete]</a>
      {% endif %}
      </p>
    {% endfor %}
    <form method="post">
      <input name="msg">
      <button>Send</button>
    </form>
    <a href="/search">Search</a> | 
    {% if current_user.role=='admin' %}<a href="/admin">Admin Dashboard</a> |{% endif %}
    <a href="/logout">Logout</a>
    ''', msgs=msgs)

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    users = []
    if request.method == 'POST':
        q = request.form['q']
        users = User.query.filter((User.username==q)|(User.name==q)).all()

    return render_template_string('''
    <h2>Search User</h2>
    <form method="post"><input name="q"><button>Search</button></form>
    {% for u in users %}
      <p>{{u.username}} ({{u.name}}) <a href="/private/{{u.username}}">Chat</a></p>
    {% endfor %}
    ''', users=users)

@app.route('/private/<username>', methods=['GET','POST'])
@login_required
def private(username):
    if request.method == 'POST':
        db.session.add(PrivateMessage(sender=current_user.username, receiver=username, text=request.form['msg']))
        db.session.commit()

    msgs = PrivateMessage.query.filter(
        ((PrivateMessage.sender==current_user.username)&(PrivateMessage.receiver==username)) |
        ((PrivateMessage.sender==username)&(PrivateMessage.receiver==current_user.username))
    ).all()

    return render_template_string('''
    <h2>Chat with {{username}}</h2>
    {% for m in msgs %}<p><b>{{m.sender}}</b>: {{m.text}}</p>{% endfor %}
    <form method="post"><input name="msg"><button>Send</button></form>
    ''', msgs=msgs, username=username)

@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin': return 'Access denied'
    users = User.query.all()
    return render_template_string('''
    <h2>Admin Dashboard</h2>
    {% for u in users %}
      <p>{{u.username}} | {{u.role}} | Banned: {{u.banned}}
      <a href="/ban/{{u.id}}">Toggle Ban</a></p>
    {% endfor %}
    <a href="/world">Back</a>
    ''', users=users)

@app.route('/ban/<int:id>')
@login_required
def ban(id):
    if current_user.role!='admin': return 'Denied'
    user = User.query.get(id)
    user.banned = not user.banned
    db.session.commit()
    return redirect('/admin')

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    if current_user.role!='admin': return 'Denied'
    WorldMessage.query.filter_by(id=id).delete()
    db.session.commit()
    return redirect('/world')

@app.route('/logout')
def logout():
    logout_user()
    return redirect('/')

# ---------- RUN ----------
if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(host="0.0.0.0", port=10000)

