from datetime import datetime

from flask import Flask, render_template, request, redirect, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://task_manager_admin:task_manager@localhost/task_manager'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///task_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'a really really really really long secret key'

db = SQLAlchemy(app)
login_manager = LoginManager(app)


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(20), unique=True, nullable=False)
    fio = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(1255), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    updated_on = db.Column(db.DateTime(), default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return '<User %r>' % self.login


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


#Таблицы
class Task(db.Model):
    __tablename__ = 'task'
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', foreign_keys=[user_id])

    direction = db.Column(db.String(20), nullable=False)

    type_id = db.Column(db.Integer, db.ForeignKey('type.id'), nullable=False)
    type = db.relationship('Type', foreign_keys=[type_id])

    description = db.Column(db.Text, nullable=False)

    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    to_user = db.relationship('User', foreign_keys=[to_user_id])

    urgency_id = db.Column(db.Integer, db.ForeignKey('urgency.id'), nullable=False)
    urgency = db.relationship('Urgency', foreign_keys=[urgency_id])

    date_start = db.Column(db.DateTime, default=datetime.utcnow)
    date_finish = db.Column(db.DateTime, default=datetime.utcnow)

    status_id = db.Column(db.Integer, db.ForeignKey('status.id'), nullable=False)
    status = db.relationship('Status', foreign_keys=[status_id])

    def __repr__(self):
        return '<Task %r>' % self.id


class Status(db.Model):
    __tablename__ = 'status'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return '<Status %r>' % self.name


class Type(db.Model):
    __tablename__ = 'type'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return '<Type %r>' % self.name


class Urgency(db.Model):
    __tablename__ = 'urgency'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return '<Urgency %r>' % self.name


#


@app.route('/login', methods=['POST', 'GET'])
def login_page():
    login = request.form.get('login')
    password = request.form.get('password')
    if login and password:
        user_login = User.query.filter_by(login=login).first()

        if user_login and check_password_hash(user_login.password, password):
            login_user(user_login)
            return render_template("tasks.html")
        else:
            flash('Неправильный логин или пароль')
    else:
        flash('Заполните и логин и пароль')
    return render_template("login.html")



@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return render_template("login.html")


@app.route('/register', methods=['POST', 'GET'])
def register():

    if request.method == "POST":
        users = User.query.order_by(User.id).all()

        login = request.form['login']
        fio = request.form['fio']
        password = request.form['password']
        password2 = request.form['password2']
        if not(login or fio or password or password2):
            flash('Заполните все поля')
        elif password != password2:
            flash('Пароли не совпадают')
        else:
            hash_pwd = generate_password_hash(password)
            new_user = User(login=login, fio=fio, password=hash_pwd)
            try:
                db.session.add(new_user)
                db.session.commit()
                return render_template('login.html')
            except:
                return "При добавлении задачи произошла ошибка"
    else:
        users = User.query.order_by(User.id).all()
    return render_template("register.html", users=users)


@app.route('/')
@app.route('/tasks')
def index():
    tasks = Task.query.order_by(Task.date_start.desc()).all()
    return render_template("tasks.html", tasks=tasks)


@app.route('/tasks/<int:id>')
@login_required
def task_detail(id):
    task = Task.query.get(id)
    return render_template("task_detail.html", task=task)


@app.route('/taskadd', methods=['POST', 'GET'])
@login_required
def addtask():
    if request.method == "POST":
        user = request.form['user']
        direction = request.form['direction']
        type = request.form['type']
        description = request.form['description']
        to_user = request.form['to_user']
        urgency = request.form['urgency']
        #date_finish = request.form['date_finish']

        task = Task(user=user, direction=direction, type=type, description=description, to_user=to_user,
                    urgency=urgency)

        try:
            db.session.add(task)
            db.session.commit()
            return redirect('/')
        except:
            print()
            return "При добавлении задачи произошла ошибка"
    else:
        return render_template("task_add.html")


@app.route('/storagescripts')
@login_required
def storagescripts():
    return render_template("storage_scripts.html")


@app.route('/statistics')
@login_required
def statistics():
    return render_template("statistics.html")


@app.route('/about')
@login_required
def about():
    return render_template("about.html")


@app.route('/user/<string:name>/<int:id>')
@login_required
def user(name,id):
    return "User page: " + name + " - " + str(id)


if __name__ == "__main__":
    app.run(debug=True)