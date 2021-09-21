from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash,  check_password_hash


app = Flask(__name__)
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://task_manager_admin:task_manager@localhost/task_manager'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///task_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'a really really really really long secret key'

db = SQLAlchemy(app)


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


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(20), unique=True, nullable=False)
    fio = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    updated_on = db.Column(db.DateTime(), default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return '<User %r>' % self.login


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
@app.route('/useradd', methods=['POST', 'GET'])
def useradd():
    if request.method == "POST":
        login = request.form['login']
        password = request.form['password']
        user = User(login=login, password=password)

        try:
            db.session.add(user)
            db.session.commit()
            return redirect('/authorization')
        except:
            return "При добавлении задачи произошла ошибка" +login+password
    else:
        return render_template("user_add.html")


@app.route('/authorization')
def authorization():
    return render_template("authorization.html")


@app.route('/registration', methods=['POST', 'GET'])
def registration():
    if request.method == "POST":
        login = request.form['login']
        fio = request.form['fio']
        password = request.form['password']

        user = User(login=login, fio=fio, password=password)
        try:
            db.session.add(user)
            db.session.commit()
            return redirect('/registration')
        except:
            print()
            return "При добавлении задачи произошла ошибка"
    else:
        users = User.query.order_by(User.id).all()
        return render_template("registration.html", users=users)


@app.route('/')
@app.route('/tasks')
def index():
    tasks = Task.query.order_by(Task.date_start.desc()).all()
    return render_template("tasks.html", tasks=tasks)


@app.route('/tasks/<int:id>')
def task_detail(id):
    task = Task.query.get(id)
    return render_template("task_detail.html", task=task)


@app.route('/taskadd', methods=['POST', 'GET'])
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
def storagescripts():
    return render_template("storage_scripts.html")


@app.route('/statistics')
def statistics():
    return render_template("statistics.html")


@app.route('/about')
def about():
    return render_template("about.html")


@app.route('/user/<string:name>/<int:id>')
def user(name,id):
    return "User page: " + name + " - " + str(id)


if __name__ == "__main__":
    app.run(debug=True)