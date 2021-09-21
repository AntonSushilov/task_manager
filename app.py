from datetime import datetime

from flask import Flask, render_template, request, redirect, flash, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
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

    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False, default='1')
    role = db.relationship('Role', foreign_keys=[role_id])

    def __repr__(self):
        return '<User %r>' % self.login


class Role(db.Model):
    __tablename__ = 'role'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return '<Role %r>' % self.name


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


#Таблицы
class Task(db.Model):
    __tablename__ = 'task'
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', foreign_keys=[user_id])

    direction_id = db.Column(db.Integer, db.ForeignKey('direction.id'), nullable=False)
    direction = db.relationship('Direction', foreign_keys=[direction_id])

    type_id = db.Column(db.Integer, db.ForeignKey('type.id'), nullable=False)
    type = db.relationship('Type', foreign_keys=[type_id])

    description = db.Column(db.Text, nullable=False)

    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    to_user = db.relationship('User', foreign_keys=[to_user_id])

    urgency_id = db.Column(db.Integer, db.ForeignKey('urgency.id'), nullable=False)
    urgency = db.relationship('Urgency', foreign_keys=[urgency_id])

    date_start = db.Column(db.DateTime(), default=datetime.utcnow())
    date_finish = db.Column(db.DateTime(), default=datetime.utcnow)

    status_id = db.Column(db.Integer, db.ForeignKey('status.id'), nullable=False, default='1')
    status = db.relationship('Status', foreign_keys=[status_id])

    def __repr__(self):
        return '<Task %r>' % self.id


class Direction(db.Model):
    __tablename__ = 'direction'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return '<Status %r>' % self.name


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
            tasks = Task.query.order_by(Task.date_start.desc()).all()
            return render_template("tasks.html", tasks=tasks)
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
    #tasks = Task.query(Task.id, User.fio, Task.direction, Type.name,
    #                    Task.description, User.fio, Urgency.name,
     #                   Task.date_start, Task.date_finish,
      #                  Status.name).filter(Task.user_id==User.id, Task.type_id==Type.id,
       #                                     Task.to_user_id==User.id, Task.urgency_id==Urgency.id,
        #                                    Task.status_id==Status.id).order_by(Task.date_start.desc())

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
        user = current_user.id
        direction = request.form['direction']
        type = request.form['type']
        description = request.form['description']
        to_user = request.form['to_user']
        urgency = request.form['urgency']
        date_finish = datetime.strptime(request.form['date_finish'], '%Y-%m-%dT%H:%M')
        print(user, direction, type, description, to_user, urgency, date_finish)
        task = Task(user_id=user, direction_id=direction, type_id=type, description=description, to_user_id=to_user,
                    urgency_id=urgency, date_finish=date_finish)

        try:
            db.session.add(task)
            db.session.commit()
            return redirect('/')
        except:
            print()
            return "При добавлении задачи произошла ошибка"
    else:

        name = current_user.fio
        directions = Direction.query.order_by(Direction.id).all()
        types = Type.query.order_by(Type.id).all()
        users = User.query.order_by(User.id).all()
        urgency = Urgency.query.order_by(Urgency.id).all()
        return render_template("task_add.html", name=name, directions=directions, types=types, users=users, urgency=urgency)


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


@app.route('/admin_panel', methods=['POST', 'GET'])
@login_required
def admin():
    users = User.query.order_by(User.id).all()
    direction = Direction.query.order_by(Direction.id).all()
    type_list = Type.query.order_by(Type.id).all()
    return render_template("admin.html", users=users, direction=direction, type=type_list)


@app.route('/admin_panel/add_direction', methods=['POST', 'GET'])
@login_required
def admin_add_redirection():
    if request.method == "POST":
        if request.form['add_direction']:
            name = request.form['direction_name']
            direction = Direction(name=name)
            try:
                db.session.add(direction)
                db.session.commit()
                return redirect("/admin_panel")
            except:
                return "При добавлении направления произошла ошибка"
    return redirect("/admin_panel")


@app.route('/admin_panel/add_type', methods=['POST', 'GET'])
@login_required
def admin_add_type():
    if request.method == "POST":
        if request.form['add_type']:
            name = request.form['type_name']
            type = Type(name=name)
            try:
                db.session.add(type)
                db.session.commit()
                return redirect("/admin_panel")
            except:
                return "При добавлении задачи произошла ошибка"
    return redirect("/admin_panel")


@app.route('/admin_panel/<int:id>/delete_type', methods=['POST', 'GET'])
@login_required
def admin_del_type(id):
    type = Type.query.get_or_404(id)
    try:
        db.session.delete(type)
        db.session.commit()
        return redirect("/admin_panel")
    except:
        return "При удалении произошла ошибка"


@app.route('/admin_panel/<int:id>/delete_direction', methods=['POST', 'GET'])
@login_required
def admin_del_dir(id):
    direction = Direction.query.get_or_404(id)
    try:
        db.session.delete(direction)
        db.session.commit()
        return redirect("/admin_panel")
    except:
        return "При удалении произошла ошибка"



if __name__ == "__main__":
    app.run(debug=True)


