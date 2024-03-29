import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, flash, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, \
    AnonymousUserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from flask_ckeditor import CKEditor




app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///task_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'a really really really really long secret key'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login_page'
login_manager.login_message = ''

app.config['CKEDITOR_SERVE_LOCAL'] = 'True'
app.config['CKEDITOR_PKG_TYPE'] = 'standard'

ckeditor = CKEditor(app)


class Anonymous(AnonymousUserMixin):
    def __init__(self):
        self.role = 'Guest'


login_manager.anonymous_user = Anonymous


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


class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)

    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    task = db.relationship('Task', foreign_keys=[task_id])

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', foreign_keys=[user_id])

    description = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return '<Log %r>' % self.description


# Таблицы
class Task(db.Model):
    __tablename__ = 'task'
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', foreign_keys=[user_id])

    direction_id = db.Column(db.Integer, db.ForeignKey('direction.id'), nullable=False)
    direction = db.relationship('Direction', foreign_keys=[direction_id])

    type_id = db.Column(db.Integer, db.ForeignKey('type.id'), nullable=False)
    type = db.relationship('Type', foreign_keys=[type_id])

    title = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, nullable=False)

    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    to_user = db.relationship('User', foreign_keys=[to_user_id])

    urgency_id = db.Column(db.Integer, db.ForeignKey('urgency.id'), nullable=False)
    urgency = db.relationship('Urgency', foreign_keys=[urgency_id])



    datetimeutc = datetime.utcnow()
    datetimenow = datetimeutc + timedelta(hours=3)
    strdatetime = datetimenow.strftime('%Y-%m-%d %H:%M')
    datetimenow = datetime.strptime(strdatetime, '%Y-%m-%d %H:%M')

    date_start = db.Column(db.DateTime(), default=datetimenow)
    date_finish = db.Column(db.DateTime(), default=datetimenow)



    status_id = db.Column(db.Integer, db.ForeignKey('status.id'), nullable=False, default='1')
    status = db.relationship('Status', foreign_keys=[status_id])

    rating = db.Column(db.Integer, nullable=False,  default='0')

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


@app.route('/login', methods=['POST', 'GET'])
def login_page():
    if current_user.is_authenticated:
        return redirect("/tasks")
    else:
        login = request.form.get('login')
        password = request.form.get('password')
        if login and password:
            user_login = User.query.filter_by(login=login).first()

            if user_login and check_password_hash(user_login.password, password):
                login_user(user_login)
                return redirect("/tasks")
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
@login_required
def register():
    if current_user.role.name == 'Admin':
        if request.method == "POST":
            login = request.form['login']
            fio = request.form['fio']
            password = request.form['password']
            password2 = request.form['password2']
            if not (login or fio or password or password2):
                flash('Заполните все поля')
            elif password != password2:
                flash('Пароли не совпадают')
            else:
                hash_pwd = generate_password_hash(password)
                new_user = User(login=login, fio=fio, password=hash_pwd)
                try:
                    db.session.add(new_user)
                    db.session.commit()
                    return redirect('/admin_panel')
                except:
                    return "При добавлении пользователя произошла ошибка"
        return render_template("register.html")
    else:
        return redirect("/tasks")


@app.route('/')
@app.route('/tasks')
def index():
    tasks = Task.query.order_by(Task.date_start.desc()).all()
    directions = Direction.query.order_by(Direction.id).all()
    return render_template("tasks.html", tasks=tasks, directions=directions)


@app.route('/tasks/<int:id>')
@login_required
def task_detail(id):
    task = Task.query.get(id)
    logs = Log.query.filter_by(task_id=id)
    name = current_user.fio
    directions = Direction.query.order_by(Direction.id).all()
    types = Type.query.order_by(Type.id).all()
    users = User.query.order_by(User.id).filter(User.id != '1')
    urgency = Urgency.query.order_by(Urgency.id).all()
    status = Status.query.order_by(Status.id).all()
    return render_template("task_detail.html", task=task, name=name, directions=directions, types=types, users=users,
                           urgency=urgency, status=status, logs=logs)


@app.route('/tasks/<int:id>/delete_task')
@login_required
def tasks_del_task(id):
    task = Task.query.get_or_404(id)
    logs = Log.query.filter_by(task_id=id).all()

    try:
        db.session.delete(task)
        for i in logs:
            db.session.delete(i)
        db.session.commit()
        return redirect("/tasks")
    except:
        return "При удалении произошла ошибка"


@app.route('/tasks/<int:id>/update_task', methods=['POST', 'GET'])
@login_required
def tasks_update_task(id):
    task = Task.query.get(id)
    if request.method == "POST":
        log_descr = "<dt>" + current_user.fio + "</dt>"
        task.direction_id = request.form['direction']
        task.type_id = request.form['type']
        task.title = request.form['title']
        task.description = request.form['description']

        if str(task.to_user_id) != str(request.form['to_user']):
            if request.form['to_user'] == '0':
                log_descr += "<dd>Снял назначение</dd>"
            else:
                log_descr += "<dd>Переназначил на: " + User.query.get(request.form['to_user']).fio + "</dd>"
        task.to_user_id = request.form['to_user']

        if str(task.urgency_id) != str(request.form['urgency']):
            log_descr += "<dd>Изменил приоритет на: " + Urgency.query.get(request.form['urgency']).name + "</dd>"
        task.urgency_id = request.form['urgency']




        if str(task.date_finish) != str(datetime.strptime(request.form['date_finish'], '%Y-%m-%dT%H:%M')):
            log_descr += "<dd>Изменил время на: " + str(
                datetime.strptime(request.form['date_finish'], '%Y-%m-%dT%H:%M')) + "</dd>"
        task.date_finish = datetime.strptime(request.form['date_finish'], '%Y-%m-%dT%H:%M')

        if str(task.status_id) != str(request.form['status']):
            log_descr += "<dd>Изменил статус на: " + Status.query.get(request.form['status']).name + "</dd>"
        task.status_id = request.form['status']
        if request.form['rating']:
            if str(task.rating) != str(request.form['rating']):
                log_descr += "<dd>Изменил оценку на: " + request.form['rating'] + "</dd>"
            task.rating = request.form['rating']
        if log_descr != str("<dt>" + current_user.fio + "</dt>"):
            log_descr += " (" + datetime.now().strftime('%Y-%m-%d %H:%M') + ")"
            user = current_user.id
            log = Log(task_id=id, user_id=user, description=log_descr)
            db.session.add(log)
            db.session.commit()

        try:
            db.session.commit()
            return redirect('/tasks')
        except:
            return "При редактировании задачи произошла ошибка"
    else:

        name = current_user.fio
        directions = Direction.query.order_by(Direction.id).all()
        types = Type.query.order_by(Type.id).all()
        users = User.query.order_by(User.id).all()
        urgency = Urgency.query.order_by(Urgency.id).all()
        return render_template("task_add.html", name=name, directions=directions, types=types, users=users,
                               urgency=urgency)


@app.route('/taskadd', methods=['POST', 'GET'])
@login_required
def taskadd():
    if request.method == "POST":
        user = current_user.id
        direction = request.form['direction']
        type = request.form['type']
        title = request.form['title']
        description = request.form['description']
        to_user = request.form['to_user']
        urgency = request.form['urgency']

        try:
            date_finish = datetime.strptime(request.form['date_finish'], '%Y-%m-%dT%H:%M')
        except:
            datetimeutc = datetime.utcnow()
            datetimenow = datetimeutc + timedelta(hours=3)
            strdatetime = datetimenow.strftime('%Y-%m-%d %H:%M')
            date_finish = datetime.strptime(strdatetime, '%Y-%m-%d %H:%M')

        task = Task(user_id=user, direction_id=direction, type_id=type, title=title, description=description,
                    to_user_id=to_user,
                    urgency_id=urgency, date_finish=date_finish)

        db.session.add(task)
        db.session.commit()
        task_id = Task.query.order_by(Task.id.desc()).first().id
        if to_user != "0":
            log_descr = "<dt>" + current_user.fio + "</dt>" + "<dd> Cоздал задачу и назначил на: " + User.query.get(
                to_user).fio + "</dd>"
        else:
            log_descr = "<dt>" + current_user.fio + "</dt>" + "<dd> Cоздал задачу"
        log_descr += " (" + str(task.date_finish) + ")"
        log = Log(task_id=task_id, user_id=user, description=log_descr)
        db.session.add(log)
        db.session.commit()
        return redirect('/')
    else:

        name = current_user.fio
        directions = Direction.query.order_by(Direction.id).all()
        types = Type.query.order_by(Type.id).all()
        users = User.query.order_by(User.id).filter(User.id != '1')
        urgency = Urgency.query.order_by(Urgency.id).all()
        return render_template("task_add.html", name=name, directions=directions, types=types, users=users,
                               urgency=urgency)


@app.route('/storagescripts', methods=['POST', 'GET'])
@login_required
def storagescripts():
    return render_template("storage_scripts.html")


@app.route('/storagescripts/open', methods=['POST', 'GET'])
@login_required
def storagescripts_open():
    try:
        path = "C:\\Users"
        path = os.path.realpath(path)
        os.startfile(path)
        return redirect("/storagescripts")
    except:
        print("Файл не найден")

    return render_template("storage_scripts.html")


@app.route('/statistics')
@login_required
def statistics():
    # res = Task.query.group_by(Task.user_id).all()
    # res = Task.query.join(User, User.id == Task.user_id).group_by(User.id).all()
    # user = User.query.with_entities(User.id, User.fio) \
    #     .filter((User.id != 1)) \
    #     .order_by(User.id) \
    #     .all()
    #
    # tasks = Task.query \
    #     .with_entities(Task.user_id, func.count(Task.user_id)) \
    #     .group_by(Task.user_id) \
    #     .order_by(Task.user_id) \
    #     .all()
    #
    # tasks = Task.query \
    #     .with_entities(Task.to_user_id, func.count(Task.to_user_id)) \
    #     .group_by(Task.to_user_id) \
    #     .order_by(Task.to_user_id) \
    #     .all()

    create = db.session.query(User.fio, func.count(Task.user))\
        .outerjoin(Task, User.id == Task.user_id)\
        .group_by(User.id)\
        .order_by(User.fio)\
        .all()

    set = db.session.query(User.fio, func.count(Task.to_user))\
        .outerjoin(Task, User.id == Task.to_user_id)\
        .group_by(User.id)\
        .order_by(User.fio)\
        .all()

    inwork = db.session.query(User.fio, func.count(Task.status_id).filter(Task.status_id=='2'))\
        .outerjoin(Task, User.id==Task.to_user_id)\
        .group_by(User.fio) \
        .order_by(User.fio) \
        .all()

    done = db.session.query(User.fio, func.count(Task.status_id).filter(Task.status_id == '3')) \
        .outerjoin(Task, User.id == Task.to_user_id) \
        .group_by(User.fio) \
        .order_by(User.fio) \
        .all()

    return render_template("statistics.html", create=create, set=set, inwork=inwork, done=done)


@app.route('/about')
@login_required
def about():
    return render_template("about.html")


@app.route('/user/<string:login>/<int:id>')
@login_required
def user(login, id):
    user = User.query.get(id)
    tasks = Task.query.filter((Task.user_id == user.id) | (Task.to_user_id == user.id)).order_by(
        Task.date_start.desc()).all()
    return render_template("user_home.html", user=user, tasks=tasks)


@app.route('/admin_panel', methods=['POST', 'GET'])
@login_required
def admin():
    users = User.query.order_by(User.id).all()
    direction = Direction.query.order_by(Direction.id).all()
    type_list = Type.query.order_by(Type.id).all()
    return render_template("admin.html", users=users, direction=direction, type=type_list)


@app.route('/admin_panel/<int:id>')
@login_required
def user_detail(id):
    user = User.query.get(id)
    roles = Role.query.order_by(Role.id).all()
    return render_template("user_update.html", user=user, roles=roles)


@app.route('/user/<int:id>/user_update', methods=['POST', 'GET'])
@login_required
def home_update_user(id):
    user = User.query.get(id)

    if request.method == "POST":
        fio = request.form['fio']
        password = request.form['password']
        password2 = request.form['password2']

        if password and (password == password2):
            hash_pwd = generate_password_hash(password)
            user.password = hash_pwd
            flash("Пароль изменен")
        elif password or password2 and (password != password2):
            flash("Пароли не совпадают")
            return redirect(url_for('user', login=user.login, id=user.id))

        else:
            flash("Пароль не изменен")

        user.fio = fio
        try:
            db.session.commit()
            return redirect('/admin_panel')
        except:
            return "При добавлении пользователя произошла ошибка"
    else:
        return redirect("/admin_panel")

    return redirect("/tasks")


@app.route('/admin_panel/<int:id>/user_update', methods=['POST', 'GET'])
@login_required
def admin_update_user(id):
    if current_user.role.name == 'Admin':
        user = User.query.get(id)
        if request.method == "POST":
            login = request.form['login']
            fio = request.form['fio']

            role = request.form['role']
            password = request.form['password']
            password2 = request.form['password2']

            if password and (password == password2):
                hash_pwd = generate_password_hash(password)
                user.password = hash_pwd
                flash("Пароль изменен")
            else:
                flash("Пароль не изменен")

            user.login = login
            user.fio = fio
            user.role_id = role
            try:
                db.session.commit()
                return redirect('/admin_panel')
            except:
                return "При добавлении пользователя произошла ошибка"
        else:

            return redirect("/admin_panel")
    else:
        return redirect("/tasks")


@app.route('/admin_panel/<int:id>/user_delete', methods=['POST', 'GET'])
@login_required
def admin_del_user(id):
    if current_user.role.name == 'Admin':
        user = User.query.get_or_404(id)
        if user.role.id != 2:
            try:
                db.session.delete(user)
                db.session.commit()
                return redirect("/admin_panel")
            except:
                return "При удалении произошла ошибка"
        else:
            return redirect("/admin_panel")
    else:
        return redirect("/tasks")


@app.route('/admin_panel/add_direction', methods=['POST', 'GET'])
@login_required
def admin_add_redirection():
    if current_user.role.name == 'Admin':
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
    else:
        return redirect("/tasks")


@app.route('/admin_panel/add_type', methods=['POST', 'GET'])
@login_required
def admin_add_type():
    if current_user.role.name == 'Admin':
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
    else:
        return redirect("/tasks")


@app.route('/admin_panel/<int:id>/delete_type', methods=['POST', 'GET'])
@login_required
def admin_del_type(id):
    if current_user.role.name == 'Admin':
        type = Type.query.get_or_404(id)
        try:
            db.session.delete(type)
            db.session.commit()
            return redirect("/admin_panel")
        except:
            return "При удалении произошла ошибка"
    else:
        return redirect("/tasks")


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
    app.run(host='0.0.0.0', port=5005, debug=True)
