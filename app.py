from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash,  check_password_hash
from flask_login import LoginManager, UserMixin, login_required

app = Flask(__name__)
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://task_manager_admin:task_manager@localhost/task_manager'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///task_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'a really really really really long secret key'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'authorization'






#Таблицы
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(20), nullable=False)
    direction = db.Column(db.String(20), nullable=False)
    type = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    to_user = db.Column(db.String(20), nullable=False)
    urgency = db.Column(db.String(20), nullable=False)
    date_start = db.Column(db.DateTime, default=datetime.utcnow)
    date_finish = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="Ожидание")

    def __repr__(self):
        return '<Task %r>' % self.id


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    updated_on = db.Column(db.DateTime(), default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return "<{}:{}>".format(self.id, self.login)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


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


@app.route('/')
@app.route('/tasks')
@login_required
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
            return "При добавлении задачи произошла ошибка" + user + direction+ type+ description+to_user+urgency
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