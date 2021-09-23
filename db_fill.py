from app import db, Task, User, Status, Type, Urgency, Direction, Role
from werkzeug.security import generate_password_hash, check_password_hash

db.create_all()
hash_pwd = generate_password_hash('admin')
hash_pwd2 = generate_password_hash('user1')
hash_pwd3 = generate_password_hash('user2')
u1 = User(login='admin', fio='Иванов И.И.', password=hash_pwd, role_id='2')
u2 = User(login='user1', fio='Петров П.П.', password=hash_pwd2)
u3 = User(login='user2', fio='Сидоров С.С.', password=hash_pwd3)
db.session.add(u1)
db.session.add(u2)
db.session.add(u3)

r1 = Role(name='User')
r2 = Role(name='Admin')
db.session.add(r1)
db.session.add(r2)


d1 = Direction(name='ОАОП')
d2 = Direction(name='Комплаенс')
d3 = Direction(name='ВХД')
db.session.add(d1)
db.session.add(d2)
db.session.add(d3)

st1 = Status(name='Ожидание')
st2 = Status(name='В работе')
st3 = Status(name='Выполнено')
db.session.add(st1)
db.session.add(st2)
db.session.add(st3)

t1 = Type(name='Выгрузка')
t2 = Type(name='Изучить')
t3 = Type(name='Спринт')
db.session.add(t1)
db.session.add(t2)
db.session.add(t3)

ur1 = Urgency(name='Низкий')
ur2 = Urgency(name='Средний')
ur3 = Urgency(name='Высокий')
db.session.add(ur1)
db.session.add(ur2)
db.session.add(ur3)

# task1 = Task(user_id='1', direction='1', type_id='1', description='Описание бла бла', to_user_id='2',
#              urgency_id='1', status_id='1')
# db.session.add(task1)

db.session.commit()
