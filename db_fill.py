from app import db, Task, User, Status, Type, Urgency, Direction, Role
from werkzeug.security import generate_password_hash, check_password_hash

db.create_all()
hash_pwd = generate_password_hash('admin')
hash_pwd2 = generate_password_hash('user')
hash_pwd2 = generate_password_hash('user')
hash_pwd2 = generate_password_hash('user')
hash_pwd2 = generate_password_hash('user')
hash_pwd2 = generate_password_hash('user')
u1 = User(login='admin', fio='Admin A.A.', password=hash_pwd, role_id='2')
u2 = User(login='novozhilov_s_a', fio='Новожилов С.А.', password=hash_pwd2)
u3 = User(login='lupol_d_i', fio='Лупол Д.И.', password=hash_pwd2)
u4 = User(login='eckert_n_a', fio='Экерт Н.А.', password=hash_pwd2)
u5 = User(login='akhmaev_r_f', fio='Ахмаев Р.Ф.', password=hash_pwd2)
u6 = User(login='sushilov_a_a', fio='Сушилов А.А.', password=hash_pwd2)

db.session.add(u1)
db.session.add(u2)
db.session.add(u3)
db.session.add(u4)
db.session.add(u5)
db.session.add(u6)





r1 = Role(name='User')
r2 = Role(name='Admin')
db.session.add(r1)
db.session.add(r2)


d1 = Direction(name='ВХД')
d2 = Direction(name='Комплаенс')
d3 = Direction(name='Касса и инкассация')
d4 = Direction(name='Operations')
d5 = Direction(name='IT')
db.session.add(d1)
db.session.add(d2)
db.session.add(d3)
db.session.add(d4)
db.session.add(d5)

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
