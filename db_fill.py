from app import db, Task, User, Status, Type, Urgency

db.create_all()
u1 = User(login='admin', fio='Иванов И.И.', password='password')
u2 = User(login='user', fio='Петров П.П.', password='password')
db.session.add(u1)
db.session.add(u2)

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

ur1 = Urgency(name='Зеленый')
ur2 = Urgency(name='Желтый')
ur3 = Urgency(name='Красный')
db.session.add(ur1)
db.session.add(ur2)
db.session.add(ur3)

task1 = Task(user_id='1', direction='ОАОП', type_id='1', description='Описание бла бла', to_user_id='2',
             urgency_id='1', status_id='1')
db.session.add(task1)

db.session.commit()
