import datetime
import sqlite3
import uuid

cx = sqlite3.connect("E:/test.db")
cu=cx.cursor()
cu.execute('''create table catalog (
            id char(64) primary key,
            chipnum text,
            create_time datetime
        )''')

cx.execute("insert into catalog values ("+uuid.uuid1()+",123,"+ datetime.datetime.now()+")", t)

print(uuid.uuid1())