import sqlite3

db = 'server.db'

conn = sqlite3.connect(db)
conn.execute(''' Create Table users
    (ID INTEGER PRIMARY KEY autoincrement,
    USERNAME INT  NOT NULL,
    PASSWORD TEXT NOT NULL);
''')
conn.execute(''' Create Table slots
    (ID INTEGER PRIMARY KEY autoincrement,
    DATE DATE  NOT NULL,
    AVAILABLE TEXT NOT NULL,
    NOT_AVAILABLE TEXT NOT NULL);
''')
print('sucess')
conn.close()