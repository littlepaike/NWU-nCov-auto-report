import sqlite3

conn = sqlite3.connect('../userInfo.db')

conn.execute('''
CREATE TABLE IF NOT EXISTS user 
    (ID INT PRIMARY KEY   NOT NULL,
    Username      TEXT  NOT NULL,
    password      TEXT   NOT NULL);'''
             )

conn.execute('''
create table IF NOT EXISTS logs (
    id int,
    Username      TEXT  NOT NULL,
    log_time TEXT NOT NULL,
    content TEXT);'''
             )

conn.execute("INSERT OR IGNORE INTO user (ID,Username,password) \
   VALUES (1, 'admin', 123456)");

conn.execute("INSERT OR IGNORE INTO logs (ID,Username,log_time,content) \
   VALUES (1, 'admin','2022-08-13 21.02','已签到')");

conn.commit()
conn.close()
