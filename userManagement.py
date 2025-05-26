import sqlite3 as sql
import bcrypt


### example
def getUsers():
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM Staff")
    con.close()
    return cur

def addUser(Username, password):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    cur.execute("INSERT INTO Staff (Username, password) VALUES (?, ?)", (Username, hashed_password))
    con.commit()
    con.close()
def validate_user(Username, password):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("SELECT password FROM Staff WHERE Username = ?", (Username,))
    result = cur.fetchone()
    con.close()
    
    if result is None:
        return False
    
    if result[0] == password: 
        return True
    return False
    #hashed_password = result[0]
    #return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))