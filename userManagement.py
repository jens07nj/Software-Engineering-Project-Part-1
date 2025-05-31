import sqlite3 as sql
import bcrypt
import datetime

### example
def getUsers():
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM Staff")
    con.close()
    return cur

def AddUser(Username, password):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("INSERT INTO Staff (Username, password) VALUES (?,?);", (Username, password))
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


def connect_db():
    return sql.connect('databaseFiles/database.db')

def insert_screen_data(pretester, patient_id, screen_complete, reason_declined, hearing_loss, booked, pls_call, recorded_time):
    with connect_db() as conn:
        conn.execute("""
    INSERT INTO ScreenData (
        Pretester, RecordedTime, Patientid,
        ScreenCompletion, HearingLoss, Booked,
        PlsCall, ReasonDeclined
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
""", (
    pretester,
    recorded_time,
    patient_id,
    screen_complete,
    hearing_loss,
    booked,
    pls_call,
    reason_declined
))


#def insert_screen_data(pretester, patient_id, screen_complete, reason_declined, hearing_loss, booked, pls_call, recorded_time):

   # recorded_time = datetime.datetime.now()#.isoformat(sep=' ', timespec='seconds')

    #with connect_db() as conn:
        #conn.execute("""
            ### VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        #""", (
            #pretester,
            #recorded_time,
           # patient_id,
           # screen_complete == "yes",
           # hearing_loss == "yes",
          #  booked == "yes",
          #  pls_call == "yes",
           # reason_declined
       # ))
      #  conn.commit()