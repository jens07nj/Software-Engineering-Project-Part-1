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

def get_user_role(username):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("SELECT staff_role FROM Staff WHERE Username = ?", (username,))
    row = cur.fetchone()
    con.close()
    # Return a plain string (or None if not found)
    return row[0] if row else None


def AddUser(Username, password):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    try:
        # Insert into Staff
        cur.execute(
            "INSERT INTO Staff (Username, password) VALUES (?, ?);",
            (Username, password)
        )

        # Insert into Staff_points (defaults will set points, coffees, total_points to 0)
        cur.execute(
            "INSERT INTO Staff_points (Username) VALUES (?);",
            (Username,)
        )

        con.commit()
    except sql.IntegrityError as e:
        print("Error inserting user:", e)
        con.rollback()
    finally:
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

def addPoints(pretester):
    with connect_db() as conn:
        # Step 1: increment points & total_points
        conn.execute("""
            UPDATE Staff_points
            SET points = points + 1,
                total_points = total_points + 1
            WHERE Staff_points.Username = ?;
        """, (pretester,))
        
        # Step 2: check current points
        cur = conn.execute("""
            SELECT points FROM Staff_points WHERE Username = ?;
        """, (pretester,))
        current_points = cur.fetchone()[0]

        # Step 3: rollover if needed
        if current_points >= 100:
            conn.execute("""
                UPDATE Staff_points
                SET coffees = coffees + 1,
                    points = 0
                WHERE Username = ?;
            """, (pretester,))

        conn.commit()

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