import sqlite3
import pdb
DATABASE = 'server.db'

dbh = None
def get_db_handle():
    dbh = None 
    if dbh == None:
        try:
            dbh = sqlite3.connect(DATABASE, isolation_level=None, check_same_thread=False)
        except sqlite3.Error as e:
            print(e)
    return dbh


def query_db(query, args=(), one=False):
    cur = get_db_handle().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def get_password(username):
    customer = query_db('select * from users where username = ?', [username], one=True)
    if customer is None:
        print('No such user')
    else:
        # print(type(customer))
        # print(customer_ph, 'is in the state ', customer['customer_state'])
        return customer[2]
def insert_users(username,password):
    cur = get_db_handle().execute(
        'insert into users (username,password) values (?,?)',
        (username,password))
    get_db_handle().commit()
    print("inserted customer", username)

def insert_slots(date,slot):
    cur = get_db_handle().execute(
        'insert into slots (date,available,not_available) values (?,?,?)',
        (date,slot,"NONE"))
    get_db_handle().commit()
    print("inserted customer", slot)

def update_slots_available(date, available_slot):
    # put checkout id in the db
    cur = get_db_handle().execute("UPDATE slots SET available = ? WHERE date = ? ",
                                  (available_slot,date), )
    get_db_handle().commit()  # print(shipping_id)
def update_slots_not_available(date, available_slot):
    # put checkout id in the db
    cur = get_db_handle().execute("UPDATE slots SET not_available = ?  WHERE date = ? ",
                                  (available_slot,date), )
    get_db_handle().commit()  # print(shipping_id)
def get_available_slots(date):
    customer = query_db('select * from slots where date = ?', [date], one=True)
    if customer is None:
        print('No such user')
    else:
        # print(type(customer))
        # print(customer_ph, 'is in the state ', customer['customer_state'])
        return customer[2]
def get_not_available_slots(date):
    customer = query_db('select * from slots where date = ?', [date], one=True)
    if customer is None:
        print('No such user')
    else:
        # print(type(customer))
        # print(customer_ph, 'is in the state ', customer['customer_state'])
        return customer[3]
def get_date(date):
    customer = query_db('select * from slots where date = ?', [date])
    if customer:
        return 'YES'
    else:
        return 'None'
if __name__=='__main__':
    insert_users('Kummur','123')
    print(get_password('Kummur'))