from flask import Flask, redirect, url_for, render_template, request, flash, session,abort
from flask_sessions import Session
import sqlite3
import os
import pathlib

import requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'hfhdaihdkfkj80834dfsd'
app.config['SESSION_TYPE'] = 'filesystem'
admin_username = 'admin'
admin_password = 'admin'
staffs_username = 'XYZ'

s = Session(app)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "1017001808656-hhtur6m5706lqkfm76klk2ol1sd5i3hi.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secert.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)
def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper

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

@app.route('/', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        insert_users(username,password)
        render_template('login.html')
    return render_template('login.html')


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        return render_template('admin_login.html')


@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if request.method == 'POST':
        result = request.form
        username = result['username']
        password = result['password']
        session['admin_username'] = username
        if username == admin_username and password == admin_password:
            print('log')
            staffs = ['satff1', 'staff2', 'staff3', 'staff4', 'staff5']
            bookings = ['Monday 3-4 Gagan', 'Tuesday 9-10 Hell']
            return render_template('admin_dashboard.html', staff=staffs, booking=bookings)
        else:
            flash('Wrong Password')
            return redirect(url_for('admin'))
    else:
        if session['admin_username'] != None:
            staffs = ['satff1', 'staff2', 'staff3', 'staff4', 'staff5']
            bookings = ['Monday 3-4 Gagan', 'Tuesday 9-10 Hell']
            return render_template('admin_dashboard.html', staff=staffs, booking=bookings)
        else:
            flash('Wrong Password')
            return redirect(url_for('admin'))




@app.route('/staff', methods=['GET', 'POST'])
def staff():
    if request.method == 'POST':
        return render_template('staff_login.html')


@app.route('/staff/dashboard', methods=['GET', 'POST'])
def staff_dashboard():
    if request.method == 'POST':
        result = request.form
        username = result['username']
        password = result['password']
        session['staff_username']= username
        if username == staffs_username and password == staffs_username:
            print('log')
            bookings = ['Monday 3-4 Gagan', 'Tuesday 9-10 Hell']
            return render_template('staff_dashboard.html', booking=bookings)
        else:
            flash('Wrong Password')
            return redirect(url_for('staff'))


@app.route('/member',methods = ['GET','POST'])
def member():
    return render_template('member.html')
@app.route('/member/register', methods = ['GET','POST'])
def registration():
    return render_template('registration.html')
@app.route('/member/login', methods = ['GET','POST'])
def member_login():
    return render_template('member_login.html')
@app.route("/google_login")
def google_login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)
@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["username"] = id_info.get("name")
    return redirect("/member/dashboard")

@app.route('/member/dashboard',methods = ['GET','POST'])
@login_is_required
def member_dashboard():
    if session.get('username') != None:
        return render_template('member_dashboard.html')
    if request.method == 'POST':
        result = request.form
        username = result['username']
        password = result['password']
        session['username'] = username
        print('ssu ', session.get('username'))
        if password == get_password(username):
            #print(session.get('username'))
            return render_template('member_dashboard.html')
        else:
            flash('Wrong Password')
            return redirect(url_for('member_login'))



@app.route('/member/dashboard/booking_ondate',methods = ['GET','POST'])
def member_booking():
    if session.get('username') != None:
        if request.method == 'POST':
            date = request.form['date']
            if get_date(date) != 'None':
                available_slots = str(get_available_slots(date)).split(' ')
                print(available_slots)
                not_available_slot = str(get_not_available_slots(date)).split(' ')
                print(not_available_slot)
                return render_template('available_slots.html',available_slots=available_slots,not_available_slot=not_available_slot,date=[date])
            else:
                insert_slots(date,'9-12 2-5 6-9')
                available_slots = str(get_available_slots(date)).split(' ')
                print(available_slots)
                not_available_slot = str(get_not_available_slots(date)).split(' ')
                print(not_available_slot)
                return render_template('available_slots.html',available_slots=available_slots,not_available_slot=not_available_slot,date=[date])
    else:
        return redirect(url_for('login'))

@app.route('/member/dashboard/booking_ondate/booking_confirm', methods =['GET','POST'])
def booking_confirm():
        if request.method == 'POST':
            time = request.form['time']
            print('rime',session.get('username'))
            date = request.form['date']
            print(date)
            available_slots = str(get_available_slots(date)).split(' ')
            new_lst =[]
            for i in range(len(available_slots)):
                if available_slots[i] != time:
                    new_lst.append(available_slots[i])
            available_slots = " ".join(new_lst)
            print(available_slots)
            not_available_slots = time
            print("g", not_available_slots)
            update_slots_available(date,available_slots)
            update_slots_not_available(date,not_available_slots)
            return redirect(url_for('member_dashboard'))
if __name__ == '__main__':
    app.run()
