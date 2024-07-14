from flask import Flask, g, flash, redirect, render_template, request, session, url_for, jsonify
from flask_session import Session
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import psycopg2
from dotenv import load_dotenv
from config import *
from tables import create

load_dotenv()

app = Flask(__name__)
app.config.from_object('config')

def get_db():
    if 'db' not in g:
        g.db = psycopg2.connect(
            dbname=POSTGRES_DATABASE,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            host=POSTGRES_HOST,
            port=POSTGRES_PORT,
            sslmode='require'
        )
    return g.db

def get_cursor():
    db = get_db()
    return db.cursor()

@app.teardown_appcontext
def close_db(error):
    if 'db' in g:
        g.db.close()

create()

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.secret_key = '123xyzabc456'
Session(app)

# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_id, username, user_type):
        self.id = user_id
        self.username = username
        self.user_type = user_type

@login_manager.user_loader
def load_user(user_id):
    with get_cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        if user_data:
            return User(user_id=user_data[0], username=user_data[1], user_type=user_data[4])
        return None

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
def index():
    if not session:
        return redirect("/login")
    user_id = session.get("user_id")
    notif = session.pop('notif', None)
    type = session.get("type")
    if not user_id:
        return redirect("/login")
    try:
        with get_cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            cursor.execute(
                "SELECT posts.id, posts.content, posts.header, users.id as user_id, users.username as username, users.name as name, users.location "
                "FROM posts JOIN users ON posts.user_id = users.id"
            )
            posts = cursor.fetchall()
        return render_template("index.html", posts=posts, user=user, notification=notif, type=type)
    except Exception as e:
        print(str(e))
        flash("An error occurred. Please try again later or wait for some time.", "danger")
        return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        user_type = ""
        if "donor" in request.args:
            user_type = "donor"
        elif "donor_org" in request.args:
            user_type = "Donor Organisation"
        elif "recipient" in request.args:
            user_type = "recipient"
        return render_template("register.html", u=user_type)
    elif request.method == "POST":
        name = request.form.get("name")
        uname = request.form.get("username")
        pw1 = request.form.get("password")
        pw2 = request.form.get("confirmation")
        mail = request.form.get("email")
        user_type = request.form.get("user_type")
        location = request.form.get("location")
        if not uname or not name or not pw1 or not pw2 or not user_type or not location or not mail:
            flash("Missing inputs", "warning")
            return redirect("/register")
        if pw1 != pw2:
            flash("Passwords don't match", "warning")
            return redirect("/register")
        hashed_pw = generate_password_hash(pw1)
        try:
            with get_cursor() as cursor:
                cursor.execute(
                    "INSERT INTO users (username, hash, email, user_type, location, name, authorized) VALUES (%s, %s, %s, %s, %s, %s, FALSE)",
                    (uname, hashed_pw, mail, user_type, location, name)
                )
            flash('Your account has been created and is awaiting authorization', 'success')
            return redirect("/login")
        except Exception as e:
            print(str(e))
            flash("An error has occurred. Please try again or wait for some time.", "danger")
            return redirect("/register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username:
            flash("Must provide username", "warning")
            return redirect("/login")
        elif not password:
            flash("Must provide password", "warning")
            return redirect("/login")
        with get_cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
        if not user or not check_password_hash(user[6], password):
            flash("Invalid username and/or password", "warning")
            return redirect("/login")
        if user[4] != 'admin':
            if not user[1]:
                flash("Please wait until account is authorized.", "warning")
                return redirect("/")
            session["user_id"] = user[0]
            session['type'] = user[4]
            user_obj = User(user_id=user[0], username=user[2], user_type=user[4])
            login_user(user_obj)
            return redirect("/")
        else:
            return render_template("login.html")

@app.route("/logout")
def logout():
    logout_user()
    session.clear()
    return redirect("/")

@app.route("/post", methods=["GET", "POST"])
@login_required
def post():
    user_id = session.get("user_id")
    user = get_current_user()
    if not user or session.get("type") not in ["recipient", "admin"]:
        flash("Unauthorized access", "danger")
        return redirect("/")
    if request.method == "POST":
        content = request.form.get("body")
        header = request.form.get("header")
        if not content or not header:
            flash("Missing content", "warning")
            return redirect("/post")
        with get_cursor() as cursor:
            cursor.execute("INSERT INTO posts (user_id, content, header) VALUES (%s, %s, %s)", (user_id, content, header))
        flash('Request posted successfully', 'success')
        return redirect("/")
    return render_template("post.html", user=user)

@app.route("/requests")
@login_required
def requests():
    user_id = session.get("user_id")
    user_type = session.get("type")
    if user_id:
        if user_type == "recipient":
            with get_cursor() as cursor:
                cursor.execute(
                    """SELECT dr.id, dr.post_id, dr.donor_id, dr.recipient_id, dr.request_date, dr.accepted, p.header AS post_header, p.content AS post_content,
                    u_d.name AS donor_name, u_r.name AS recipient_name, u_r.username as r_uname, u_d.username as d_uname
                    FROM donation_requests dr
                    JOIN posts p ON dr.post_id = p.id
                    JOIN users u_d ON dr.donor_id = u_d.id
                    JOIN users u_r ON dr.recipient_id = u_r.id
                    WHERE dr.recipient_id = %s;""",
                    (user_id,)
                )
        elif user_type in ["donor", "donor org"]:
            with get_cursor() as cursor:
                cursor.execute(
                    """SELECT dr.id, dr.post_id, dr.donor_id, dr.recipient_id, dr.request_date, dr.accepted, p.header AS post_header, p.content AS post_content,
                    u_d.name AS donor_name, u_r.name AS recipient_name, u_r.username as r_uname, u_d.username as d_uname
                    FROM donation_requests dr
                    JOIN posts p ON dr.post_id = p.id
                    JOIN users u_d ON dr.donor_id = u_d.id
                    JOIN users u_r ON dr.recipient_id = u_r.id
                    WHERE dr.donor_id = %s;""",
                    (user_id,)
                )
        else:
            with get_cursor() as cursor:
                cursor.execute(
                    """SELECT dr.id, dr.post_id, dr.donor_id, dr.recipient_id, dr.request_date, dr.accepted, p.header AS post_header, p.content AS post_content,
                    u_d.name AS donor_name, u_r.name AS recipient_name, u_r.username as r_uname, u_d.username as d_uname
                    FROM donation_requests dr
                    JOIN posts p ON dr.post_id = p.id
                    JOIN users u_d ON dr.donor_id = u_d.id
                    JOIN users u_r ON dr.recipient_id = u_r.id;"""
                )
        requests = cursor.fetchall()
        return render_template("requests.html", requests=requests)
    else:
        flash("Unauthorized access", "danger")
        return redirect("/")

def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with get_cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
    return user if user else None

if __name__ == "__main__":
    app.run(debug=True)

@app.route("/request/", methods=["GET", "POST"])
@login_required
def request_donation(post_id):
    user_id = session.get("user_id")
    user_type = session.get("type")
    if user_type != "recipient":
        donor_id = user_id
        post = get_cursor().execute("SELECT user_id FROM posts WHERE id =?", (post_id,))
        recipient_id = post[0]["user_id"]
        if recipient_id == user_id:
            flash("Cant donate on own request.", "warning")
            return redirect(url_for("index"))
        existing_request = get_cursor().execute("SELECT * FROM donation_requests WHERE post_id =? AND donor_id =?", (post_id, user_id))
        if existing_request:
            flash("Already Donated", "success")
            return redirect(url_for("index"))
        get_cursor().execute("INSERT INTO donation_requests (post_id, donor_id, recipient_id) VALUES (?,?,?)", (post_id, donor_id, recipient_id))
        flash("Donation request submitted successfully", "success")
        return redirect(url_for("index"))
    else:
        flash("Error: Cannot Donate as Recipient", 'warning')
        return redirect("/")

@app.route("/accept_request/", methods=["POST"])
@login_required
def accept_request(request_id):
    user_id = session.get("user_id")
    user_type = session.get("type")
    if user_type in ['recipient', 'admin']:
        get_cursor().execute("UPDATE donation_requests SET accepted = 1 WHERE id =?", (request_id,))
        post_id = get_cursor().execute("SELECT post_id FROM donation_requests WHERE id =?", (request_id,))[0]["post_id"]
        get_cursor().execute("UPDATE donation_requests SET accepted = 0 WHERE post_id =? AND id!=?", (post_id, request_id))
        flash("Donation request accepted successfully", "success")
        return redirect(url_for("requests"))
    else:
        flash("Unauthorized access", "danger")
        return redirect("/")

@app.route("/remove_request/", methods=["POST"])
@login_required
def remove_request(request_id):
    user_id = session.get("user_id")
    user_type = session.get("type")
    request = get_cursor().execute("SELECT * FROM donation_requests WHERE id =?", (request_id,))
    if not request:
        flash("Request not found", "warning")
        return redirect(url_for("requests"))
    request = request[0]
    if user_type == "admin" or request["recipient_id"] == user_id or request["donor_id"] == user_id:
        get_cursor().execute("DELETE FROM donation_requests WHERE id =?", (request_id,))
        flash("Request removed successfully", "success")
    else:
        flash("Unauthorized Access", "danger")
    return redirect(url_for("requests"))

@app.route('/filter_requests')
def filter_requests():
    query = request.args.get('query', '')
    status = request.args.get('status', '')
    sql_query = """ SELECT dr.id, dr.post_id, dr.donor_id, dr.recipient_id, dr.request_date, p.header AS post_header, p.content AS post_content, u_d.username AS donor_username, u_r.username AS recipient_username, u_d.name AS donor_name, u_r.name AS recipient_name, dr.accepted FROM donation_requests dr JOIN posts p ON dr.post_id = p.id JOIN users u_d ON dr.donor_id = u_d.id JOIN users u_r ON dr.recipient_id = u_r.id WHERE (u_d.name LIKE? OR u_r.name LIKE?) """
    sql_params = [f'%{query}%', f'%{query}%']
    if status:
        sql_query += " AND dr.accepted =?"
        sql_params.append(status == 'accepted')
    filtered_requests = get_cursor().execute(sql_query, *sql_params)
    result = {}
    for req in filtered_requests:
        if req['post_id'] not in result:
            result[req['post_id']] = {
                'post_header': req['post_header'],
                'post_content': req['post_content'],
                'requests': []
            }
        result[req['post_id']]['requests'].append({
            'id': req['id'],
            'd_uname': req['donor_username'],
            'r_uname': req['recipient_username'],
            'donor_name': req['donor_name'],
            'recipient_name': req['recipient_name'],
            'request_date': req['request_date'],
            'accepted': req['accepted']
        })
    user_type = session.get("type")
    return jsonify({'requests': list(result.values()), 'user_type': user_type})

@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin_dashboard():
    user_id = session.get("user_id")
    type = session.get("type")
    if type != "admin":
        flash("Unauthorized Access", "danger")
        return redirect("/")
    if request.method == "POST":
        user_id_action = request.form.get("user_id")
        if "auth" in request.form:
            get_cursor().execute("UPDATE users SET is_authorized = 1 WHERE id =?", (user_id_action,))
            flash('User authorized successfully', 'success')
        elif "unauth" in request.form:
            get_cursor().execute("DELETE FROM users WHERE id =?", (user_id_action,))
            flash("User removed successfully", 'success')
        return redirect("/admin")
    users_awaiting_auth = get_cursor().execute(""" SELECT id, username, name, email, user_type, location FROM users WHERE is_authorized = 0 """)
    return render_template("admin.html", users=users_awaiting_auth, type=type)

@app.route("/post-history")
@app.route("/history")
@login_required
def history():
    user_id = session.get("user_id")
    user_type = session.get("type")
    if user_id:
        user_posts = get_cursor().execute(""" select p.*, u.name as name from posts p JOIN users u ON p.user_id == u.id where p.user_id =? """, (session.get("user_id"),))
        return render_template("history.html", posts=user_posts)
    else:
        flash("Unauthorized Access", "danger")
        return redirect("/login")

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user = get_current_user()
    if request.method == 'POST':
        username = request.form.get('username')
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        email = request.form.get("email")
        if not username or not old_password or not new_password or not confirm_password or not email:
            flash("Missing inputs", "warning")
            return redirect("/settings")
        if new_password != confirm_password:
            flash("Passwords don't match", "warning")
            return redirect("/settings")
        hashed_old_pw = get_cursor().execute("SELECT hash FROM users WHERE id =?", (user.id,))
        if not check_password_hash(hashed_old_pw[0][0], old_password):
            flash("Invalid old password", "warning")
            return redirect("/settings")
        hashed_new_pw = generate_password_hash(new_password)
        get_cursor().execute("UPDATE users SET hash = %s, email = %s WHERE id = %s", (hashed_new_pw, email, user.id))
        flash("Settings updated successfully", "success")
        return redirect("/settings")
    return render_template("settings.html", user=user)

def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    with get_cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        return user if user else None

if __name__ == "__main__":
    app.run(debug=True)
