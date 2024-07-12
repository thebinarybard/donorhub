from flask import Flask, flash, redirect, render_template, request, session, url_for, jsonify
from flask_session import Session 
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required

from tables import create
from werkzeug.security import generate_password_hash, check_password_hash
from cs50 import SQL
from datetime import datetime



app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.secret_key = '123xyzabc456'
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///donations.db")

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
    user_data = db.execute("SELECT * FROM users WHERE id = ?", user_id)
    if user_data:
        user = user_data[0]
        return User(user_id=user['id'], username=user['username'], user_type=user['user_type'])
    return None

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
@login_required
def index():
    """Show portfolio of posts"""
    user_id = session.get("user_id")
    notif = session.pop('notif', None)
    type = session.get("type")

    # If user is not logged in, redirect to login page
    if not user_id:
        return redirect("/login")

    try:
        # Fetch user and posts data
        user = db.execute("SELECT * FROM users WHERE id = ?", user_id)[0]
        posts = db.execute(
            "SELECT posts.id, posts.content, posts.header, users.id as user_id, users.username as username, users.name as name, users.location FROM posts JOIN users ON posts.user_id = users.id"
        )
        
        return render_template("index.html", posts=posts, user=user, notification=notif, type=type)
        
    
    except Exception as e:
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

        # Ensure all fields are filled out
        if not uname or not name or not pw1 or not pw2 or not user_type or not location or not mail:
            flash("Missing inputs", "warning")
            return redirect("/register")

        # Ensure passwords match
        if pw1 != pw2:
            flash("Passwords don't match", "warning")
            return redirect("/register")

        # Hash the user's password
        hashed_pw = generate_password_hash(pw1)

        try:
            # Insert the new user into the database
            db.execute("INSERT INTO users (username, hash, email, user_type, location, name, is_authorized) VALUES (?, ?, ?, ?, ?, ?, 0)", uname, hashed_pw, mail, user_type, location, name)
            flash('Your account has been created and is awaiting authorization', 'success')
            return redirect("/login")
        except Exception as e:
            flash("An error has occured. Please try again or wait for some time.", "danger")
            return redirect("/register")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Ensure username and password were submitted
        if not username:
            flash("Must provide username", "warning")
            return redirect("/login")
        elif not password:
            flash("Must provide password", "warning")
            return redirect("/login")

        # Query database for username
        user = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username exists and password is correct
        if not user or not check_password_hash(user[0]["hash"], password):
            flash("Invalid username and/or password", "warning")
            return redirect("/login")

        # Check if user is authorized
        if user[0]['user_type'] != 'admin':
            if not user[0]["is_authorized"]:
                flash("Please wait until account is authorized.", "warning")
                return redirect("/")

        # Remember which user has logged in
        session["user_id"] = user[0]["id"]
        session['type'] = user[0]["user_type"]
        user_obj = User(user_id=user[0]['id'], username=user[0]['username'], user_type=user[0]['user_type'])
        login_user(user_obj)
        return redirect("/")
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""
    
    logout_user()
    session.clear()
    return redirect("/")

@app.route("/post", methods=["GET", "POST"])
@login_required
def post():
    """Post a new request"""
    user_id = session.get("user_id")
    user = db.execute("SELECT * FROM users WHERE id = ?", user_id)

    # Ensure user is authorized to post
    if not user or session.get("type") not in ["recipient", "admin"]:
        flash("Unauthorized access", "danger")
        return redirect("/")

    if request.method == "POST":
        content = request.form.get("body")
        header = request.form.get("header")

        if not content or not header:
            flash("Missing content", "warning")
            return redirect("/post")

        # Insert new post into the database
        db.execute("INSERT INTO posts (user_id, content, header) VALUES (?, ?, ?)", user_id, content, header)
        flash('Request posted successfully', 'success')
        return redirect("/")

    return render_template("post.html", user=user)


#displays request page
@app.route("/requests")
@login_required
def requests():
    """Display donation requests"""
    user_id = session.get("user_id")
    user_type = session.get("type")

    if user_id:
        if user_type == "recipient":
            # Fetch requests for the logged-in user (recipient)
            requests = db.execute("""
                SELECT dr.id, dr.post_id, dr.donor_id, dr.recipient_id, dr.request_date, dr.accepted, p.header AS post_header, p.content AS post_content, 
                       u_d.name AS donor_name, u_r.name AS recipient_name, u_r.username as r_uname, u_d.username as d_uname
                FROM donation_requests dr
                JOIN posts p ON dr.post_id = p.id
                JOIN users u_d ON dr.donor_id = u_d.id
                JOIN users u_r ON dr.recipient_id = u_r.id
                WHERE dr.recipient_id = ?;
            """, user_id)
        elif user_type in ["donor", "donor org"]:
            requests = db.execute("""
                SELECT dr.id, dr.post_id, dr.donor_id, dr.recipient_id, dr.request_date, dr.accepted, p.header AS post_header, p.content AS post_content, 
                       u_d.name AS donor_name, u_r.name AS recipient_name, u_r.username as r_uname, u_d.username as d_uname
                FROM donation_requests dr
                JOIN posts p ON dr.post_id = p.id
                JOIN users u_d ON dr.donor_id = u_d.id
                JOIN users u_r ON dr.recipient_id = u_r.id
                WHERE dr.donor_id = ?;
            """, user_id)
        else:
            requests = db.execute("""
                SELECT dr.id, dr.post_id, dr.donor_id, dr.recipient_id, dr.request_date, dr.accepted, p.header AS post_header, p.content AS post_content, 
                       u_d.name AS donor_name, u_r.name AS recipient_name, u_r.username as r_uname, u_d.username as d_uname
                FROM donation_requests dr
                JOIN posts p ON dr.post_id = p.id
                JOIN users u_d ON dr.donor_id = u_d.id
                JOIN users u_r ON dr.recipient_id = u_r.id
                WHERE dr.recipient_id = ? OR dr.donor_id = ?;
            """, user_id, user_id)

        # Group requests by post_id
        grouped_requests = {}
        for request in requests:
            post_id = request["post_id"]
            if post_id not in grouped_requests:
                grouped_requests[post_id] = {
                    "post_header": request["post_header"],
                    "post_content": request["post_content"],
                    "requests": []
                }
            grouped_requests[post_id]["requests"].append(request)

        return render_template("requests.html", grouped_requests=grouped_requests, user_type=user_type)
    else:
        flash("Unauthorized access", "danger")
        return redirect("/")

#makes request on a post
@app.route("/request/<int:post_id>", methods=["GET", "POST"])
@login_required
def request_donation(post_id):
    """Make a donation request"""
    user_id = session.get("user_id")
    user_type = session.get("type")

    if user_type != "recipient":
        donor_id = user_id
        post = db.execute("SELECT user_id FROM posts WHERE id = ?", post_id)
        recipient_id = post[0]["user_id"]

        if recipient_id == user_id:
            flash("Cant donate on own request.","warning")
            return redirect(url_for("index"))

        # Check if the user has already made the same request
        existing_request = db.execute("SELECT * FROM donation_requests WHERE post_id = ? AND donor_id = ?", post_id, user_id)
        if existing_request:
            flash("Already Donated", "success")
            return redirect(url_for("index"))

        # Insert new donation request into the database
        db.execute("INSERT INTO donation_requests (post_id, donor_id, recipient_id) VALUES (?, ?, ?)", post_id, donor_id, recipient_id)
        flash("Donation request submitted successfully", "success")
        return redirect(url_for("index"))
    else:
        flash("Error: Cannot Donate as Recipient", 'warning')
        return redirect("/")

@app.route("/accept_request/<int:request_id>", methods=["POST"])
@login_required
def accept_request(request_id):
    #Accept a donation request
    user_id = session.get("user_id")
    user_type = session.get("type")

    if user_type in ['recipient', 'admin']:
        # Accept the request
        db.execute("UPDATE donation_requests SET accepted = 1 WHERE id = ?", request_id)

        # Set all other requests for the same post to not accepted
        post_id = db.execute("SELECT post_id FROM donation_requests WHERE id = ?", request_id)[0]["post_id"]
        db.execute("UPDATE donation_requests SET accepted = 0 WHERE post_id = ? AND id != ?", post_id, request_id)

        flash("Donation request accepted successfully", "success")
        return redirect(url_for("requests"))
    else:
        flash("Unauthorized access", "danger")
        return redirect("/")

@app.route("/remove_request/<int:request_id>", methods=["POST"])
@login_required
def remove_request(request_id):
    #Remove a donation request
    user_id = session.get("user_id")
    user_type = session.get("type")

    # Fetch the request details
    request = db.execute("SELECT * FROM donation_requests WHERE id = ?", request_id)
    if not request:
        flash("Request not found", "warning")
        return redirect(url_for("requests"))
    request = request[0]

    # Check if the user is authorized to remove the request
    if user_type == "admin" or request["recipient_id"] == user_id or request["donor_id"] == user_id:
        db.execute("DELETE FROM donation_requests WHERE id = ?", request_id)
        flash("Request removed successfully", "success")
    else:
        flash("Unauthorized Access", "danger")

    return redirect(url_for("requests"))

@app.route('/filter_requests')
def filter_requests():
    query = request.args.get('query', '')
    status = request.args.get('status', '')

    sql_query = """
        SELECT dr.id, dr.post_id, dr.donor_id, dr.recipient_id, dr.request_date, p.header AS post_header, p.content AS post_content, 
               u_d.username AS donor_username, u_r.username AS recipient_username, u_d.name AS donor_name, u_r.name AS recipient_name, dr.accepted
        FROM donation_requests dr
        JOIN posts p ON dr.post_id = p.id
        JOIN users u_d ON dr.donor_id = u_d.id
        JOIN users u_r ON dr.recipient_id = u_r.id
        WHERE (u_d.name LIKE ? OR u_r.name LIKE ?)
    """
    sql_params = [f'%{query}%', f'%{query}%']

    if status:
        sql_query += " AND dr.accepted = ?"
        sql_params.append(status == 'accepted')

    filtered_requests = db.execute(sql_query, *sql_params)

    # Format the results to send back to the client
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

    # Simulating user_type as a placeholder, replace it with actual user type fetching logic
    user_type = session.get("type")

    return jsonify({'requests': list(result.values()), 'user_type': user_type})



@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin_dashboard():
    #Admin dashboard to authorize users
    user_id = session.get("user_id")
    type = session.get("type")

    # Only admins can access this page
    if type != "admin":
        flash("Unauthorized Access", "danger")
        return redirect("/")

    if request.method == "POST":
        user_id_action = request.form.get("user_id")
        if "auth" in request.form:
            # Authorize user
            db.execute("UPDATE users SET is_authorized = 1 WHERE id = ?", user_id_action)
            flash('User authorized successfully', 'success')
        elif "unauth" in request.form:
            # Remove user
            db.execute("DELETE FROM users WHERE id = ?", user_id_action)
            flash("User removed successfully", 'success')
        return redirect("/admin")

    # Fetch users awaiting authorization
    users_awaiting_auth = db.execute("""
        SELECT id, username, name, email, user_type, location
        FROM users
        WHERE is_authorized = 0
    """)
    return render_template("admin.html", users=users_awaiting_auth, type=type)

@app.route("/post-history")
@app.route("/history")
@login_required
def history():
    user_id = session.get("user_id")
    user_type = session.get("type")

    if user_id:
        # Fetch user posts
        user_posts = db.execute("""
            select p.*, u.name as name from posts p
            JOIN users u ON p.user_id == u.id
            where p.user_id = ? 
        """,session.get("user_id"))
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
            flash('Please fill in all the fields.', 'warning')
            return redirect(url_for('settings'))

        if not check_password_hash(user["hash"], old_password):
            flash('Old password is incorrect.', 'warning')
            return redirect(url_for('settings'))    

        if new_password != confirm_password:
            flash('New passwords do not match.', 'warning')  
            return redirect(url_for('settings'))

        # Update the user's username and password
        user['username'] = username
        user["password"] = generate_password_hash(new_password)
        user["email"] = email

        #TODO: update user details
        return redirect("/")

        flash('Settings updated successfully.', 'success')
        return redirect(url_for('index'))

    return render_template('settings.html', user=user)

#User profile
@app.route("/profile/<user_name>", methods=["GET", "POST"])
@app.route("/profile", methods=["GET","POST"], defaults={'user_name': None})
@login_required
def profile(user_name):
  
    if user_name is None:
        user_id = session.get("user_id")
        user = db.execute("SELECT * FROM users WHERE id = ?", user_id)
    else:
        user = db.execute("SELECT * FROM users WHERE username = ?", user_name)

    

    #User Past Successful Donations
    complete_donations = db.execute("""
            SELECT dr.id, dr.post_id, dr.donor_id, dr.recipient_id, dr.request_date, p.header AS post_header, p.content AS post_content, u_d.username AS donor_username, u_r.username AS recipient_username, u_d.name AS d_name, u_r.name AS r_name
            FROM donation_requests dr
            JOIN posts p ON dr.post_id = p.id
            JOIN users u_d ON dr.donor_id = u_d.id
            JOIN users u_r ON dr.recipient_id = u_r.id
            WHERE dr.accepted = 1;
        """)

    if not user:
        flash("User not found", "warning")
        return redirect("/")
    join_date = datetime.strptime(user[0]["join_date"], "%Y-%m-%d %H:%M:%S").strftime("%d-%m-%Y")
    return render_template("profile.html", user=user[0], date=join_date, donations = complete_donations)

    return redirect("/")


@app.route("/users",methods=['get','post'])
@login_required
def user_list():
    if session['type'] != 'admin':
        return redirect("/")
    
    users = db.execute("select * from users where is_authorized = 1;")

    return render_template("users.html",users=users)

def initialize_app():
    # Call create_tables function to ensure tables are created if they do not exist
    create()

@login_required
def get_current_user():
    # Implement your logic to fetch the current user from the database
    user_id = session.get('user_id')
    user = db.execute("SELECT * FROM users WHERE id = ?", user_id)[0]
    return user

if __name__ == '__main__':
    #session.clear()
    initialize_app()
    app.run(debug=True)
   