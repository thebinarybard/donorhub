import sqlite3

def create():
    # Connect to SQLite database (creates it if it doesn't exist)
    conn = sqlite3.connect('donations.db')
    cursor = conn.cursor()

    # SQL statements to create tables (unchanged)
    create_users_table = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            hash TEXT NOT NULL,
            email TEXT NOT NULL,
            user_type TEXT,
            location TEXT,
            is_authorized BOOLEAN DEFAULT 0,
            join_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            name TEXT
        );
    """

   

    create_posts_table = """
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            content TEXT,
            header TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """

    create_trigger_set_timestamp = """
        CREATE TRIGGER IF NOT EXISTS set_timestamp
        AFTER INSERT ON users
        FOR EACH ROW
        BEGIN
            UPDATE users SET join_date = CURRENT_TIMESTAMP WHERE id = NEW.id;
        END;
    """

    create_donation_requests_table = """
        CREATE TABLE IF NOT EXISTS donation_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            donor_id INTEGER NOT NULL,
            recipient_id INTEGER NOT NULL,
            request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            accepted BOOLEAN DEFAULT FALSE,
            FOREIGN KEY(post_id) REFERENCES posts(id),
            FOREIGN KEY(donor_id) REFERENCES users(id),
            FOREIGN KEY(recipient_id) REFERENCES users(id)
        );
    """
    
    insert_admin_user = """ UPDATE users set user_type='admin' WHERE name="ADMIN"; """  #manually make a person admin

    # Execute each table creation statement
    cursor.execute(create_users_table)
    cursor.execute(create_posts_table)
    cursor.execute(insert_admin_user)
    cursor.execute(create_trigger_set_timestamp)
    cursor.execute(create_donation_requests_table)

    # Commit changes and close connection
    conn.commit()
    conn.close()

if __name__ == "__main__":
    create()
