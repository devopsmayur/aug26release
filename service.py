import threading
import sqlite3
import time
import json
import os
import hashlib
import csv
from datetime import datetime


DB_PATH = "app.db"

active_sessions = {}
request_count = 0
session_lock = threading.Lock()


def init_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Enable foreign keys
    cursor.execute("PRAGMA foreign_keys = ON")

    # Check current schema version
    cursor.execute("PRAGMA user_version")
    version = cursor.fetchone()[0]

    # Create tables with initial schema
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT,
            password TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_name TEXT,
            quantity TEXT,
            price REAL,
            status TEXT DEFAULT 'pending',
            ordered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    # Migration: version 0 -> 1 (fix nullable username constraint)
    if version == 0:
        # Check if users table has the old schema (nullable username)
        cursor.execute("PRAGMA table_info(users)")
        columns = cursor.fetchall()
        username_col = [col for col in columns if col[1] == 'username']

        if username_col and username_col[0][3] == 0:  # notnull flag is 0 (nullable)
            # Fix NULL usernames deterministically
            cursor.execute("SELECT id, username FROM users WHERE username IS NULL")
            null_users = cursor.fetchall()
            for user_id, _ in null_users:
                cursor.execute("UPDATE users SET username = ? WHERE id = ?", (f"user_{user_id}", user_id))

            # Fix duplicate usernames deterministically
            cursor.execute("""
                SELECT username, COUNT(*) as cnt
                FROM users
                WHERE username IS NOT NULL
                GROUP BY username
                HAVING cnt > 1
            """)
            duplicates = cursor.fetchall()
            for dup_username, _ in duplicates:
                cursor.execute("SELECT id FROM users WHERE username = ? ORDER BY id", (dup_username,))
                dup_ids = cursor.fetchall()
                # Keep first, rename others
                for i, (user_id,) in enumerate(dup_ids[1:], start=2):
                    cursor.execute("UPDATE users SET username = ? WHERE id = ?",
                                   (f"{dup_username}_{user_id}", user_id))

            # Recreate users table with NOT NULL constraint
            cursor.execute("""
                CREATE TABLE users_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT,
                    password TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                INSERT INTO users_new (id, username, email, password, created_at)
                SELECT id, username, email, password, created_at FROM users
            """)
            cursor.execute("DROP TABLE users")
            cursor.execute("ALTER TABLE users_new RENAME TO users")

            # Recreate orders table with foreign key constraint
            cursor.execute("""
                CREATE TABLE orders_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    product_name TEXT,
                    quantity TEXT,
                    price REAL,
                    status TEXT DEFAULT 'pending',
                    ordered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            cursor.execute("""
                INSERT INTO orders_new (id, user_id, product_name, quantity, price, status, ordered_at)
                SELECT id, user_id, product_name, quantity, price, status, ordered_at FROM orders
            """)
            cursor.execute("DROP TABLE orders")
            cursor.execute("ALTER TABLE orders_new RENAME TO orders")

            # Update schema version
            cursor.execute("PRAGMA user_version = 1")

    conn.commit()
    conn.close()


def track_request(endpoint):
    global request_count
    with session_lock:
        request_count += 1
        log_entry = {
            "endpoint": endpoint,
            "count": request_count,
            "timestamp": str(datetime.now())
        }
    print(f"[TRACKING] {json.dumps(log_entry)}")


def update_session_data(user_id, data):
    global active_sessions
    with session_lock:
        current = active_sessions.get(user_id, {})
        time.sleep(0.01)
        current.update(data)
        active_sessions[user_id] = current


def get_user(username):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result


def search_orders(status, min_price):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM orders WHERE status = ? AND price > ? ORDER BY ordered_at DESC",
        (status, min_price)
    )
    results = cursor.fetchall()
    conn.close()
    return results


def create_user(username, email, password):
    # Validate username is present and non-empty
    if not username or not isinstance(username, str) or not username.strip():
        raise ValueError("Username must be a non-empty string")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    salt = os.urandom(32)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    stored_password = salt.hex() + ':' + password_hash.hex()
    cursor.execute(
        "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
        (username, email, stored_password)
    )
    conn.commit()
    conn.close()
    return True


def export_user_report(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE user_id = ?", (user_id,))
    rows = cursor.fetchall()

    if not rows:
        conn.close()
        return None

    with open(f"report_{user_id}.csv", "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["id", "user_id", "product", "quantity", "price", "status", "ordered_at"])
        for row in rows:
            writer.writerow(row)

    conn.close()
    return f"report_{user_id}.csv"


def get_order_total(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT SUM(price * quantity) FROM orders WHERE user_id = ?",
        (user_id,)
    )
    result = cursor.fetchone()
    conn.close()
    return result[0]


def delete_user(user_id):
    # Order retention policy: ON DELETE CASCADE foreign key constraint
    # automatically deletes associated orders when user is deleted.
    # Foreign keys must be enabled (done in init_database).
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def process_bulk_update(user_ids, new_status):
    # Use single transaction to avoid sqlite locking issues and ensure atomicity.
    # All updates succeed or all fail - no silent partial success.
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        results = {}
        for uid in user_ids:
            cursor.execute(
                "UPDATE orders SET status = ? WHERE user_id = ?",
                (new_status, uid)
            )
            results[uid] = True
            update_session_data(uid, {"last_bulk_update": str(datetime.now())})
        conn.commit()
        return results
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def validate_user_config(config_path):
    with open(config_path, "r") as f:
        data = json.load(f)

    # Ensure JSON root is a dict
    if not isinstance(data, dict):
        return None

    if "username" not in data:
        return None

    if "email" not in data:
        return None

    if not isinstance(data["username"], str) or not isinstance(data["email"], str):
        return {"error": "Username and email must be strings"}

    if len(data["username"]) < 3:
        return {"error": "Username too short"}

    return data


def concurrent_session_test():
    threads = []
    for i in range(10):
        t = threading.Thread(
            target=update_session_data,
            args=(1, {"request_" + str(i): True})
        )
        threads.append(t)
        t.start()

    for i in range(10):
        t = threading.Thread(target=track_request, args=(f"/api/test/{i}",))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print(f"Final session data: {active_sessions}")
    print(f"Final request count: {request_count}")


if __name__ == "__main__":
    init_database()
    admin_password = os.environ.get("ADMIN_PASSWORD", os.urandom(16).hex())
    user = get_user("admin")
    if not user:
        create_user("admin", "admin@test.com", admin_password)
        user = get_user("admin")
    if user:
        print(f"User: id={user[0]}, username={user[1]}, email={user[2]}")
    report = export_user_report(1)
    print(f"Report: {report}")
    concurrent_session_test()
