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
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
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
            ordered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
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
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return True


def process_bulk_update(user_ids, new_status):
    threads = []
    results = {}

    def update_single(uid):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE orders SET status = ? WHERE user_id = ?",
            (new_status, uid)
        )
        conn.commit()
        results[uid] = True
        conn.close()
        update_session_data(uid, {"last_bulk_update": str(datetime.now())})

    for uid in user_ids:
        t = threading.Thread(target=update_single, args=(uid,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return results


def validate_user_config(config_path):
    with open(config_path, "r") as f:
        data = json.load(f)

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
