import os
import sqlite3
import secrets
import string
from flask import Flask, request, jsonify

app = Flask(__name__)

# ============================================================
# CẤU HÌNH
# ============================================================

DATABASE = "bankdev.db"

# STK đầu tiên
START_ACCOUNT = 3212215014760


# ============================================================
# DATABASE
# ============================================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account TEXT UNIQUE NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            balance INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


# ============================================================
# TẠO API KEY
# ============================================================

def generate_api_key():
    characters = string.ascii_letters + string.digits

    random_part = ''.join(
        secrets.choice(characters)
        for _ in range(32)
    )

    return "bdk_" + random_part


# ============================================================
# TẠO SỐ TÀI KHOẢN TIẾP THEO
# ============================================================

def generate_next_account():
    conn = get_db()

    row = conn.execute("""
        SELECT account
        FROM accounts
        ORDER BY id DESC
        LIMIT 1
    """).fetchone()

    if row is None:
        account_number = START_ACCOUNT
    else:
        account_number = int(row["account"]) + 1

    conn.close()

    # Kiểm tra đúng 13 số
    if len(str(account_number)) != 13:
        raise ValueError("Số tài khoản đã vượt quá 13 chữ số")

    return str(account_number)


# ============================================================
# TRANG CHỦ
# ============================================================

@app.get("/")
def home():
    return jsonify({
        "status": "online",
        "service": "Bank Dev",
        "version": "1.0",
        "message": "Bank Dev API is running"
    })


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():
    return jsonify({
        "status": "ok"
    })


# ============================================================
# ĐĂNG KÝ TÀI KHOẢN
# ============================================================

@app.post("/api/register")
def register():

    try:
        account = generate_next_account()
        api_key = generate_api_key()

        conn = get_db()

        conn.execute("""
            INSERT INTO accounts
            (account, api_key, balance)
            VALUES (?, ?, ?)
        """, (
            account,
            api_key,
            0
        ))

        conn.commit()
        conn.close()

        print("=" * 60)
        print("TÀI KHOẢN MỚI ĐƯỢC CẤP")
        print("Số tài khoản:", account)
        print("API Key:", api_key)
        print("Số dư:", 0)
        print("=" * 60)

        return jsonify({
            "status": "success",
            "message": "Account created successfully",
            "account": account,
            "api_key": api_key,
            "balance": 0
        }), 201

    except Exception as e:

        print("REGISTER ERROR:", str(e))

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ============================================================
# KIỂM TRA TÀI KHOẢN
# ============================================================

@app.get("/api/account/<account>")
def get_account(account):

    conn = get_db()

    row = conn.execute("""
        SELECT account, balance, created_at
        FROM accounts
        WHERE account = ?
    """, (account,)).fetchone()

    conn.close()

    if row is None:
        return jsonify({
            "status": "error",
            "message": "Account not found"
        }), 404

    return jsonify({
        "status": "success",
        "account": row["account"],
        "balance": row["balance"],
        "created_at": row["created_at"]
    })


# ============================================================
# KIỂM TRA API KEY
# ============================================================

@app.get("/api/verify")
def verify_api_key():

    api_key = request.headers.get("X-API-Key")

    if not api_key:
        return jsonify({
            "status": "error",
            "message": "Missing X-API-Key"
        }), 401

    conn = get_db()

    row = conn.execute("""
        SELECT account, balance
        FROM accounts
        WHERE api_key = ?
    """, (api_key,)).fetchone()

    conn.close()

    if row is None:
        return jsonify({
            "status": "error",
            "message": "Invalid API Key"
        }), 401

    return jsonify({
        "status": "success",
        "message": "API Key is valid",
        "account": row["account"],
        "balance": row["balance"]
    })


# ============================================================
# XEM DANH SÁCH TÀI KHOẢN
# ============================================================

@app.get("/api/accounts")
def list_accounts():

    conn = get_db()

    rows = conn.execute("""
        SELECT
            id,
            account,
            balance,
            created_at
        FROM accounts
        ORDER BY id ASC
    """).fetchall()

    conn.close()

    accounts = []

    for row in rows:
        accounts.append({
            "id": row["id"],
            "account": row["account"],
            "balance": row["balance"],
            "created_at": row["created_at"]
        })

    return jsonify({
        "status": "success",
        "total": len(accounts),
        "accounts": accounts
    })


# ============================================================
# KHỞI TẠO DATABASE
# ============================================================

init_database()


# ============================================================
# CHẠY SERVER
# ============================================================

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 10000))

    print("=" * 60)
    print("BANK DEV SERVER")
    print("Server đang chạy...")
    print("PORT:", port)
    print("Database:", DATABASE)
    print("STK bắt đầu:", START_ACCOUNT)
    print("=" * 60)

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )

