from flask import Flask, request, jsonify
import sqlite3
import secrets
from datetime import datetime, timezone
from functools import wraps
import os

app = Flask(__name__)

DATABASE = os.environ.get("DATABASE_PATH", "bank.db")


# ============================================================
# DATABASE
# ============================================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_number TEXT UNIQUE NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            balance INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_id TEXT UNIQUE NOT NULL,
            account_number TEXT NOT NULL,
            transaction_type TEXT NOT NULL,
            amount INTEGER NOT NULL,
            balance_after INTEGER NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# ============================================================
# HELPER
# ============================================================

def now_utc():
    return datetime.now(timezone.utc).isoformat()


def generate_transaction_id(prefix="TX"):
    return (
        prefix
        + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        + secrets.token_hex(4).upper()
    )


def generate_account_number():
    while True:
        number = str(
            secrets.randbelow(900000000000) + 100000000000
        )

        conn = get_db()

        exists = conn.execute(
            "SELECT 1 FROM accounts WHERE account_number = ?",
            (number,)
        ).fetchone()

        conn.close()

        if not exists:
            return number


def generate_api_key():
    return "sk_live_" + secrets.token_urlsafe(32)


# ============================================================
# API KEY AUTHENTICATION
# ============================================================

def require_api_key(func):

    @wraps(func)
    def wrapper(*args, **kwargs):

        api_key = request.headers.get("X-API-Key")

        if not api_key:
            return jsonify({
                "status": "error",
                "message": "Missing X-API-Key header"
            }), 401

        conn = get_db()

        account = conn.execute(
            "SELECT * FROM accounts WHERE api_key = ?",
            (api_key,)
        ).fetchone()

        conn.close()

        if not account:
            return jsonify({
                "status": "error",
                "message": "Invalid API Key"
            }), 401

        return func(account, *args, **kwargs)

    return wrapper


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():

    return jsonify({
        "name": "Bank Dev API",
        "version": "1.1.0",
        "status": "online",
        "message": "Demo API for development/testing only"
    })


# ============================================================
# REGISTER ACCOUNT
# ============================================================

@app.post("/api/register")
def register():

    account_number = generate_account_number()
    api_key = generate_api_key()
    created_at = now_utc()

    conn = get_db()

    conn.execute("""
        INSERT INTO accounts
        (account_number, api_key, balance, created_at)
        VALUES (?, ?, 0, ?)
    """, (
        account_number,
        api_key,
        created_at
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "status": "success",
        "message": "Account created",
        "account_number": account_number,
        "api_key": api_key,
        "balance": 0,
        "created_at": created_at
    }), 201


# ============================================================
# DEPOSIT - NẠP TIỀN
# ============================================================

@app.post("/api/deposit")
@require_api_key
def deposit(account):

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "status": "error",
            "message": "JSON body is required"
        }), 400

    amount = data.get("amount")
    description = data.get(
        "description",
        "Nạp tiền"
    )

    try:
        amount = int(amount)
    except (TypeError, ValueError):

        return jsonify({
            "status": "error",
            "message": "amount must be an integer"
        }), 400

    if amount <= 0:

        return jsonify({
            "status": "error",
            "message": "amount must be greater than 0"
        }), 400

    transaction_id = generate_transaction_id("TX")
    created_at = now_utc()

    conn = get_db()

    try:

        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            """
            SELECT balance
            FROM accounts
            WHERE account_number = ?
            """,
            (account["account_number"],)
        ).fetchone()

        if row is None:

            conn.rollback()

            return jsonify({
                "status": "error",
                "message": "Account not found"
            }), 404

        current_balance = row["balance"]

        new_balance = current_balance + amount

        conn.execute(
            """
            UPDATE accounts
            SET balance = ?
            WHERE account_number = ?
            """,
            (
                new_balance,
                account["account_number"]
            )
        )

        conn.execute("""
            INSERT INTO transactions
            (
                transaction_id,
                account_number,
                transaction_type,
                amount,
                balance_after,
                description,
                created_at
            )
            VALUES (?, ?, 'DEPOSIT', ?, ?, ?, ?)
        """, (
            transaction_id,
            account["account_number"],
            amount,
            new_balance,
            str(description),
            created_at
        ))

        conn.commit()

    except Exception:

        conn.rollback()
        raise

    finally:

        conn.close()

    return jsonify({
        "status": "success",
        "transaction_id": transaction_id,
        "account_number": account["account_number"],
        "transaction_type": "DEPOSIT",
        "amount": amount,
        "balance": new_balance,
        "description": description,
        "created_at": created_at
    })


# ============================================================
# WITHDRAW - RÚT TIỀN
# ============================================================

@app.post("/api/withdraw")
@require_api_key
def withdraw(account):

    data = request.get_json(silent=True)

    if not isinstance(data, dict):

        return jsonify({
            "status": "error",
            "message": "JSON body is required"
        }), 400

    amount = data.get("amount")

    description = data.get(
        "description",
        "Rút tiền"
    )

    try:
        amount = int(amount)

    except (TypeError, ValueError):

        return jsonify({
            "status": "error",
            "message": "amount must be an integer"
        }), 400

    if amount <= 0:

        return jsonify({
            "status": "error",
            "message": "amount must be greater than 0"
        }), 400

    transaction_id = generate_transaction_id("WD")
    created_at = now_utc()

    conn = get_db()

    try:

        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            """
            SELECT balance
            FROM accounts
            WHERE account_number = ?
            """,
            (account["account_number"],)
        ).fetchone()

        if row is None:

            conn.rollback()

            return jsonify({
                "status": "error",
                "message": "Account not found"
            }), 404

        current_balance = row["balance"]

        # Không cho rút vượt quá số dư
        if amount > current_balance:

            conn.rollback()

            return jsonify({
                "status": "error",
                "message": "Insufficient balance",
                "balance": current_balance,
                "requested_amount": amount
            }), 400

        new_balance = current_balance - amount

        conn.execute(
            """
            UPDATE accounts
            SET balance = ?
            WHERE account_number = ?
            """,
            (
                new_balance,
                account["account_number"]
            )
        )

        conn.execute("""
            INSERT INTO transactions
            (
                transaction_id,
                account_number,
                transaction_type,
                amount,
                balance_after,
                description,
                created_at
            )
            VALUES (?, ?, 'WITHDRAW', ?, ?, ?, ?)
        """, (
            transaction_id,
            account["account_number"],
            amount,
            new_balance,
            str(description),
            created_at
        ))

        conn.commit()

    except Exception:

        conn.rollback()
        raise

    finally:

        conn.close()

    return jsonify({
        "status": "success",
        "transaction_id": transaction_id,
        "account_number": account["account_number"],
        "transaction_type": "WITHDRAW",
        "amount": amount,
        "balance": new_balance,
        "description": description,
        "created_at": created_at
    })


# ============================================================
# TRANSFER - CHUYỂN TIỀN
# ============================================================

@app.post("/api/transfer")
@require_api_key
def transfer(account):

    data = request.get_json(silent=True)

    if not isinstance(data, dict):

        return jsonify({
            "status": "error",
            "message": "JSON body is required"
        }), 400

    to_account = data.get("to_account")
    amount = data.get("amount")

    description = data.get(
        "description",
        "Chuyển tiền"
    )

    if not to_account:

        return jsonify({
            "status": "error",
            "message": "to_account is required"
        }), 400

    to_account = str(to_account).strip()

    try:

        amount = int(amount)

    except (TypeError, ValueError):

        return jsonify({
            "status": "error",
            "message": "amount must be an integer"
        }), 400

    if amount <= 0:

        return jsonify({
            "status": "error",
            "message": "amount must be greater than 0"
        }), 400

    from_account = account["account_number"]

    # Không cho chuyển cho chính mình
    if from_account == to_account:

        return jsonify({
            "status": "error",
            "message": "Cannot transfer to the same account"
        }), 400

    transaction_id = generate_transaction_id("TR")
    created_at = now_utc()

    conn = get_db()

    try:

        # Khóa transaction SQLite
        conn.execute("BEGIN IMMEDIATE")

        # ----------------------------------------------------
        # Tìm tài khoản nhận
        # ----------------------------------------------------

        receiver = conn.execute(
            """
            SELECT account_number, balance
            FROM accounts
            WHERE account_number = ?
            """,
            (to_account,)
        ).fetchone()

        if receiver is None:

            conn.rollback()

            return jsonify({
                "status": "error",
                "message": "Receiver account not found",
                "to_account": to_account
            }), 404

        # ----------------------------------------------------
        # Lấy số dư người gửi
        # ----------------------------------------------------

        sender = conn.execute(
            """
            SELECT balance
            FROM accounts
            WHERE account_number = ?
            """,
            (from_account,)
        ).fetchone()

        if sender is None:

            conn.rollback()

            return jsonify({
                "status": "error",
                "message": "Sender account not found"
            }), 404

        sender_balance = sender["balance"]

        # ----------------------------------------------------
        # Kiểm tra số dư
        # ----------------------------------------------------

        if amount > sender_balance:

            conn.rollback()

            return jsonify({
                "status": "error",
                "message": "Insufficient balance",
                "balance": sender_balance,
                "requested_amount": amount
            }), 400

        # ----------------------------------------------------
        # Tính số dư mới
        # ----------------------------------------------------

        sender_new_balance = sender_balance - amount

        receiver_new_balance = (
            receiver["balance"] + amount
        )

        # ----------------------------------------------------
        # Trừ tiền người gửi
        # ----------------------------------------------------

        conn.execute(
            """
            UPDATE accounts
            SET balance = ?
            WHERE account_number = ?
            """,
            (
                sender_new_balance,
                from_account
            )
        )

        # ----------------------------------------------------
        # Cộng tiền người nhận
        # ----------------------------------------------------

        conn.execute(
            """
            UPDATE accounts
            SET balance = ?
            WHERE account_number = ?
            """,
            (
                receiver_new_balance,
                to_account
            )
        )

        # ----------------------------------------------------
        # Lịch sử người gửi
        # ----------------------------------------------------

        sender_description = (
            f"{description} - Đến {to_account}"
        )

        conn.execute("""
            INSERT INTO transactions
            (
                transaction_id,
                account_number,
                transaction_type,
                amount,
                balance_after,
                description,
                created_at
            )
            VALUES (?, ?, 'TRANSFER_OUT', ?, ?, ?, ?)
        """, (
            transaction_id,
            from_account,
            amount,
            sender_new_balance,
            sender_description,
            created_at
        ))

        # ----------------------------------------------------
        # Lịch sử người nhận
        # ----------------------------------------------------

        receiver_description = (
            f"{description} - Từ {from_account}"
        )

        conn.execute("""
            INSERT INTO transactions
            (
                transaction_id,
                account_number,
                transaction_type,
                amount,
                balance_after,
                description,
                created_at
            )
            VALUES (?, ?, 'TRANSFER_IN', ?, ?, ?, ?)
        """, (
            transaction_id,
            to_account,
            amount,
            receiver_new_balance,
            receiver_description,
            created_at
        ))

        conn.commit()

    except Exception:

        conn.rollback()
        raise

    finally:

        conn.close()

    return jsonify({
        "status": "success",
        "transaction_id": transaction_id,
        "transaction_type": "TRANSFER",
        "from_account": from_account,
        "to_account": to_account,
        "amount": amount,
        "sender_balance": sender_new_balance,
        "receiver_balance": receiver_new_balance,
        "description": description,
        "created_at": created_at
    })


# ============================================================
# BALANCE - SỐ DƯ
# ============================================================

@app.get("/api/balance")
@require_api_key
def balance(account):

    conn = get_db()

    row = conn.execute(
        """
        SELECT balance
        FROM accounts
        WHERE account_number = ?
        """,
        (account["account_number"],)
    ).fetchone()

    conn.close()

    if row is None:

        return jsonify({
            "status": "error",
            "message": "Account not found"
        }), 404

    return jsonify({
        "status": "success",
        "account_number": account["account_number"],
        "balance": row["balance"]
    })


# ============================================================
# TRANSACTIONS - LỊCH SỬ GIAO DỊCH
# ============================================================

@app.get("/api/transactions")
@require_api_key
def transactions(account):

    conn = get_db()

    rows = conn.execute("""
        SELECT
            transaction_id,
            transaction_type,
            amount,
            balance_after,
            description,
            created_at
        FROM transactions
        WHERE account_number = ?
        ORDER BY id DESC
    """, (
        account["account_number"],
    )).fetchall()

    conn.close()

    return jsonify({
        "status": "success",
        "account_number": account["account_number"],
        "transactions": [
            dict(row)
            for row in rows
        ]
    })


# ============================================================
# 404
# ============================================================

@app.errorhandler(404)
def not_found(error):

    return jsonify({
        "status": "error",
        "message": "Endpoint not found"
    }), 404


# ============================================================
# 405
# ============================================================

@app.errorhandler(405)
def method_not_allowed(error):

    return jsonify({
        "status": "error",
        "message": "HTTP method not allowed"
    }), 405


# ============================================================
# DATABASE INIT
# ============================================================

init_db()


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                8080
            )
        )
    )
