import os
import time
import secrets
import sqlite3
import threading
import requests

from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify


# ============================================================
# BANKDEV ONE - CONFIGURATION
# ============================================================

app = Flask(__name__)

DATABASE = os.environ.get("DATABASE_PATH", "bank.db")

PROGRAM_NAME = "BANKDEV ONE"
PROGRAM_VERSION = "2.0.0"


# ============================================================
# ACB ONE CONNECT - OAUTH CONFIGURATION
# ============================================================

ACB_CLIENT_ID = os.environ.get("ACB_CLIENT_ID", "").strip()
ACB_CLIENT_SECRET = os.environ.get("ACB_CLIENT_SECRET", "").strip()
ACB_TOKEN_URL = os.environ.get("ACB_TOKEN_URL", "").strip()

# body = client_id/client_secret trong form body
# basic = HTTP Basic Authentication
ACB_TOKEN_AUTH_METHOD = os.environ.get(
    "ACB_TOKEN_AUTH_METHOD", "body"
).strip().lower()

ACB_ACCESS_TOKEN = None
ACB_TOKEN_EXPIRES_AT = 0

ACB_TOKEN_LOCK = threading.Lock()


# ============================================================
# DATABASE
# ============================================================

def get_db():

    conn = sqlite3.connect(
        DATABASE,
        timeout=30
    )

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
            """
            SELECT 1
            FROM accounts
            WHERE account_number = ?
            """,
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
            """
            SELECT *
            FROM accounts
            WHERE api_key = ?
            """,
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
# ACB AUTOMATIC OAUTH TOKEN
# ============================================================

def get_acb_access_token(force_refresh=False):

    global ACB_ACCESS_TOKEN
    global ACB_TOKEN_EXPIRES_AT

    with ACB_TOKEN_LOCK:

        current_time = time.monotonic()

        # Reuse existing token
        if (
            not force_refresh
            and ACB_ACCESS_TOKEN
            and current_time < ACB_TOKEN_EXPIRES_AT - 60
        ):

            return ACB_ACCESS_TOKEN

        # Check configuration
        if not ACB_CLIENT_ID:

            raise RuntimeError("Missing ACB_CLIENT_ID")

        if not ACB_CLIENT_SECRET:

            raise RuntimeError("Missing ACB_CLIENT_SECRET")

        if not ACB_TOKEN_URL:

            raise RuntimeError("Missing ACB_TOKEN_URL")

        if ACB_TOKEN_AUTH_METHOD not in ("body", "basic"):

            raise RuntimeError(
                "ACB_TOKEN_AUTH_METHOD must be body or basic"
            )

        # OAuth form
        payload = {
            "grant_type": "client_credentials"
        }

        if ACB_TOKEN_AUTH_METHOD == "body":

            payload["client_id"] = ACB_CLIENT_ID
            payload["client_secret"] = ACB_CLIENT_SECRET

            auth = None

        else:

            auth = (
                ACB_CLIENT_ID,
                ACB_CLIENT_SECRET
            )

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        }

        try:

            response = requests.post(
                ACB_TOKEN_URL,
                data=payload,
                headers=headers,
                auth=auth,
                timeout=30
            )

            if not response.ok:

                print(
                    "ACB OAuth HTTP error:",
                    response.status_code
                )

                # Do not expose credentials or token
                raise RuntimeError(
                    f"ACB OAuth returned HTTP {response.status_code}"
                )

            result = response.json()

            access_token = result.get("access_token")

            if not access_token:

                raise RuntimeError(
                    "ACB response does not contain access_token"
                )

            expires_in = result.get("expires_in", 300)

            try:

                expires_in = max(1, int(expires_in))

            except (TypeError, ValueError):

                expires_in = 300

            # Save token in memory
            ACB_ACCESS_TOKEN = access_token

            ACB_TOKEN_EXPIRES_AT = (
                time.monotonic() + expires_in
            )

            print("===================================")
            print("BANKDEV ONE - ACB OAUTH")
            print("Token status: SUCCESS")
            print("Token obtained automatically")
            print("Expires in:", expires_in, "seconds")
            print("===================================")

            return ACB_ACCESS_TOKEN

        except requests.exceptions.RequestException as error:

            ACB_ACCESS_TOKEN = None
            ACB_TOKEN_EXPIRES_AT = 0

            raise RuntimeError(
                f"ACB connection failed: {type(error).__name__}"
            ) from None

        except ValueError:

            ACB_ACCESS_TOKEN = None
            ACB_TOKEN_EXPIRES_AT = 0

            raise RuntimeError(
                "ACB returned invalid JSON"
            ) from None


# ============================================================
# ACB AUTHORIZATION HEADERS
# ============================================================

def acb_headers(extra_headers=None):

    token = get_acb_access_token()

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer " + token
    }

    if extra_headers:

        headers.update(extra_headers)

    return headers


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():

    return jsonify({

        "name": PROGRAM_NAME,

        "version": PROGRAM_VERSION,

        "status": "online",

        "message": "BankDev One API is running",

        "services": {

            "register": "/api/register",

            "deposit": "/api/deposit",

            "withdraw": "/api/withdraw",

            "transfer": "/api/transfer",

            "balance": "/api/balance",

            "transactions": "/api/transactions",

            "acb_token_check": "/ACB/token/check",

            "health": "/health"

        }

    })


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return jsonify({

        "status": "online",

        "service": PROGRAM_NAME,

        "version": PROGRAM_VERSION,

        "database": "configured",

        "acb_oauth_configured": bool(
            ACB_CLIENT_ID
            and ACB_CLIENT_SECRET
            and ACB_TOKEN_URL
        )

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

    try:

        conn.execute("""
            INSERT INTO accounts
            (
                account_number,
                api_key,
                balance,
                created_at
            )
            VALUES (?, ?, 0, ?)
        """, (
            account_number,
            api_key,
            created_at
        ))

        conn.commit()

    finally:

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
# DEPOSIT
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

    try:

        amount = int(data.get("amount"))

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

    description = str(
        data.get("description", "Nạp tiền")
    )

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

        new_balance = row["balance"] + amount

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
            description,
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
# WITHDRAW
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

    try:

        amount = int(data.get("amount"))

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

    description = str(
        data.get("description", "Rút tiền")
    )

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
            description,
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
# TRANSFER - INTERNAL BANKDEV TRANSFER
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

    if not to_account:

        return jsonify({
            "status": "error",
            "message": "to_account is required"
        }), 400

    to_account = str(to_account).strip()

    try:

        amount = int(data.get("amount"))

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

    if from_account == to_account:

        return jsonify({
            "status": "error",
            "message": "Cannot transfer to the same account"
        }), 400

    description = str(
        data.get("description", "Chuyển tiền")
    )

    transaction_id = generate_transaction_id("TR")

    created_at = now_utc()

    conn = get_db()

    try:

        conn.execute("BEGIN IMMEDIATE")

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

        if amount > sender_balance:

            conn.rollback()

            return jsonify({

                "status": "error",

                "message": "Insufficient balance",

                "balance": sender_balance,

                "requested_amount": amount

            }), 400

        sender_new_balance = sender_balance - amount

        receiver_new_balance = receiver["balance"] + amount

        # Update sender
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

        # Update receiver
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

        # Sender transaction
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
            f"{description} - Đến {to_account}",
            created_at
        ))

        # Receiver transaction
        receiver_transaction_id = generate_transaction_id("TR")

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
            receiver_transaction_id,
            to_account,
            amount,
            receiver_new_balance,
            f"{description} - Từ {from_account}",
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
# BALANCE
# ============================================================

@app.get("/api/balance")
@require_api_key
def balance(account):

    conn = get_db()

    try:

        row = conn.execute(
            """
            SELECT balance
            FROM accounts
            WHERE account_number = ?
            """,
            (account["account_number"],)
        ).fetchone()

    finally:

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
# TRANSACTIONS
# ============================================================

@app.get("/api/transactions")
@require_api_key
def transactions(account):

    conn = get_db()

    try:

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

    finally:

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
# ACB TOKEN CHECK
# ============================================================

@app.get("/ACB/token/check")
@require_api_key
def acb_token_check(account):

    try:
        token = get_acb_access_token()

        return jsonify({
            "status": "success",
            "message": "ACB access token obtained successfully",
            "token_obtained": bool(token),
            "account_number": account["account_number"],
            "token_type": "Bearer",
            "expires_in_seconds": max(
                0,
                int(ACB_TOKEN_EXPIRES_AT - time.monotonic())
            )
        }), 200

    except Exception as error:
        return jsonify({
            "status": "error",
            "message": "Unable to obtain ACB access token",
            "detail": str(error)
        }), 502


# ============================================================
# ACB TOKEN FORCE REFRESH
# ============================================================

@app.post("/ACB/token/refresh")
@require_api_key
def acb_token_refresh(account):

    try:
        token = get_acb_access_token(force_refresh=True)

        return jsonify({
            "status": "success",
            "message": "ACB token refreshed successfully",
            "token_obtained": bool(token),
            "account_number": account["account_number"],
            "token_type": "Bearer",
            "expires_in_seconds": max(
                0,
                int(ACB_TOKEN_EXPIRES_AT - time.monotonic())
            )
        }), 200

    except Exception as error:
        return jsonify({
            "status": "error",
            "message": "Unable to refresh ACB token",
            "detail": str(error)
        }), 502


# ============================================================
# ACB PAYMENT ORDER - BANKDEV ONE
# ============================================================

@app.post("/ACB/payment-order")
@require_api_key
def acb_payment_order(account):

    try:

        # 1. Lấy dữ liệu giao dịch từ BDO 4
        payload = request.get_json(silent=True)

        if not isinstance(payload, dict):
            return jsonify({
                "status": "error",
                "message": "Request body must be valid JSON"
            }), 400

        # 2. Kiểm tra cấu trúc dữ liệu
        request_parameters = payload.get("requestParameters")

        if not isinstance(request_parameters, dict):
            return jsonify({
                "status": "error",
                "message": "Missing requestParameters"
            }), 400

        data = request_parameters.get("data")

        if not isinstance(data, dict):
            return jsonify({
                "status": "error",
                "message": "Missing requestParameters.data"
            }), 400

        # 3. Đọc cấu hình ACB từ Render Environment
        payment_url = os.environ.get(
            "ACB_PAYMENT_URL", ""
        ).strip()

        client_id = os.environ.get(
            "ACB_HEADER_CLIENT_ID", ""
        ).strip()

        provider_id = os.environ.get(
            "ACB_PROVIDER_ID", ""
        ).strip()

        channel = os.environ.get(
            "ACB_CHANNEL", ""
        ).strip()

        authorization_string = os.environ.get(
            "ACB_AUTHORIZATION_STRING", ""
        ).strip()

        authorization_id = os.environ.get(
            "ACB_AUTHORIZATION_ID", ""
        ).strip()

        required = {
            "ACB_PAYMENT_URL": payment_url,
            "ACB_HEADER_CLIENT_ID": client_id,
            "ACB_PROVIDER_ID": provider_id,
            "ACB_CHANNEL": channel,
            "ACB_AUTHORIZATION_STRING": authorization_string,
            "ACB_AUTHORIZATION_ID": authorization_id
        }

        missing = [
            name for name, value in required.items()
            if not value
        ]

        if missing:
            return jsonify({
                "status": "error",
                "message": "Missing ACB configuration",
                "missing_variables": missing
            }), 500

        # 4. Lấy OAuth access token
        token = get_acb_access_token()

        if not token:
            return jsonify({
                "status": "error",
                "message": "Unable to obtain ACB access token"
            }), 502

        # 5. Gắn authorization cố định dùng lại
        # Chỉ thay thế trường authorizations trong dữ liệu gửi lên ACB.
        data["authorizations"] = [
            {
                "authorizationString": authorization_string,
                "authorizationId": authorization_id
            }
        ]

        # 6. Tạo header gửi đến ACB
        headers = {
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Client-ID": client_id,
            "X-Service": "Payment Order",
            "X-Provider-ID": provider_id,
            "X-Channel": channel
        }

        # 7. Gửi lệnh đến ACB Sandbox
        # Không tự động gửi lại nếu bị timeout.
        response = requests.post(
            payment_url,
            headers=headers,
            json=payload,
            timeout=30
        )

        # 8. Đọc kết quả trả về
        try:
            acb_result = response.json()
        except ValueError:
            acb_result = {
                "raw_response": response.text
            }

        # 9. Trả kết quả ACB về BDO 4
        return jsonify({
            "status": (
                "success"
                if 200 <= response.status_code < 300
                else "error"
            ),
            "message": "ACB Payment Order response",
            "bankdev_account": account["account_number"],
            "acb_http_status": response.status_code,
            "acb_response": acb_result
        }), 200

    except requests.Timeout:
        return jsonify({
            "status": "unknown",
            "message": (
                "ACB request timed out. "
                "Check transaction status before retrying."
            )
        }), 504

    except requests.RequestException as error:
        return jsonify({
            "status": "error",
            "message": "Unable to connect to ACB",
            "detail": str(error)
        }), 502

    except Exception as error:
        return jsonify({
            "status": "error",
            "message": "BankDev One ACB Payment Order error",
            "detail": str(error)
        }), 500


# ============================================================
# 404 ERROR
# ============================================================

@app.errorhandler(404)
def not_found(error):

    return jsonify({
        "status": "error",
        "message": "Endpoint not found"
    }), 404


# ============================================================
# 405 ERROR
# ============================================================

@app.errorhandler(405)
def method_not_allowed(error):

    return jsonify({
        "status": "error",
        "message": "HTTP method not allowed"
    }), 405


# ============================================================
# 404 ERROR
# ============================================================

@app.errorhandler(404)
def not_found(error):

    return jsonify({

        "status": "error",

        "message": "Endpoint not found"

    }), 404


# ============================================================
# 405 ERROR
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
            os.environ.get("PORT", 8080)
        )

    )
