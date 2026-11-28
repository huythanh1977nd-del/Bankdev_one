import os
import time
import secrets
import hashlib
import threading
import uuid
import requests
import psycopg

from datetime import datetime, timezone
from functools import wraps
from psycopg.rows import dict_row
from flask import Flask, request, jsonify


# ============================================================
# BANKDEV ONE - CONFIGURATION
# ============================================================

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

PROGRAM_NAME = "BANKDEV ONE"
PROGRAM_VERSION = "3.0.0"


# ============================================================
# ACB ONE CONNECT - OAUTH CONFIGURATION
# ============================================================

ACB_CLIENT_ID = os.environ.get("ACB_CLIENT_ID", "").strip()
ACB_CLIENT_SECRET = os.environ.get("ACB_CLIENT_SECRET", "").strip()
ACB_TOKEN_URL = os.environ.get("ACB_TOKEN_URL", "").strip()

ACB_TOKEN_AUTH_METHOD = os.environ.get(
    "ACB_TOKEN_AUTH_METHOD", "body"
).strip().lower()

ACB_ACCESS_TOKEN = None
ACB_TOKEN_EXPIRES_AT = 0

ACB_TOKEN_LOCK = threading.Lock()


# ============================================================
# ACB ONEBIZ PAYMENT ORDER CONFIGURATION
# ============================================================

ACB_PAYMENT_ORDER_URL = os.environ.get(
    "ACB_PAYMENT_ORDER_URL", ""
).strip()

ACB_SOURCE_ACCOUNT = os.environ.get(
    "ACB_SOURCE_ACCOUNT", ""
).strip()

ACB_BANK_CODE = os.environ.get(
    "ACB_BANK_CODE", "970416"
).strip()

ACB_CITAD_CODE = os.environ.get(
    "ACB_CITAD_CODE", "79307001"
).strip()

ACB_NAPAS_CODE = os.environ.get(
    "ACB_NAPAS_CODE", "970416"
).strip()


# ============================================================
# NEON POSTGRESQL DATABASE
# ============================================================

def get_db():

    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not configured"
        )

    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
        connect_timeout=15,
        sslmode="require"
    )


def init_db():

    conn = get_db()

    try:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS accounts (

                id BIGSERIAL PRIMARY KEY,

                account_number TEXT UNIQUE NOT NULL,

                api_key_hash TEXT UNIQUE NOT NULL,

                balance BIGINT NOT NULL DEFAULT 0,

                created_at TEXT NOT NULL

            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS transactions (

                id BIGSERIAL PRIMARY KEY,

                transaction_id TEXT UNIQUE NOT NULL,

                account_number TEXT NOT NULL,

                transaction_type TEXT NOT NULL,

                amount BIGINT NOT NULL,

                balance_after BIGINT NOT NULL,

                description TEXT,

                created_at TEXT NOT NULL

            )
        """)

        conn.commit()

        print("===================================")
        print("BANKDEV ONE")
        print("NEON POSTGRESQL: CONNECTED")
        print("DATABASE: READY")
        print("===================================")

    except Exception:

        conn.rollback()
        raise

    finally:

        conn.close()


# ============================================================
# HELPER FUNCTIONS
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

    conn = get_db()

    try:
        row = conn.execute("""
            SELECT MAX(account_number::BIGINT)
            FROM accounts
            WHERE account_number ~ '^511135[0-9]{2}$'
        """).fetchone()

        if row and row[0]:
            number = str(int(row[0]) + 1)
        else:
            number = "51113526"

        if len(number) != 8:
            raise ValueError("Đã vượt giới hạn số tài khoản 8 chữ số")

        return number

    finally:
        conn.close()


def generate_api_key():

    return "sk_live_" + secrets.token_urlsafe(32)


def hash_api_key(api_key):

    return hashlib.sha256(
        api_key.encode("utf-8")
    ).hexdigest()


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

        try:

            account = conn.execute("""
                SELECT *
                FROM accounts
                WHERE api_key_hash = %s
            """, (
                hash_api_key(api_key),
            )).fetchone()

        finally:

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

        if (
            not force_refresh
            and ACB_ACCESS_TOKEN
            and current_time < ACB_TOKEN_EXPIRES_AT - 60
        ):

            return ACB_ACCESS_TOKEN

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

            ACB_ACCESS_TOKEN = access_token

            ACB_TOKEN_EXPIRES_AT = (
                time.monotonic() + expires_in
            )

            print("ACB OAUTH: SUCCESS")
            print("Token obtained automatically")
            print("Expires in:", expires_in)

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
            )


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
# ACB ONEBIZ - OUTSIDE BANK PAYMENT ORDER
# ============================================================

def create_acb_payment_order(
    destination_account,
    beneficiary_name,
    amount,
    request_id=None,
    remarks="Chuyen tien den ngan hang"
):

    if not ACB_PAYMENT_ORDER_URL:
        raise RuntimeError(
            "Missing ACB_PAYMENT_ORDER_URL"
        )

    if not ACB_SOURCE_ACCOUNT:
        raise RuntimeError(
            "Missing ACB_SOURCE_ACCOUNT"
        )

    amount = int(amount)

    if amount <= 0:
        raise ValueError("Amount must be positive")

    destination_account = str(
        destination_account
    ).strip()

    beneficiary_name = str(
        beneficiary_name
    ).strip()

    if not destination_account or not beneficiary_name:
        raise ValueError(
            "Beneficiary information is required"
        )

    request_id = request_id or str(uuid.uuid4())

    transaction_trace = str(uuid.uuid4())

    request_body = {

        "requestTrace": request_id,

        "requestDateTime": datetime.now(
            timezone.utc
        ).isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z"),

        "requestParameters": {

            "data": {

                "sourceAccountNumber": ACB_SOURCE_ACCOUNT,

                "transaction": {

                    "transactionType": "OUTSIDEBANK",

                    "beneficiary": {

                        "outside": {

                            "accountNumber": destination_account,

                            "beneficiaryName": beneficiary_name,

                            "bank": {
                                "code": ACB_BANK_CODE,
                                "citadCode": ACB_CITAD_CODE,
                                "napasCode": ACB_NAPAS_CODE
                            }
                        }
                    },

                    "amount": {
                        "sourceCurrency": "VND",
                        "targetCurrency": "VND",
                        "amount": str(amount),
                        "exchangeRate": "1",
                        "exchangeAmount": str(amount)
                    },

                    "remarks": remarks,

                    "transactionTraceNumber": transaction_trace
                },

                "attributes": [
                    {
                        "name": "userName",
                        "value": beneficiary_name
                    }
                ]
            }
        }
    }

    headers = acb_headers({
        "X-Request-ID": request_id
    })

    try:

        response = requests.post(
            ACB_PAYMENT_ORDER_URL,
            json=request_body,
            headers=headers,
            timeout=45
        )

        try:
            result = response.json()
        except ValueError:
            result = {
                "raw_response": response.text[:2000]
            }

        print("ACB PAYMENT ORDER")
        print("HTTP:", response.status_code)
        print("Request ID:", request_id)

        return {

            "status": (
                "submitted"
                if response.ok
                else "http_error"
            ),

            "http_status": response.status_code,

            "request_id": request_id,

            "transaction_trace_number": transaction_trace,

            "response": result
        }

    except requests.exceptions.Timeout:

        return {
            "status": "unknown",
            "request_id": request_id,
            "message": "ACB request timed out. Reconcile before retrying."
        }

    except requests.exceptions.RequestException as error:

        return {
            "status": "unknown",
            "request_id": request_id,
            "message": type(error).__name__
        }


# ============================================================
# API ROUTE: BANKDEV ONE -> ACB ONEBIZ
# ============================================================

@app.post("/api/acb/payment-order")
@require_api_key
def acb_payment_order(account):

    data = request.get_json(silent=True)

    if not isinstance(data, dict):

        return jsonify({
            "status": "error",
            "message": "Invalid JSON"
        }), 400

    try:

        transaction = data["requestParameters"]["data"]["transaction"]

        beneficiary = transaction["beneficiary"]["outside"]

        amount = int(transaction["amount"]["amount"])

        request_id = data.get("requestTrace")

        destination_account = beneficiary["accountNumber"]

        beneficiary_name = beneficiary["beneficiaryName"]

        remarks = transaction.get(
            "remarks",
            "Chuyen tien den ngan hang"
        )

        if not request_id:

            return jsonify({
                "status": "error",
                "message": "Missing requestTrace"
            }), 400

        if amount <= 0:

            return jsonify({
                "status": "error",
                "message": "Invalid amount"
            }), 400

        result = create_acb_payment_order(
            destination_account=destination_account,
            beneficiary_name=beneficiary_name,
            amount=amount,
            request_id=request_id,
            remarks=remarks
        )

        if result.get("status") == "unknown":

            return jsonify({
                "status": "unknown",
                "message": result.get("message"),
                "request_id": request_id,
                "payment_status": "reconcile_required"
            }), 504

        return jsonify({

            "status": (
                "success"
                if result.get("status") == "submitted"
                else "error"
            ),

            "message": "ACB response received",

            "acb_http_status": result.get("http_status"),

            "acb_response": result.get("response"),

            "request_id": request_id,

            "payment_status": result.get("status")

        }), 200

    except (KeyError, TypeError, ValueError):

        return jsonify({
            "status": "error",
            "message": "Invalid payment request"
        }), 400

    except RuntimeError as error:

        return jsonify({
            "status": "error",
            "message": str(error)
        }), 503


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

        "database": "Neon PostgreSQL",

        "services": {

            "register": "/api/register",

            "deposit": "/api/deposit",

            "withdraw": "/api/withdraw",

            "transfer": "/api/transfer",

            "balance": "/api/balance",

            "transactions": "/api/transactions",

            "acb_token_check": "/ACB/token/check",

            "acb_payment_order": "/api/acb/payment-order",

            "health": "/health"
        }
    })


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    database_status = "disconnected"

    try:

        conn = get_db()

        conn.execute("SELECT 1")

        conn.close()

        database_status = "connected"

    except Exception:

        database_status = "disconnected"

    return jsonify({

        "status": "online",

        "service": PROGRAM_NAME,

        "version": PROGRAM_VERSION,

        "database": database_status,

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

    api_key = generate_api_key()
    created_at = now_utc()

    conn = get_db()

    try:

        # Lock bảng để tránh hai yêu cầu cấp cùng số
        conn.execute("""
            LOCK TABLE accounts IN EXCLUSIVE MODE
        """)

        row = conn.execute("""
            SELECT MAX(account_number)
            FROM accounts
            WHERE account_number ~ '^511135[0-9]{2}$'
        """).fetchone()

        if row and row[0]:
            account_number = str(int(row[0]) + 1)
        else:
            account_number = "51113526"

        # Kiểm tra giới hạn 8 chữ số
        if len(account_number) != 8:
            raise ValueError("Account number limit reached")

        conn.execute("""
            INSERT INTO accounts
            (
                account_number,
                api_key_hash,
                balance,
                created_at
            )
            VALUES (%s, %s, 0, %s)
        """, (
            account_number,
            hash_api_key(api_key),
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

        row = conn.execute("""
            UPDATE accounts
            SET balance = balance + %s
            WHERE account_number = %s
            RETURNING balance
        """, (
            amount,
            account["account_number"]
        )).fetchone()

        if row is None:

            conn.rollback()

            return jsonify({
                "status": "error",
                "message": "Account not found"
            }), 404

        new_balance = row["balance"]

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
            VALUES (%s, %s, 'DEPOSIT', %s, %s, %s, %s)
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

        row = conn.execute("""
            UPDATE accounts
            SET balance = balance - %s
            WHERE account_number = %s
            AND balance >= %s
            RETURNING balance
        """, (
            amount,
            account["account_number"],
            amount
        )).fetchone()

        if row is None:

            exists = conn.execute("""
                SELECT 1
                FROM accounts
                WHERE account_number = %s
            """, (
                account["account_number"],
            )).fetchone()

            conn.rollback()

            if not exists:

                return jsonify({
                    "status": "error",
                    "message": "Account not found"
                }), 404

            return jsonify({

                "status": "error",

                "message": "Insufficient balance"

            }), 400

        new_balance = row["balance"]

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
            VALUES (%s, %s, 'WITHDRAW', %s, %s, %s, %s)
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

    receiver_transaction_id = generate_transaction_id("TR")

    created_at = now_utc()

    conn = get_db()

    try:

        # Lock both accounts in a consistent order.
        locked_accounts = conn.execute("""
            SELECT account_number, balance
            FROM accounts
            WHERE account_number IN (%s, %s)
            ORDER BY account_number
            FOR UPDATE
        """, (
            from_account,
            to_account
        )).fetchall()

        account_map = {
            row["account_number"]: row
            for row in locked_accounts
        }

        sender = account_map.get(from_account)

        receiver = account_map.get(to_account)

        if sender is None:

            conn.rollback()

            return jsonify({
                "status": "error",
                "message": "Sender account not found"
            }), 404

        if receiver is None:

            conn.rollback()

            return jsonify({
                "status": "error",
                "message": "Receiver account not found",
                "to_account": to_account
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

        conn.execute("""
            UPDATE accounts
            SET balance = %s
            WHERE account_number = %s
        """, (
            sender_new_balance,
            from_account
        ))

        conn.execute("""
            UPDATE accounts
            SET balance = %s
            WHERE account_number = %s
        """, (
            receiver_new_balance,
            to_account
        ))

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
            VALUES (%s, %s, 'TRANSFER_OUT', %s, %s, %s, %s)
        """, (
            transaction_id,
            from_account,
            amount,
            sender_new_balance,
            f"{description} - Đến {to_account}",
            created_at
        ))

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
            VALUES (%s, %s, 'TRANSFER_IN', %s, %s, %s, %s)
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

        row = conn.execute("""
            SELECT balance
            FROM accounts
            WHERE account_number = %s
        """, (
            account["account_number"],
        )).fetchone()

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
            WHERE account_number = %s
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
                int(
                    ACB_TOKEN_EXPIRES_AT - time.monotonic()
                )
            )

        }), 200

    except Exception:

        return jsonify({

            "status": "error",

            "message": "Unable to obtain ACB access token"

        }), 502


# ============================================================
# ACB TOKEN FORCE REFRESH
# ============================================================

@app.post("/ACB/token/refresh")
@require_api_key
def acb_token_refresh(account):

    try:

        token = get_acb_access_token(
            force_refresh=True
        )

        return jsonify({

            "status": "success",

            "message": "ACB token refreshed successfully",

            "token_obtained": bool(token),

            "account_number": account["account_number"],

            "token_type": "Bearer",

            "expires_in_seconds": max(
                0,
                int(
                    ACB_TOKEN_EXPIRES_AT - time.monotonic()
                )
            )

        }), 200

    except Exception:

        return jsonify({

            "status": "error",

            "message": "Unable to refresh ACB token"

        }), 502


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
# DATABASE INITIALIZATION
# ============================================================

init_db()


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    from waitress import serve

    serve(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8080))
    )
