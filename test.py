"""Security-focused payment processing examples used by review tests.

Importing this module is side-effect free. Runtime secrets and database
connections are acquired only when the corresponding service is instantiated.
"""

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import jwt  # PyJWT
import requests
import yaml
from lxml import etree


logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = (3.05, 15)


def _required_secret(name):
    """Read a required secret at point of use, not during module import."""
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Required environment variable {name} is not set")
    return value


def _mask_pan(card_number):
    """Retain at most the PAN's BIN and last four digits."""
    digits = "".join(character for character in str(card_number) if character.isdigit())
    if len(digits) < 10:
        return "****"
    return f"{digits[:6]}{'*' * (len(digits) - 10)}{digits[-4:]}"


def _base64url_encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value):
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _validated_public_https_url(url):
    """Validate that a URL resolves exclusively to public HTTPS endpoints."""
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("Only HTTPS URLs with a hostname are allowed")
    if parsed.username or parsed.password:
        raise ValueError("URL credentials are not allowed")

    try:
        addresses = socket.getaddrinfo(
            parsed.hostname,
            parsed.port or 443,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError("URL hostname could not be resolved") from exc

    if not addresses:
        raise ValueError("URL hostname could not be resolved")
    for address in addresses:
        resolved_ip = ipaddress.ip_address(address[4][0])
        if not resolved_ip.is_global:
            raise ValueError("URL hostname resolves to a non-public address")
    return url


class PaymentProcessor:
    """Handle card transactions without retaining cardholder data."""

    def __init__(self, db_path="payments.db", api_key=None):
        self.db_connection = sqlite3.connect(db_path)
        self.api_key = api_key or _required_secret("PAYMENT_GATEWAY_API_KEY")

    def process_card_payment(self, card_number, cvv, expiry, amount, customer_id):
        masked_pan = _mask_pan(card_number)
        logger.info("Processing payment customer_id=%s card=%s", customer_id, masked_pan)

        if not self._validate_card(card_number):
            logger.warning("Rejected payment customer_id=%s card=%s", customer_id, masked_pan)
            return {"status": "failed", "error": "Card details are invalid"}

        try:
            gateway_result, gateway_token = self._call_payment_gateway(
                card_number, cvv, expiry, amount
            )
        except (requests.RequestException, ValueError):
            logger.warning(
                "Payment gateway failure customer_id=%s card=%s",
                customer_id,
                masked_pan,
            )
            return {"status": "failed", "error": "Payment could not be processed"}

        if gateway_token and gateway_result["status"] == "success":
            self._store_card_details(customer_id, gateway_token)

        logger.info(
            "Payment completed customer_id=%s card=%s transaction_id=%s",
            customer_id,
            masked_pan,
            gateway_result.get("transaction_id"),
        )
        return gateway_result

    def process_recurring_payment(self, customer_id, amount):
        """Process a recurring payment using only the stored gateway token."""
        stored_method = self.db_connection.execute(
            "SELECT gateway_token FROM stored_cards WHERE customer_id = ? LIMIT 1",
            (customer_id,),
        ).fetchone()
        if stored_method is None:
            return {"status": "failed", "error": "No stored payment method"}

        try:
            result = self._call_recurring_payment_gateway(stored_method[0], amount)
        except (requests.RequestException, ValueError):
            logger.warning("Recurring payment failed customer_id=%s", customer_id)
            return {"status": "failed", "error": "Payment could not be processed"}

        logger.info(
            "Recurring payment completed customer_id=%s transaction_id=%s",
            customer_id,
            result.get("transaction_id"),
        )
        return result

    def _store_card_details(self, customer_id, gateway_token):
        """Store only the gateway token needed for recurring payments."""
        cursor = self.db_connection.cursor()
        cursor.execute(
            "INSERT INTO stored_cards (customer_id, gateway_token) VALUES (?, ?)",
            (customer_id, gateway_token),
        )
        self.db_connection.commit()
        logger.info("Stored payment method customer_id=%s", customer_id)

    def _validate_card(self, card_number):
        """Perform the service's basic card-shape validation."""
        return str(card_number).isdigit() and len(str(card_number)) == 16

    def _call_payment_gateway(self, card_number, cvv, expiry, amount):
        """Call the payment gateway over verified HTTPS with a finite timeout."""
        response = requests.post(
            "https://payment-gateway.example.com/process",
            json={
                "card": card_number,
                "cvv": cvv,
                "expiry": expiry,
                "amount": amount,
                "api_key": self.api_key,
            },
            timeout=REQUEST_TIMEOUT,
            verify=True,
        )
        response.raise_for_status()
        payload, public_result = self._sanitize_gateway_response(response)
        gateway_token = payload.get("payment_token")
        return public_result, gateway_token

    def _call_recurring_payment_gateway(self, gateway_token, amount):
        response = requests.post(
            "https://payment-gateway.example.com/recurring",
            json={
                "payment_token": gateway_token,
                "amount": amount,
                "api_key": self.api_key,
            },
            timeout=REQUEST_TIMEOUT,
            verify=True,
        )
        response.raise_for_status()
        _, public_result = self._sanitize_gateway_response(response)
        return public_result

    @staticmethod
    def _sanitize_gateway_response(response):
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Unexpected payment gateway response")
        status = payload.get("status")
        if status not in {"success", "failed", "pending"}:
            status = "failed"
        return payload, {
            "status": status,
            "transaction_id": payload.get("transaction_id"),
        }


class CustomerAuthentication:
    """Handle customer login and session management."""

    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_SECONDS = 300
    RESET_TOKEN_LIFETIME = timedelta(minutes=30)
    SCRYPT_N = 2**14
    SCRYPT_R = 8
    SCRYPT_P = 1

    def __init__(self, db_path="customers.db"):
        self.db = sqlite3.connect(db_path)
        self.sessions = {}
        self._failed_attempts = {}
        self._locked_until = {}
        self._reset_tokens = {}

    def authenticate_user(self, username, password):
        """Authenticate a customer and enforce a bounded lockout policy."""
        now = time.monotonic()
        if self._locked_until.get(username, 0) > now:
            logger.warning("Blocked login attempt username=%s", username)
            return {"status": "failed", "error": "Invalid credentials"}

        cursor = self.db.cursor()
        result = cursor.execute(
            "SELECT password_hash FROM customers WHERE username = ?",
            (username,),
        ).fetchone()
        logger.info("Login attempt username=%s", username)

        if result and self._verify_password(password, result[0]):
            self._failed_attempts.pop(username, None)
            self._locked_until.pop(username, None)
            session_token = secrets.token_urlsafe(32)
            self.sessions[session_token] = username
            logger.info("Authentication succeeded username=%s", username)
            return {"status": "success", "token": session_token}

        attempts = self._failed_attempts.get(username, 0) + 1
        self._failed_attempts[username] = attempts
        if attempts >= self.MAX_FAILED_ATTEMPTS:
            self._locked_until[username] = now + self.LOCKOUT_SECONDS
            self._failed_attempts.pop(username, None)
            logger.warning("Account temporarily locked username=%s", username)
        return {"status": "failed", "error": "Invalid credentials"}

    def register_user(self, username, password, email):
        """Register a customer using a uniquely salted password KDF."""
        password_hash = self._hash_password(password)
        cursor = self.db.cursor()
        cursor.execute(
            "INSERT INTO customers (username, password_hash, email) VALUES (?, ?, ?)",
            (username, password_hash, email),
        )
        self.db.commit()
        logger.info("Registered user username=%s", username)
        return {"status": "success", "message": f"User {username} registered"}

    @classmethod
    def _hash_password(cls, password):
        salt = secrets.token_bytes(16)
        derived_key = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=cls.SCRYPT_N,
            r=cls.SCRYPT_R,
            p=cls.SCRYPT_P,
            dklen=32,
        )
        return "$".join(
            (
                "scrypt",
                str(cls.SCRYPT_N),
                str(cls.SCRYPT_R),
                str(cls.SCRYPT_P),
                _base64url_encode(salt),
                _base64url_encode(derived_key),
            )
        )

    @classmethod
    def _verify_password(cls, password, encoded_hash):
        try:
            algorithm, n, r, p, salt, expected = encoded_hash.split("$")
            if algorithm != "scrypt":
                return False
            parameters = (int(n), int(r), int(p))
            if parameters != (cls.SCRYPT_N, cls.SCRYPT_R, cls.SCRYPT_P):
                return False
            decoded_salt = _base64url_decode(salt)
            expected_key = _base64url_decode(expected)
            if len(decoded_salt) != 16 or len(expected_key) != 32:
                return False
            derived_key = hashlib.scrypt(
                password.encode("utf-8"),
                salt=decoded_salt,
                n=parameters[0],
                r=parameters[1],
                p=parameters[2],
                dklen=len(expected_key),
            )
            return hmac.compare_digest(derived_key, expected_key)
        except (TypeError, ValueError):
            return False

    def reset_password(self, email):
        """Create a one-time reset token while retaining only its digest."""
        reset_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(reset_token.encode("utf-8")).digest()
        expires_at = datetime.now(timezone.utc) + self.RESET_TOKEN_LIFETIME
        self._reset_tokens[email] = (token_hash, expires_at)
        logger.info("Password reset requested")
        return {"status": "success", "token": reset_token}

    def validate_reset_token(self, email, token):
        """Validate and consume an unexpired reset token."""
        stored = self._reset_tokens.get(email)
        if not stored:
            return False
        expected_hash, expires_at = stored
        supplied_hash = hashlib.sha256(token.encode("utf-8")).digest()
        valid = datetime.now(timezone.utc) < expires_at and hmac.compare_digest(
            supplied_hash, expected_hash
        )
        if valid:
            self._reset_tokens.pop(email, None)
        return valid

    def generate_jwt(self, username):
        """Issue a signed JWT for an authenticated user."""
        return jwt.encode(
            {"user": username},
            _required_secret("JWT_SECRET"),
            algorithm="HS256",
        )

    def verify_jwt_token(self, token):
        """Verify a JWT using the required algorithm and signing secret."""
        return jwt.decode(
            token,
            _required_secret("JWT_SECRET"),
            algorithms=["HS256"],
        )

    def create_session_blob(self, token, username):
        """Create a signed JSON representation of a resumable session."""
        payload = json.dumps(
            {"token": token, "username": username},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        encoded_payload = _base64url_encode(payload)
        signature = hmac.new(
            _required_secret("JWT_SECRET").encode("utf-8"),
            encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()
        return f"{encoded_payload}.{_base64url_encode(signature)}"

    def resume_session(self, token_blob):
        """Verify a signed JSON session before parsing and restoring it."""
        try:
            encoded_payload, encoded_signature = token_blob.split(".", 1)
            supplied_signature = _base64url_decode(encoded_signature)
        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid session token") from exc

        expected_signature = hmac.new(
            _required_secret("JWT_SECRET").encode("utf-8"),
            encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise ValueError("Invalid session token")

        try:
            data = json.loads(_base64url_decode(encoded_payload).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("Invalid session token") from exc
        if not isinstance(data, dict) or not all(
            isinstance(data.get(field), str) for field in ("token", "username")
        ):
            raise ValueError("Invalid session token")
        self.sessions[data["token"]] = data["username"]
        return data

    def _tokens_match(self, provided, expected):
        """Compare session tokens in constant time."""
        return hmac.compare_digest(provided, expected)


class WebhookService:
    """Deliver transaction webhooks to validated public endpoints."""

    def notify(self, callback_url, payload):
        safe_url = _validated_public_https_url(callback_url)
        response = requests.get(
            safe_url,
            params=payload,
            allow_redirects=False,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        return response.text

    def fetch_remote_config(self, url):
        safe_url = _validated_public_https_url(url)
        response = requests.get(
            safe_url,
            allow_redirects=False,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        return response.text


class StatementService:
    """Serve account statements and parse uploaded invoices."""

    STATEMENT_DIR = "/var/statements/"

    def get_statement(self, filename):
        base_directory = Path(self.STATEMENT_DIR).resolve()
        candidate = (base_directory / filename).resolve()
        try:
            candidate.relative_to(base_directory)
        except ValueError as exc:
            raise ValueError("Statement path escapes the statement directory") from exc
        with candidate.open("r", encoding="utf-8") as statement:
            return statement.read()

    def parse_invoice(self, xml_data):
        parser = etree.XMLParser(
            resolve_entities=False,
            no_network=True,
            load_dtd=False,
        )
        root = etree.fromstring(xml_data.encode("utf-8"), parser=parser)
        return {child.tag: child.text for child in root}

    def cache_statement(self, content):
        descriptor, temporary_path = tempfile.mkstemp(prefix="stmt_")
        with os.fdopen(descriptor, "w", encoding="utf-8") as temporary_file:
            temporary_file.write(content)
        return temporary_path


class ConfigLoader:
    """Load runtime configuration without constructing Python objects."""

    def load(self, config_str):
        return yaml.safe_load(config_str)


class TransactionLogger:
    """Log transactions without authentication or cardholder secrets."""

    def log_transaction(self, transaction_data):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "card_number": _mask_pan(transaction_data.get("card_number", "")),
            "amount": transaction_data.get("amount"),
            "customer_id": transaction_data.get("customer_id"),
        }

        with open("transactions.log", "a", encoding="utf-8") as transaction_log:
            transaction_log.write(json.dumps(log_entry, sort_keys=True) + "\n")

        print(
            "TRANSACTION: "
            f"Customer={log_entry['customer_id']}, Card={log_entry['card_number']}"
        )
        logger.info(
            "Transaction logged customer_id=%s card=%s",
            log_entry["customer_id"],
            log_entry["card_number"],
        )
        return log_entry


class CardEncryption:
    """Encrypt PANs with KMS/HSM-provided key material."""

    def __init__(self, encryption_key, pan_hmac_key):
        if not isinstance(encryption_key, bytes) or len(encryption_key) not in {16, 24, 32}:
            raise ValueError("AES key must be 16, 24, or 32 bytes")
        if not isinstance(pan_hmac_key, bytes) or len(pan_hmac_key) < 32:
            raise ValueError("PAN HMAC key must contain at least 32 bytes")
        self._encryption_key = encryption_key
        self._pan_hmac_key = pan_hmac_key

    def encrypt_card_number(self, card_number):
        """Return an authenticated envelope containing nonce, tag, and ciphertext."""
        from Crypto.Cipher import AES

        nonce = secrets.token_bytes(12)
        cipher = AES.new(self._encryption_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(card_number.encode("utf-8"))
        return _base64url_encode(nonce + tag + ciphertext)

    def decrypt_card_number(self, encrypted_card_number):
        """Decrypt a PAN and propagate authentication failures to the caller."""
        from Crypto.Cipher import AES

        envelope = _base64url_decode(encrypted_card_number)
        if len(envelope) < 29:
            raise ValueError("Invalid encrypted PAN")
        nonce, tag, ciphertext = envelope[:12], envelope[12:28], envelope[28:]
        cipher = AES.new(self._encryption_key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")

    def hash_pan(self, card_number):
        """Create a keyed lookup digest using separately managed key material."""
        return hmac.new(
            self._pan_hmac_key,
            card_number.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()


class ReportGenerator:
    """Generate transaction reports."""

    def generate_daily_report(self, date):
        connection = sqlite3.connect("payments.db")
        try:
            results = connection.execute(
                "SELECT * FROM transactions WHERE date = ?",
                (date,),
            ).fetchall()
        finally:
            connection.close()

        report = [
            {
                "transaction_id": row[0],
                "card_number": _mask_pan(row[1]),
                "amount": row[3],
                "customer_name": row[4],
            }
            for row in results
        ]
        logger.info("Daily report generated date=%s count=%s", date, len(report))
        return report

    def export_customer_data(self, customer_id):
        connection = sqlite3.connect("customers.db")
        try:
            customer = connection.execute(
                "SELECT * FROM customers WHERE id = ?",
                (customer_id,),
            ).fetchone()
            has_stored_payment_method = connection.execute(
                "SELECT 1 FROM stored_cards WHERE customer_id = ? LIMIT 1",
                (customer_id,),
            ).fetchone() is not None
        finally:
            connection.close()
        return {
            "customer": customer,
            "has_stored_payment_method": has_stored_payment_method,
        }


class APIHandler:
    """Handle API requests for the mobile banking app."""

    def process_api_request(self, request_data):
        action = request_data.get("action")
        if action == "transfer":
            return self._execute_transfer(
                request_data.get("from_account"),
                request_data.get("to_account"),
                request_data.get("amount"),
            )
        if action == "get_balance":
            return self._get_account_balance(request_data.get("account_id"))
        return {"status": "error", "message": "Unknown action"}

    def _execute_transfer(self, from_account, to_account, amount):
        try:
            numeric_amount = float(amount)
        except (TypeError, ValueError):
            return {"status": "error", "message": "Amount must be positive"}
        if not math.isfinite(numeric_amount) or numeric_amount <= 0:
            return {"status": "error", "message": "Amount must be positive"}

        connection = sqlite3.connect("accounts.db")
        try:
            connection.execute("BEGIN IMMEDIATE")
            source = connection.execute(
                "SELECT balance FROM accounts WHERE account_id = ?",
                (from_account,),
            ).fetchone()
            destination = connection.execute(
                "SELECT 1 FROM accounts WHERE account_id = ?",
                (to_account,),
            ).fetchone()
            if source is None or destination is None:
                connection.rollback()
                return {"status": "error", "message": "Transfer could not be completed"}
            if source[0] < numeric_amount:
                connection.rollback()
                return {"status": "error", "message": "Insufficient funds"}

            connection.execute(
                "UPDATE accounts SET balance = balance - ? WHERE account_id = ?",
                (numeric_amount, from_account),
            )
            connection.execute(
                "UPDATE accounts SET balance = balance + ? WHERE account_id = ?",
                (numeric_amount, to_account),
            )
            connection.commit()
        except sqlite3.Error:
            connection.rollback()
            logger.exception("Transfer failed")
            return {"status": "error", "message": "Transfer could not be completed"}
        finally:
            connection.close()

        logger.info(
            "Transfer completed amount=%s from_account=%s to_account=%s",
            numeric_amount,
            from_account,
            to_account,
        )
        return {"status": "success", "message": "Transfer completed"}

    def _get_account_balance(self, account_id):
        connection = sqlite3.connect("accounts.db")
        try:
            result = connection.execute(
                "SELECT balance FROM accounts WHERE account_id = ?",
                (account_id,),
            ).fetchone()
        finally:
            connection.close()
        return {"balance": result[0] if result else 0}


def run_payment_batch(card_list):
    """Process a batch without executing callbacks or printing sensitive data."""
    processor = PaymentProcessor()
    for card in card_list:
        result = processor.process_card_payment(
            card["number"],
            card["cvv"],
            card["expiry"],
            card["amount"],
            card["customer_id"],
        )
        print(
            "Processed: "
            f"customer_id={card['customer_id']} card={_mask_pan(card['number'])} "
            f"status={result.get('status')}"
        )


ADMIN_ACTIONS = {
    "disk_usage": ["df", "-h"],
    "uptime": ["uptime"],
}


def execute_admin_command(action):
    """Execute one predefined administrative action without a shell."""
    argv = ADMIN_ACTIONS.get(action)
    if argv is None:
        raise ValueError("Unknown administrative action")
    result = subprocess.run(
        argv,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout
