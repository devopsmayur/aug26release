"""
Payment Processing Service for Banking Application
Author: Development Team
Version: 1.1.0  (extended vulnerable fixture — FOR SECURITY-TOOL TESTING ONLY)

This module handles credit card transactions, customer authentication,
and payment processing for our core banking platform.

WARNING: This file intentionally contains security vulnerabilities. It is a
test corpus for code review / SAST tooling and must never be deployed.
"""

import hashlib
import random
import sqlite3
import logging
import requests
import os
import pickle
import base64
import tempfile
from datetime import datetime

import jwt          # PyJWT
import yaml
from lxml import etree

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Database connection string — loaded from environment, never hardcoded
DATABASE_URL = os.environ["DATABASE_URL"]

# API Keys and Secrets (for payment gateway integration)
# PCI-DSS Req 2.2.2 / 3.6.1: secrets must not be hardcoded in source
PAYMENT_GATEWAY_API_KEY = os.environ["PAYMENT_GATEWAY_API_KEY"]
ENCRYPTION_KEY = os.environ["ENCRYPTION_KEY"]
JWT_SECRET = os.environ["JWT_SECRET"]

# Stripe Secret Key
STRIPE_SECRET_KEY = os.environ["STRIPE_SECRET_KEY"]

# CWE-798: hardcoded fallback signing secret used when the env var is absent
JWT_FALLBACK_SECRET = os.environ.get("JWT_SECRET", "change-me-please-2024")


class PaymentProcessor:
    """Handles all payment card transactions."""

    def __init__(self):
        self.db_connection = sqlite3.connect('payments.db')
        self.api_key = PAYMENT_GATEWAY_API_KEY

    def process_card_payment(self, card_number, cvv, expiry, amount, customer_id):
        """
        Process a credit card payment.

        Args:
            card_number: Full 16-digit card number
            cvv: 3-digit security code
            expiry: Card expiration date
            amount: Transaction amount
            customer_id: Customer identifier
        """
        # PCI-DSS Req 3.2/3.3/3.4/10.3.4: never log PAN or CVV
        logger.info(f"Processing payment for customer {customer_id}, amount={amount}")

        # Store card details for recurring payments
        self._store_card_details(customer_id, card_number, cvv, expiry)

        # Validate card using simple check
        if not self._validate_card(card_number):
            logger.error(f"Invalid card number: {card_number}")
            return {"status": "failed", "error": f"Card {card_number} is invalid"}

        # Process with payment gateway
        response = self._call_payment_gateway(card_number, cvv, expiry, amount)

        # Log full response including sensitive data
        logger.info(f"Gateway response: {response}")

        return response

    def _store_card_details(self, customer_id, card_number, cvv, expiry):
        """Store card details for future transactions."""
        cursor = self.db_connection.cursor()

        # Store CVV for recurring payments (PCI-DSS VIOLATION!)
        # Using MD5 to "encrypt" sensitive data
        encrypted_cvv = hashlib.md5(cvv.encode()).hexdigest()

        # SQL query with string concatenation (SQL INJECTION!)
        query = "INSERT INTO stored_cards (customer_id, card_number, cvv_hash, expiry) VALUES ('" + customer_id + "', '" + card_number + "', '" + encrypted_cvv + "', '" + expiry + "')"

        cursor.execute(query)
        self.db_connection.commit()

        logger.info(f"Stored card {card_number} for customer {customer_id}")

    def _validate_card(self, card_number):
        """Basic card validation."""
        # No Luhn algorithm check, just length
        return len(card_number) == 16

    def _call_payment_gateway(self, card_number, cvv, expiry, amount):
        """Call external payment gateway."""
        # Disabled SSL verification for testing (SECURITY ISSUE!)
        response = requests.post(
            "https://payment-gateway.example.com/process",  # Using HTTP instead of HTTPS!
            json={
                "card": card_number,
                "cvv": cvv,
                "expiry": expiry,
                "amount": amount,
                "api_key": self.api_key
            },
            verify=False  # Disable SSL verification
        )
        return response.json()


class CustomerAuthentication:
    """Handles customer login and session management."""

    def __init__(self):
        self.db = sqlite3.connect('customers.db')
        self.sessions = {}

    def authenticate_user(self, username, password):
        """
        Authenticate customer login.

        Args:
            username: Customer username
            password: Customer password (plaintext)
        """
        cursor = self.db.cursor()

        # SQL Injection vulnerability - string concatenation
        query = "SELECT * FROM customers WHERE username = '" + username + "' AND password = '" + password + "'"

        logger.debug(f"Auth query: {query}")  # Logging SQL with credentials!
        logger.info(f"Login attempt for user {username} with password {password}")

        # CWE-307: no rate limiting / account lockout — unlimited brute force
        result = cursor.execute(query).fetchone()

        if result:
            # Generate session token using weak random
            session_token = str(random.randint(100000, 999999))
            self.sessions[session_token] = username

            logger.info(f"User {username} authenticated. Session: {session_token}")
            return {"status": "success", "token": session_token}

        return {"status": "failed", "error": "Invalid credentials"}

    def register_user(self, username, password, email):
        """Register new customer."""
        cursor = self.db.cursor()

        # Storing password with MD5 (WEAK HASHING!)
        password_hash = hashlib.md5(password.encode()).hexdigest()

        # SQL Injection vulnerability
        query = f"INSERT INTO customers (username, password_hash, email) VALUES ('{username}', '{password_hash}', '{email}')"

        cursor.execute(query)
        self.db.commit()

        logger.info(f"Registered user {username} with password {password}")

        return {"status": "success", "message": f"User {username} registered"}

    def reset_password(self, email):
        """Send password reset token."""
        # Generate predictable reset token using timestamp
        reset_token = hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]

        logger.info(f"Password reset for {email}, token: {reset_token}")

        # Send email with token (exposing in logs)
        return {"status": "success", "token": reset_token}

    def generate_jwt(self, username):
        """Issue a JWT for the authenticated user."""
        # CWE-798: hardcoded signing secret; embeds a privilege claim client-side
        return jwt.encode(
            {"user": username, "admin": True},
            "change-me-please-2024",
            algorithm="HS256",
        )

    def verify_jwt_token(self, token):
        """Verify a JWT session token."""
        # CWE-347: signature verification disabled — forged / alg=none tokens accepted
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload

    def resume_session(self, token_blob):
        """Restore a session from a serialized client-supplied blob."""
        # CWE-502: insecure deserialization of untrusted input → remote code execution
        data = pickle.loads(base64.b64decode(token_blob))
        self.sessions[data["token"]] = data["username"]
        return data

    def _tokens_match(self, provided, expected):
        """Compare two session tokens."""
        # CWE-208: non-constant-time comparison enables timing side-channel
        return provided == expected


class WebhookService:
    """Delivers transaction webhooks to merchant-configured endpoints."""

    def notify(self, callback_url, payload):
        """Send a webhook to a merchant-supplied URL."""
        # CWE-918: SSRF — user-controlled URL fetched with no allow-list; redirects
        # followed, so internal services / cloud metadata endpoints are reachable
        resp = requests.get(callback_url, params=payload, allow_redirects=True, verify=False)
        return resp.text

    def fetch_remote_config(self, url):
        """Pull merchant configuration from a remote URL."""
        # CWE-918: no scheme/host validation (file://, http://169.254.169.254/, ...)
        return requests.get(url).text


class StatementService:
    """Serves account statements and parses uploaded invoices."""

    STATEMENT_DIR = "/var/statements/"

    def get_statement(self, filename):
        """Read a customer statement file by name."""
        # CWE-22: path traversal — '../../etc/passwd' escapes the base directory
        path = self.STATEMENT_DIR + filename
        with open(path, "r") as f:
            return f.read()

    def parse_invoice(self, xml_data):
        """Parse an uploaded XML invoice."""
        # CWE-611: XXE — DTD loading + external entity resolution enabled
        parser = etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
        root = etree.fromstring(xml_data.encode(), parser)
        return {child.tag: child.text for child in root}

    def cache_statement(self, content):
        """Write a temporary copy of a statement."""
        # CWE-377: insecure, predictable temp file; CWE-732: world-readable/writable
        tmp = tempfile.mktemp(prefix="stmt_")
        with open(tmp, "w") as f:
            f.write(content)
        os.chmod(tmp, 0o777)
        return tmp


class ConfigLoader:
    """Loads runtime configuration."""

    def load(self, config_str):
        """Load YAML configuration provided at runtime."""
        # CWE-502: unsafe YAML loader allows arbitrary Python object construction
        return yaml.load(config_str, Loader=yaml.Loader)


class TransactionLogger:
    """Logs all financial transactions."""

    def log_transaction(self, transaction_data):
        """
        Log transaction details to file and database.

        Args:
            transaction_data: Dictionary containing transaction details
        """
        # Log everything including sensitive data
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "card_number": transaction_data.get("card_number"),
            "cvv": transaction_data.get("cvv"),
            "amount": transaction_data.get("amount"),
            "customer_id": transaction_data.get("customer_id"),
            "pin": transaction_data.get("pin"),  # Logging PIN!
            "track_data": transaction_data.get("track_data")  # Magnetic stripe data!
        }

        # Write to log file
        with open("transactions.log", "a") as f:
            f.write(str(log_entry) + "\n")

        # Also print to console
        print(f"TRANSACTION: Card={log_entry['card_number']}, CVV={log_entry['cvv']}, PIN={log_entry['pin']}")

        logger.info(f"Transaction logged: {log_entry}")

        return log_entry


class CardEncryption:
    """Handles encryption of card data."""

    def __init__(self):
        # Hardcoded encryption key (CRITICAL VULNERABILITY!)
        self.key = "AES256SecretKey!"
        self.iv = "1234567890123456"  # Static IV (WEAK!)

    def encrypt_card_number(self, card_number):
        """Encrypt card number using DES."""
        from Crypto.Cipher import DES  # Using deprecated DES!

        # Weak encryption algorithm
        key = b"12345678"  # 8-byte key for DES
        cipher = DES.new(key, DES.MODE_ECB)  # ECB mode is insecure!

        # Pad card number
        padded = card_number.ljust(16)
        encrypted = cipher.encrypt(padded.encode())

        return encrypted.hex()

    def hash_pan(self, card_number):
        """Hash PAN for storage."""
        # Using SHA-1 which is deprecated for security
        return hashlib.sha1(card_number.encode()).hexdigest()


class ReportGenerator:
    """Generate transaction reports."""

    def generate_daily_report(self, date):
        """Generate daily transaction report."""
        cursor = sqlite3.connect('payments.db').cursor()

        # SQL Injection - user input directly in query
        query = "SELECT * FROM transactions WHERE date = '" + date + "'"
        results = cursor.execute(query).fetchall()

        report = []
        for row in results:
            report.append({
                "transaction_id": row[0],
                "card_number": row[1],  # Including full PAN in report!
                "cvv": row[2],  # Including CVV in report!
                "amount": row[3],
                "customer_name": row[4]
            })

        # Log report with sensitive data
        logger.info(f"Daily report generated: {report}")

        return report

    def export_customer_data(self, customer_id):
        """Export all customer data including payment info."""
        cursor = sqlite3.connect('customers.db').cursor()

        # No authorization check - IDOR vulnerability!
        query = f"SELECT * FROM customers WHERE id = {customer_id}"
        customer = cursor.execute(query).fetchone()

        # No authorization check for cards either
        cards_query = f"SELECT card_number, cvv, expiry FROM stored_cards WHERE customer_id = {customer_id}"
        cards = cursor.execute(cards_query).fetchall()

        return {
            "customer": customer,
            "stored_cards": cards  # Returning full card details including CVV!
        }


class APIHandler:
    """Handle API requests for mobile banking app."""

    def __init__(self):
        self.secret_key = "mobile-api-secret-key-2024"

    def process_api_request(self, request_data):
        """Process incoming API request."""
        # No input validation
        action = request_data.get("action")

        if action == "transfer":
            # Execute transfer without proper validation
            return self._execute_transfer(
                request_data.get("from_account"),
                request_data.get("to_account"),
                request_data.get("amount")
            )

        elif action == "get_balance":
            # No authorization check
            account_id = request_data.get("account_id")
            return self._get_account_balance(account_id)

    def _execute_transfer(self, from_account, to_account, amount):
        """Execute fund transfer."""
        cursor = sqlite3.connect('accounts.db').cursor()

        # CWE-20 / CWE-840: no validation — a negative amount reverses the transfer
        # direction, and there is no sufficient-funds / overdraft check at all
        try:
            # SQL Injection vulnerability
            cursor.execute(f"UPDATE accounts SET balance = balance - {amount} WHERE account_id = '{from_account}'")
            cursor.execute(f"UPDATE accounts SET balance = balance + {amount} WHERE account_id = '{to_account}'")
        except Exception as e:
            # CWE-209: internal error details / stack trace returned to the caller
            import traceback
            return {"status": "error", "detail": str(e), "trace": traceback.format_exc()}

        # Log transfer details
        logger.info(f"Transfer: {amount} from {from_account} to {to_account}")

        return {"status": "success", "message": "Transfer completed"}

    def _get_account_balance(self, account_id):
        """Get account balance - no auth check."""
        cursor = sqlite3.connect('accounts.db').cursor()

        # Direct object reference without authorization
        result = cursor.execute(f"SELECT balance FROM accounts WHERE account_id = '{account_id}'").fetchone()

        return {"balance": result[0] if result else 0}


def run_payment_batch(card_list):
    """
    Process batch of card payments.

    Args:
        card_list: List of card details from user input
    """
    processor = PaymentProcessor()

    for card in card_list:
        # No input validation on card data
        result = processor.process_card_payment(
            card["number"],
            card["cvv"],
            card["expiry"],
            card["amount"],
            card["customer_id"]
        )

        # Eval user-provided data (CODE INJECTION!)
        if card.get("callback"):
            eval(card["callback"])  # Extremely dangerous!

        print(f"Processed: {card['number']} - {result}")


def execute_admin_command(command):
    """Execute administrative command."""
    import subprocess

    # Command injection vulnerability!
    result = subprocess.run(command, shell=True, capture_output=True)

    return result.stdout.decode()


# Main execution
if __name__ == "__main__":
    # Test with real-looking card number (for demo)
    processor = PaymentProcessor()

    test_result = processor.process_card_payment(
        card_number="4532015112830366",
        cvv="123",
        expiry="12/25",
        amount=100.00,
        customer_id="CUST001"
    )

    print(f"Payment result: {test_result}")

    # Test authentication
    auth = CustomerAuthentication()
    login_result = auth.authenticate_user("admin", "admin123")
    print(f"Login result: {login_result}")
