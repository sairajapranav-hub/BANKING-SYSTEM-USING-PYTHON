import hashlib
import hmac
import os
import secrets
from decimal import Decimal, InvalidOperation

import mysql.connector


class BankingDatabase:
    def __init__(self, connection):
        self.connection = connection

    def _execute(self, query, values=()):
        cursor = self.connection.cursor()
        try:
            cursor.execute(query, values)
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def _fetchone(self, query, values=()):
        cursor = self.connection.cursor()
        try:
            cursor.execute(query, values)
            return cursor.fetchone()
        finally:
            cursor.close()

    def create_login_table(self):
        self._execute(
            """
            CREATE TABLE IF NOT EXISTS login_credentials (
                username VARCHAR(50) PRIMARY KEY,
                password_hash VARCHAR(255) NOT NULL
            ) ENGINE=InnoDB
            """
        )

    def create_user_table(self):
        self._execute(
            """
            CREATE TABLE IF NOT EXISTS bank_users (
                username VARCHAR(50) PRIMARY KEY,
                balance DECIMAL(12, 2) NOT NULL DEFAULT 0.00,
                FOREIGN KEY (username) REFERENCES login_credentials(username)
            ) ENGINE=InnoDB
            """
        )

    def create_transaction_table(self):
        self._execute(
            """
            CREATE TABLE IF NOT EXISTS bank_transactions (
                transaction_id BIGINT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL,
                transaction_type VARCHAR(20) NOT NULL,
                amount DECIMAL(12, 2) NOT NULL,
                recipient_username VARCHAR(50),
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (username) REFERENCES bank_users(username),
                FOREIGN KEY (recipient_username) REFERENCES bank_users(username)
            ) ENGINE=InnoDB
            """
        )

    def user_exists(self, username):
        return self._fetchone(
            "SELECT 1 FROM login_credentials WHERE username = %s", (username,)
        ) is not None

    def create_user(self, username, password):
        salt = secrets.token_bytes(16)
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, 310_000
        )
        stored_hash = f"{salt.hex()}${password_hash.hex()}"
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "INSERT INTO login_credentials (username, password_hash) VALUES (%s, %s)",
                (username, stored_hash),
            )
            cursor.execute(
                "INSERT INTO bank_users (username, balance) VALUES (%s, %s)",
                (username, Decimal("0.00")),
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def authenticate_user(self, username, password):
        row = self._fetchone(
            "SELECT password_hash FROM login_credentials WHERE username = %s",
            (username,),
        )
        if row is None:
            return False

        try:
            salt_hex, expected_hash = row[0].split("$", 1)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(expected_hash)
        except (AttributeError, ValueError):
            return False

        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, 310_000
        )
        return hmac.compare_digest(actual, expected)

    def get_balance(self, username):
        row = self._fetchone(
            "SELECT balance FROM bank_users WHERE username = %s", (username,)
        )
        if row is None:
            raise ValueError(f"No bank account exists for {username!r}.")
        return Decimal(row[0])

    def deposit(self, username, amount):
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "UPDATE bank_users SET balance = balance + %s WHERE username = %s",
                (amount, username),
            )
            if cursor.rowcount != 1:
                raise ValueError(f"No bank account exists for {username!r}.")
            cursor.execute(
                """
                INSERT INTO bank_transactions (username, transaction_type, amount)
                VALUES (%s, 'DEPOSIT', %s)
                """,
                (username, amount),
            )
            cursor.execute(
                "SELECT balance FROM bank_users WHERE username = %s", (username,)
            )
            new_balance = Decimal(cursor.fetchone()[0])
            self.connection.commit()
            return new_balance
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def withdraw(self, username, amount):
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                """
                UPDATE bank_users SET balance = balance - %s
                WHERE username = %s AND balance >= %s
                """,
                (amount, username, amount),
            )
            if cursor.rowcount != 1:
                self.connection.rollback()
                return None
            cursor.execute(
                """
                INSERT INTO bank_transactions (username, transaction_type, amount)
                VALUES (%s, 'WITHDRAWAL', %s)
                """,
                (username, amount),
            )
            cursor.execute(
                "SELECT balance FROM bank_users WHERE username = %s", (username,)
            )
            new_balance = Decimal(cursor.fetchone()[0])
            self.connection.commit()
            return new_balance
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def transfer(self, username, recipient, amount):
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                """
                UPDATE bank_users SET balance = balance - %s
                WHERE username = %s AND balance >= %s
                """,
                (amount, username, amount),
            )
            if cursor.rowcount != 1:
                self.connection.rollback()
                return None

            cursor.execute(
                "UPDATE bank_users SET balance = balance + %s WHERE username = %s",
                (amount, recipient),
            )
            if cursor.rowcount != 1:
                raise ValueError("Recipient account does not exist.")

            cursor.execute(
                """
                INSERT INTO bank_transactions
                    (username, transaction_type, amount, recipient_username)
                VALUES (%s, 'TRANSFER_OUT', %s, %s)
                """,
                (username, amount, recipient),
            )
            cursor.execute(
                """
                INSERT INTO bank_transactions
                    (username, transaction_type, amount, recipient_username)
                VALUES (%s, 'TRANSFER_IN', %s, %s)
                """,
                (recipient, amount, username),
            )
            cursor.execute(
                "SELECT balance FROM bank_users WHERE username = %s", (username,)
            )
            new_balance = Decimal(cursor.fetchone()[0])
            self.connection.commit()
            return new_balance
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()


def read_amount(prompt):
    try:
        raw_amount = Decimal(input(prompt).strip())
        if not raw_amount.is_finite():
            print("Enter a valid finite amount.")
            return None
        amount = raw_amount.quantize(Decimal("0.01"))
    except InvalidOperation:
        print("Enter a valid amount with no more than two decimal places.")
        return None

    if (
        amount != raw_amount
        or amount <= 0
        or amount >= Decimal("10000000000")
    ):
        print("Enter a positive amount within the supported range.")
        return None
    return amount


def signup(connector):
    print("Welcome to the Banking System Signup!")
    username = input("Enter your desired username: ").strip()
    password = input("Enter your desired password: ")

    if not username or len(username) > 50 or not password:
        print("Enter a username (up to 50 characters) and a non-empty password.")
        return
    if connector.user_exists(username):
        print("Username already taken. Please try a different one.")
        return

    connector.create_user(username, password)
    print("Signup successful! You can now log in with your credentials.")


def login(connector):
    print("Welcome to the Banking System Login!")
    username = input("Enter your username: ").strip()
    password = input("Enter your password: ")

    if connector.authenticate_user(username, password):
        print(f"Login successful! Welcome, {username}.")
        return username

    print("Invalid username or password. Please try again.")
    return None


def withdraw(connector, username):
    print("Withdraw Funds")
    amount = read_amount("Enter the amount to withdraw: ")
    if amount is None:
        return

    new_balance = connector.withdraw(username, amount)
    if new_balance is None:
        print("Insufficient funds. Transaction cancelled.")
        return
    print(f"Withdrawal successful! New balance: {new_balance:.2f}")


def deposit(connector, username):
    print("Deposit Funds")
    amount = read_amount("Enter the amount to deposit: ")
    if amount is None:
        return

    new_balance = connector.deposit(username, amount)
    print(f"Deposit successful! New balance: {new_balance:.2f}")


def transfer(connector, username):
    print("Transfer Funds")
    recipient = input("Enter the recipient's username: ").strip()
    amount = read_amount("Enter the amount to transfer: ")
    if amount is None:
        return
    if recipient == username:
        print("You cannot transfer funds to your own account.")
        return
    if not connector.user_exists(recipient):
        print("Recipient does not exist. Transaction cancelled.")
        return

    new_balance = connector.transfer(username, recipient, amount)
    if new_balance is None:
        print("Insufficient funds. Transaction cancelled.")
        return
    print(f"Transfer successful! New balance: {new_balance:.2f}")


def check_balance(connector, username):
    balance = connector.get_balance(username)
    print(f"Your current balance is: {balance:.2f}")


def menu(connector, username):
    while True:
        print("\nBanking System Menu:")
        print("1. Withdraw Funds")
        print("2. Deposit Funds")
        print("3. Transfer Funds")
        print("4. Check Balance")
        print("5. Logout")

        choice = input("Enter your choice (1-5): ")
        if choice == "1":
            withdraw(connector, username)
        elif choice == "2":
            deposit(connector, username)
        elif choice == "3":
            transfer(connector, username)
        elif choice == "4":
            check_balance(connector, username)
        elif choice == "5":
            print("Logging out...")
            break
        else:
            print("Invalid choice. Please try again.")


def main():
    password = os.getenv("MYSQL_PASSWORD")
    if password is None:
        raise RuntimeError(
            "Set the MYSQL_PASSWORD environment variable before starting the app."
        )

    connection = mysql.connector.connect(
        host=os.getenv("MYSQL_HOST", "localhost"),
        user=os.getenv("MYSQL_USER", "root"),
        password=password,
        database=os.getenv("MYSQL_DATABASE", "banking_system"),
    )
    try:
        connector = BankingDatabase(connection)
        connector.create_login_table()
        connector.create_user_table()
        connector.create_transaction_table()

        while True:
            print("\nWelcome to the Banking System!")
            print("1. Signup")
            print("2. Login")
            print("3. Exit")

            choice = input("Enter your choice (1-3): ")
            if choice == "1":
                signup(connector)
            elif choice == "2":
                username = login(connector)
                if username:
                    menu(connector, username)
            elif choice == "3":
                print("Exiting the Banking System. Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")
    finally:
        connection.close()


if __name__ == "__main__":
    main()
