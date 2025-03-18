import sqlite3
import secrets
import string
from cryptography.fernet import Fernet
import base64
import hashlib
import getpass  # For hidden password input
import os

# List available databases
def list_databases():
    """List all .db files in the current directory."""
    databases = [f for f in os.listdir() if f.endswith(".db")]
    if not databases:
        print("No databases found.")
        return None
    print("Available databases:")
    for i, db in enumerate(databases):
        print(f"{i + 1}. {db}")
    return databases


# Select or create a database
def select_or_create_database():
    """Let the user select an existing database or create a new one."""
    databases = list_databases()
    if not databases:
        db_name = input(
            "Enter a name for the new database (e.g., accounts.db): "
        ).strip()
        if not db_name.endswith(".db"):
            db_name += ".db"
        return db_name

    choice = input(
        "Select a database (number) or enter a new name to create one: "
    ).strip()
    if choice.isdigit():
        index = int(choice) - 1
        if 0 <= index < len(databases):
            return databases[index]
    elif choice:
        if not choice.endswith(".db"):
            choice += ".db"
        return choice
    return None


# Initialize the database
def initialize_db(db_name):
    """Initialize the database with the required tables."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Create accounts table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Auto-incrementing ID
            email TEXT UNIQUE NOT NULL,            -- Unique email address
            password_encrypted TEXT NOT NULL,      -- Encrypted password
            github_username TEXT,                  -- Associated GitHub account
            twitter_username TEXT,                 -- Associated Twitter account
            twitter_password_encrypted TEXT        -- Encrypted Twitter password
        )
    """
    )

    # Create master_password table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS master_password (
            hash TEXT NOT NULL  -- Hash of the master password
        )
    """
    )

    conn.commit()
    conn.close()
    print(f"Database '{db_name}' initialized successfully.")


# Password generation
def generate_password(length=12):
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(characters) for _ in range(length))


# Derive encryption key from master password
def derive_key(master_password):
    """Derive a 32-byte key from the master password using SHA-256."""
    hash_bytes = hashlib.sha256(master_password.encode()).digest()
    return base64.urlsafe_b64encode(hash_bytes)


# Encrypt password
def encrypt_password(password, key):
    """Encrypt the password using Fernet symmetric encryption."""
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()


# Decrypt password
def decrypt_password(encrypted_password, key):
    """Decrypt the password using Fernet symmetric encryption."""
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()


# Email account manager class
class EmailAccountManager:
    def __init__(self, db_name):
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.master_password = None  # Master password
        self.encryption_key = None  # Encryption key derived from master password
        self.load_master_password()

    def load_master_password(self):
        """Load the master password hash from the database."""
        self.cursor.execute("SELECT hash FROM master_password")
        result = self.cursor.fetchone()
        if result:
            self.master_password_hash = result[0]
            self.master_password = None  # Master password is not stored in memory
        else:
            self.set_master_password()

    def set_master_password(self):
        """Set master password and store its hash in the database."""
        while True:
            master_password = getpass.getpass(
                "Set a master password (input is hidden): "
            ).strip()
            if master_password:
                self.master_password_hash = hashlib.sha256(
                    master_password.encode()
                ).hexdigest()
                self.encryption_key = derive_key(master_password)
                self.cursor.execute(
                    "INSERT INTO master_password (hash) VALUES (?)",
                    (self.master_password_hash,),
                )
                self.conn.commit()
                print("Master password set successfully!")
                break
            else:
                print("Master password cannot be empty!")

    def verify_master_password(self, password):
        """Verify master password."""
        return (
            hashlib.sha256(password.encode()).hexdigest() == self.master_password_hash
        )

    def change_master_password(self):
        """Change the master password."""
        old_password = getpass.getpass(
            "Enter current master password (input is hidden): "
        ).strip()
        if not self.verify_master_password(old_password):
            print("Incorrect master password!")
            return False

        new_password = getpass.getpass(
            "Enter new master password (input is hidden): "
        ).strip()
        if not new_password:
            print("New master password cannot be empty!")
            return False

        # Re-encrypt all passwords with the new key
        new_key = derive_key(new_password)
        self.cursor.execute(
            "SELECT id, password_encrypted, twitter_password_encrypted FROM accounts"
        )
        accounts = self.cursor.fetchall()
        for account in accounts:
            account_id, password_encrypted, twitter_password_encrypted = account
            # Decrypt with old key
            try:
                password = decrypt_password(password_encrypted, self.encryption_key)
                if twitter_password_encrypted:
                    twitter_password = decrypt_password(
                        twitter_password_encrypted, self.encryption_key
                    )
                else:
                    twitter_password = None
            except Exception as e:
                print(f"Failed to decrypt passwords for account ID {account_id}: {e}")
                continue

            # Encrypt with new key
            new_password_encrypted = encrypt_password(password, new_key)
            new_twitter_password_encrypted = (
                encrypt_password(twitter_password, new_key)
                if twitter_password
                else None
            )

            # Update the database
            self.cursor.execute(
                """
                UPDATE accounts
                SET password_encrypted = ?, twitter_password_encrypted = ?
                WHERE id = ?
            """,
                (new_password_encrypted, new_twitter_password_encrypted, account_id),
            )

        # Update master password hash
        new_master_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        self.cursor.execute(
            "UPDATE master_password SET hash = ?", (new_master_password_hash,)
        )
        self.conn.commit()
        self.master_password_hash = new_master_password_hash
        self.encryption_key = new_key
        print("Master password changed successfully!")
        return True

    def add_account(
        self, email, github_username=None, twitter_username=None, twitter_password=None
    ):
        """Add a new account."""
        if self.find_account_by_email(email):
            print("Email already exists!")
            return False

        password = generate_password()
        password_encrypted = encrypt_password(password, self.encryption_key)

        # Handle Twitter password
        twitter_password_encrypted = None
        if twitter_username:
            twitter_password_encrypted = (
                encrypt_password(twitter_password, self.encryption_key)
                if twitter_password
                else password_encrypted  # Default to email password if Twitter password is not provided
            )

        self.cursor.execute(
            """
            INSERT INTO accounts (
                email, password_encrypted, github_username,
                twitter_username, twitter_password_encrypted
            ) VALUES (?, ?, ?, ?, ?)
        """,
            (
                email,
                password_encrypted,
                github_username,
                twitter_username,
                twitter_password_encrypted,
            ),
        )
        self.conn.commit()
        print(f"Account added successfully! Generated password: {password}")
        return True

    def find_account_by_email(self, email):
        """Find an account by email."""
        self.cursor.execute("SELECT * FROM accounts WHERE email = ?", (email,))
        return self.cursor.fetchone()

    def find_account_by_id(self, account_id):
        """Find an account by ID."""
        self.cursor.execute("SELECT * FROM accounts WHERE id = ?", (account_id,))
        return self.cursor.fetchone()

    def update_password(self, email, new_password=None):
        """Update password."""
        account = self.find_account_by_email(email)
        if not account:
            print("Account does not exist!")
            return False

        if not new_password:
            new_password = generate_password()

        password_encrypted = encrypt_password(new_password, self.encryption_key)
        self.cursor.execute(
            "UPDATE accounts SET password_encrypted = ? WHERE email = ?",
            (password_encrypted, email),
        )
        self.conn.commit()
        print(f"Password updated successfully! New password: {new_password}")
        return True

    def delete_account_by_email(self, email):
        """Delete an account by email."""
        if not self.find_account_by_email(email):
            print("Account does not exist!")
            return False

        self.cursor.execute("DELETE FROM accounts WHERE email = ?", (email,))
        self.conn.commit()
        print("Account deleted successfully!")
        return True

    def delete_account_by_id(self, account_id):
        """Delete an account by ID."""
        if not self.find_account_by_id(account_id):
            print("Account does not exist!")
            return False

        self.cursor.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        self.conn.commit()
        print("Account deleted successfully!")
        return True

    def list_accounts(self, show_passwords=False):
        """List all accounts."""
        self.cursor.execute("SELECT * FROM accounts")
        accounts = self.cursor.fetchall()
        if not accounts:
            print("No accounts found.")
            return

        for account in accounts:
            (
                account_id,
                email,
                password_encrypted,
                github_username,
                twitter_username,
                twitter_password_encrypted,
            ) = account
            password_display = "******"  # Default hidden password
            twitter_password_display = "******"  # Default hidden Twitter password
            if show_passwords:
                if not self.master_password_hash:
                    print("Please set a master password to view passwords!")
                    return
                # Decrypt the email password
                try:
                    password_display = decrypt_password(
                        password_encrypted, self.encryption_key
                    )
                except Exception as e:
                    password_display = "[Decryption failed]"
                # Decrypt the Twitter password
                if twitter_username:
                    try:
                        twitter_password_display = (
                            decrypt_password(
                                twitter_password_encrypted, self.encryption_key
                            )
                            if twitter_password_encrypted
                            else password_display  # Use email password if Twitter password is not set
                        )
                    except Exception as e:
                        twitter_password_display = "[Decryption failed]"
            print(
                f"ID: {account_id}, Email: {email}, Password: {password_display}, "
                f"GitHub: {github_username or 'Not set'}, "
                f"Twitter: {twitter_username or 'Not set'}, "
                f"Twitter Password: {twitter_password_display if twitter_username else 'N/A'}"
            )

    def update_github_username(self, email, github_username):
        """Update GitHub username."""
        if not self.find_account_by_email(email):
            print("Account does not exist!")
            return False

        self.cursor.execute(
            "UPDATE accounts SET github_username = ? WHERE email = ?",
            (github_username, email),
        )
        self.conn.commit()
        print(f"GitHub username updated to: {github_username}")
        return True

    def update_twitter_username(self, email, twitter_username):
        """Update Twitter username."""
        if not self.find_account_by_email(email):
            print("Account does not exist!")
            return False

        self.cursor.execute(
            "UPDATE accounts SET twitter_username = ? WHERE email = ?",
            (twitter_username, email),
        )
        self.conn.commit()
        print(f"Twitter username updated to: {twitter_username}")
        return True

    def update_twitter_password(self, email, twitter_password=None):
        """Update Twitter password."""
        if not self.find_account_by_email(email):
            print("Account does not exist!")
            return False

        if not twitter_password:
            twitter_password = generate_password()

        twitter_password_encrypted = encrypt_password(
            twitter_password, self.encryption_key
        )
        self.cursor.execute(
            "UPDATE accounts SET twitter_password_encrypted = ? WHERE email = ?",
            (twitter_password_encrypted, email),
        )
        self.conn.commit()
        print(
            f"Twitter password updated successfully! New password: {twitter_password}"
        )
        return True

    def close(self):
        """Close database connection."""
        self.conn.close()


# Helper function to handle 'q' input
def get_input(prompt):
    """Get user input and handle 'q' to return to the main menu."""
    user_input = input(prompt).strip()
    if user_input.lower() == "q":
        return None
    return user_input


# Main menu
def main_menu():
    db_name = select_or_create_database()
    if not db_name:
        print("No database selected. Exiting...")
        return

    initialize_db(db_name)
    manager = EmailAccountManager(db_name)

    while True:
        print("\nEmail Account Management System")
        print("1. Add a new account")
        print("2. Find an account by email")
        print("3. Update email password")
        print("4. Delete an account by email")
        print("5. Delete an account by ID")
        print("6. List all accounts")
        print("7. Update GitHub username")
        print("8. Update Twitter username")
        print("9. Update Twitter password")
        print("10. Change master password")
        print("11. Exit")

        choice = get_input("Choose an option (1-11, or 'q' to quit): ")
        if choice is None:
            print("Returning to main menu...")
            continue

        if choice == "1":
            email = get_input("Enter email address (or 'q' to return): ")
            if email is None:
                continue
            if "@" not in email:
                print("Invalid email format!")
                continue
            github_username = (
                get_input(
                    "Enter associated GitHub username (optional, or 'q' to return): "
                )
                or None
            )
            if github_username is None:
                continue
            twitter_username = (
                get_input(
                    "Enter associated Twitter username (optional, or 'q' to return): "
                )
                or None
            )
            if twitter_username is None:
                continue
            if twitter_username:
                twitter_password = (
                    getpass.getpass(
                        "Enter Twitter password (optional, default to email password, or 'q' to return): "
                    )
                    or None
                )
                if twitter_password is None:
                    continue
            else:
                twitter_password = None
            manager.add_account(
                email, github_username, twitter_username, twitter_password
            )

        elif choice == "2":
            email = get_input("Enter email to search (or 'q' to return): ")
            if email is None:
                continue
            account = manager.find_account_by_email(email)
            if account:
                (
                    account_id,
                    email,
                    password_encrypted,
                    github_username,
                    twitter_username,
                    twitter_password_encrypted,
                ) = account
                print(
                    f"Account found: ID {account_id}, Email {email}, "
                    f"GitHub: {github_username or 'Not set'}, "
                    f"Twitter: {twitter_username or 'Not set'}"
                )
            else:
                print("Account not found!")

        elif choice == "3":
            email = get_input("Enter email to update password (or 'q' to return): ")
            if email is None:
                continue
            action = get_input(
                "Generate a new password automatically? (y/n, or 'q' to return): "
            )
            if action is None:
                continue
            if action.lower() == "y":
                manager.update_password(email)
            elif action.lower() == "n":
                new_pwd = getpass.getpass("Enter new password (or 'q' to return): ")
                if new_pwd is None:
                    continue
                manager.update_password(email, new_pwd)
            else:
                print("Invalid input!")

        elif choice == "4":
            email = get_input("Enter email to delete (or 'q' to return): ")
            if email is None:
                continue
            manager.delete_account_by_email(email)

        elif choice == "5":
            account_id = get_input("Enter account ID to delete (or 'q' to return): ")
            if account_id is None:
                continue
            if account_id.isdigit():
                manager.delete_account_by_id(int(account_id))
            else:
                print("Invalid account ID!")

        elif choice == "6":
            master_pwd = getpass.getpass(
                "Enter master password to view all account passwords (or 'q' to return): "
            )
            if master_pwd is None:
                continue
            if manager.verify_master_password(master_pwd):
                print("\nAll accounts:")
                manager.list_accounts(show_passwords=True)
            else:
                print("Incorrect master password!")

        elif choice == "7":
            email = get_input(
                "Enter email to update GitHub username (or 'q' to return): "
            )
            if email is None:
                continue
            github_username = get_input(
                "Enter new GitHub username (or 'q' to return): "
            )
            if github_username is None:
                continue
            manager.update_github_username(email, github_username)

        elif choice == "8":
            email = get_input(
                "Enter email to update Twitter username (or 'q' to return): "
            )
            if email is None:
                continue
            twitter_username = get_input(
                "Enter new Twitter username (or 'q' to return): "
            )
            if twitter_username is None:
                continue
            manager.update_twitter_username(email, twitter_username)

        elif choice == "9":
            email = get_input(
                "Enter email to update Twitter password (or 'q' to return): "
            )
            if email is None:
                continue
            action = get_input(
                "Generate a new password automatically? (y/n, or 'q' to return): "
            )
            if action is None:
                continue
            if action.lower() == "y":
                manager.update_twitter_password(email)
            elif action.lower() == "n":
                new_pwd = getpass.getpass(
                    "Enter new Twitter password (or 'q' to return): "
                )
                if new_pwd is None:
                    continue
                manager.update_twitter_password(email, new_pwd)
            else:
                print("Invalid input!")

        elif choice == "10":
            manager.change_master_password()

        elif choice == "11":
            manager.close()
            print("Exiting the system...")
            break

        else:
            print("Invalid option, please try again!")


if __name__ == "__main__":
    main_menu()
