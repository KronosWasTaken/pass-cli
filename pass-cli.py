import os
import sqlite3
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import secrets
import string
from cryptography.fernet import Fernet, InvalidToken
import base64
import getpass
import keyring
import time

MAX_ATTEMPTS = 5
LOCK_TIME = 60

login_attempts = {}

DB_PATH = "password_manager.db"

SALT_KEY_SERVICE = "PasswordManager"
SALT_KEY_USERNAME = "SaltKey"


def save_salt_key():
    key = Fernet.generate_key()
    keyring.set_password(SALT_KEY_SERVICE, SALT_KEY_USERNAME, key.decode())


def load_salt_key():
    key = keyring.get_password(SALT_KEY_SERVICE, SALT_KEY_USERNAME)
    if key is None:
        save_salt_key()
        key = keyring.get_password(SALT_KEY_SERVICE, SALT_KEY_USERNAME)
    return key.encode()


SALT_KEY = load_salt_key()


def create_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS master (
                id INTEGER PRIMARY KEY,
                encrypted_salt TEXT NOT NULL,
                encrypted_key TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                encrypted_item_name TEXT NOT NULL,
                encrypted_data TEXT NOT NULL
            )
        """)
        conn.commit()


def generator(length=12):
    new_punctuation = ["!", "@", "#", "$", "%", "^", "&", "*"]
    punctuation = new_punctuation
    digits = string.digits
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase

    chars = list(punctuation) + list(digits) + list(uppercase) + list(lowercase)

    generated_password = [
        secrets.choice(digits),
        secrets.choice(uppercase),
        secrets.choice(lowercase)
    ]

    for _ in range(length - 3):
        generated_password.append(secrets.choice(chars))

    return "".join(generated_password)


def check_password(password):
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)

    if len(password) < 12:
        print("At least 12 characters long but 14 or more is better.")
        return False

    if not has_lower or not has_upper:
        print("At least one uppercase and one lowercase letter")
        return False

    if not has_digit:
        print("At least one numeral")
        return False

    return True


def argon2(password, salt):
    # Derive key using Argon2id
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=4,
        lanes=4,
        memory_cost=64 * 1024,
        ad=None,
        secret=None,
    )

    key = kdf.derive(password.encode("utf-8"))
    fernet_key = base64.urlsafe_b64encode(key)

    # Verify the key
    kdf_verify = Argon2id(
        salt=salt,
        length=32,
        iterations=4,
        lanes=4,
        memory_cost=64 * 1024,
        ad=None,
        secret=None,
    )

    try:
        kdf_verify.verify(password.encode("utf-8"), key)
        return fernet_key
    except Exception as e:
        print("Password verification failed:", str(e))
        return None


def encrypt_salt(salt):
    return Fernet(SALT_KEY).encrypt(salt).decode()


def decrypt_salt(encrypted_salt):
    return Fernet(SALT_KEY).decrypt(encrypted_salt.encode())


def save_master_password(password):
    salt = os.urandom(16)
    encrypted_salt = encrypt_salt(salt)

    key = argon2(password, salt)
    cipher = Fernet(key)
    encrypted_key = cipher.encrypt(key).decode()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO master (encrypted_salt, encrypted_key) VALUES (?, ?)",
                       (encrypted_salt, encrypted_key))
        conn.commit()
    print("Master password set successfully.")


def load_master_key(password):
    username = "user"
    current_time = time.time()

    if username in login_attempts:
        user_attempts = login_attempts[username]
        if user_attempts['failed_attempts'] >= MAX_ATTEMPTS:
            last_failed_time = user_attempts['last_failed_time']
            lock_time_remaining = user_attempts['lock_time'] - (current_time - last_failed_time)

            if lock_time_remaining > 0:
                print(f"Too many failed attempts. Try again in {lock_time_remaining:.0f} seconds.")
                time.sleep(1)
                return None
            else:
                user_attempts['failed_attempts'] = 0
                user_attempts['last_failed_time'] = 0
                print("You can now try to login again.")
                user_attempts['lock_time'] *= 2
    else:
        login_attempts[username] = {'failed_attempts': 0, 'last_failed_time': 0, 'lock_time': LOCK_TIME}

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_salt, encrypted_key FROM master LIMIT 1")
        result = cursor.fetchone()

        if result:
            encrypted_salt, encrypted_key = result
            try:
                salt = decrypt_salt(encrypted_salt)
                master_key = argon2(password, salt)
                cipher = Fernet(master_key)
                decrypted_key = cipher.decrypt(encrypted_key.encode())
                return decrypted_key
            except InvalidToken:
                print("Incorrect master password. Please try again.")
                login_attempts[username]['failed_attempts'] += 1
                login_attempts[username]['last_failed_time'] = current_time
                return None
        else:
            print("Master password not set.")
            return None


def save_app_creds(item_name, username, login_password, key):
    cipher = Fernet(key)
    encrypted_item_name = cipher.encrypt(item_name.encode()).decode()
    encrypted_data = cipher.encrypt(f"{username},{login_password}".encode()).decode()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO credentials (encrypted_item_name, encrypted_data) VALUES (?, ?)",
                       (encrypted_item_name, encrypted_data))
        conn.commit()
    print(f"Credentials for '{item_name}' saved successfully.")


def show_app_creds(key):
    cipher = Fernet(key)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_item_name, encrypted_data FROM credentials")
        rows = cursor.fetchall()

        if not rows:
            print("No stored credentials found.")
            return

        for row in rows:
            encrypted_item_name, encrypted_data = row
            try:
                decrypted_item_name = cipher.decrypt(encrypted_item_name.encode()).decode()
                decrypted_data = cipher.decrypt(encrypted_data.encode()).decode()
                username, password = decrypted_data.split(',')
                print(f"Item Name: {decrypted_item_name}, Username: {username}, Password: {password}")
            except InvalidToken:
                print("Error decrypting a record. It might be corrupted.")


def search_db(master_key, search):
    cipher = Fernet(master_key)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_item_name, encrypted_data FROM credentials")
        rows = cursor.fetchall()

        for encrypted_item_name, encrypted_data in rows:
            try:
                decrypted_item_name = cipher.decrypt(encrypted_item_name.encode()).decode()
            except InvalidToken:
                continue

            if search.lower() in decrypted_item_name.lower():
                try:
                    decrypted_data = cipher.decrypt(encrypted_data.encode()).decode()
                    username, password = decrypted_data.split(',')
                    print(f"Item Name: {decrypted_item_name}, Username: {username}, Password: {password}")
                except InvalidToken:
                    print(f"Error: Could not decrypt data for '{decrypted_item_name}'.")


def change_master_password(old_password, new_password):
    old_master_key = load_master_key(old_password)
    if not old_master_key:
        return False

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, encrypted_item_name, encrypted_data FROM credentials")
        rows = cursor.fetchall()

        new_master_key = argon2(new_password, os.urandom(16))
        cipher_new = Fernet(new_master_key)
        cipher_old = Fernet(old_master_key)
        for row in rows:
            row_id, encrypted_item_name, encrypted_data = row
            try:
                decrypted_item_name = cipher_old.decrypt(encrypted_item_name.encode()).decode()
                decrypted_data = cipher_old.decrypt(encrypted_data.encode()).decode()
                username, login_password = decrypted_data.split(',')
            except Exception as e:
                print("Error re-encrypting a record:", e)
                continue

            new_encrypted_item_name = cipher_new.encrypt(decrypted_item_name.encode()).decode()
            new_encrypted_data = cipher_new.encrypt(f"{username},{login_password}".encode()).decode()
            cursor.execute("""
                UPDATE credentials
                SET encrypted_item_name = ?, encrypted_data = ?
                WHERE id = ?
            """, (new_encrypted_item_name, new_encrypted_data, row_id))

        save_master_password(new_password)
        conn.commit()
        print("Master password and all credentials re-encrypted successfully.")
        return True


def modify_app_item(key):
    cipher = Fernet(key)
    item_to_modify = input("Enter the name of the app/site you wish to modify: ")
    found = False

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, encrypted_item_name, encrypted_data FROM credentials")
        rows = cursor.fetchall()

        for row in rows:
            row_id, encrypted_item_name, encrypted_data = row
            try:
                decrypted_item_name = cipher.decrypt(encrypted_item_name.encode()).decode()
            except InvalidToken:
                continue

            if decrypted_item_name.lower() == item_to_modify.lower():
                found = True
                action = input("Enter 'update' to update the password or 'delete' to remove this credential: ").lower()
                if action == 'update':
                    try:
                        decrypted_data = cipher.decrypt(encrypted_data.encode()).decode()
                        username, old_password = decrypted_data.split(',')
                    except InvalidToken:
                        print("Failed to decrypt data for this item. Skipping.")
                        continue
                    print(f"Found credentials for '{decrypted_item_name}'. Username: {username}")
                    new_password = getpass.getpass("Enter new password for this item: ")
                    new_encrypted_data = cipher.encrypt(f"{username},{new_password}".encode()).decode()
                    cursor.execute("UPDATE credentials SET encrypted_data = ? WHERE id = ?", (new_encrypted_data, row_id))
                    conn.commit()
                    print(f"Password for '{decrypted_item_name}' updated successfully.")
                elif action == 'delete':
                    confirm = input(f"Are you sure you want to delete credentials for '{decrypted_item_name}'? (yes/no): ")
                    if confirm.lower() == "yes" or "y":
                        cursor.execute("DELETE FROM credentials WHERE id = ?", (row_id,))
                        conn.commit()
                        print(f"Credentials for '{decrypted_item_name}' have been deleted.")
                    else:
                        print("Deletion cancelled.")
                else:
                    print("Invalid action. No changes made.")
                break

    if not found:
        print("No credentials found with that app/site name.")


def main():
    create_db()
    master_password_set = False
    master_key = None

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM master")
        if cursor.fetchone()[0] > 0:
            master_password_set = True

    if master_password_set:
        print("Master password found. Please enter it to unlock.")
        while True:
            password = getpass.getpass("Enter master password: ")
            master_key = load_master_key(password)
            if master_key:
                print("Master password verified.")
                break

    while True:
        print("\n--- Password Manager Menu ---")
        print("1. Generate Random Password")
        print("2. Set Master Password")
        print("3. Save App Credentials")
        print("4. Show App Credentials")
        print("5. Search Item")
        print("6. Change Master Password")
        print("7. Modify an App's Credentials (Update/Delete)")
        print("8. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            length = None
            while True:
                try:
                    length = int(input("Enter the length of password (12-96 characters): "))
                except ValueError:
                    print("Please enter a valid number.")
                    continue
                if 12 <= length <= 96:
                    break
                else:
                    print("Please enter the length of password between 12-96 characters.")
            print("Generated Password: ", generator(length))

        elif choice == "2":
            if master_password_set:
                print("Master password already set.")
                continue
            password = getpass.getpass("Enter a master password: ")
            if check_password(password):
                save_master_password(password)
                master_password_set = True
                master_key = load_master_key(password)
            else:
                print("Password invalid. Please try again.")

        elif choice == "3":
            if not master_password_set or not master_key:
                print("Please unlock the master password first.")
                continue
            item_name = input("Enter the name of the app or site: ")
            username = input("Enter username: ")
            login_password = getpass.getpass("Enter password: ")
            save_app_creds(item_name, username, login_password, master_key)

        elif choice == "4":
            if not master_password_set or not master_key:
                print("Please unlock the master password first.")
                continue
            show_app_creds(master_key)

        elif choice == "5":
            if not master_password_set or not master_key:
                print("Please unlock the master password first.")
                continue
            search = input("Enter item name to search: ")
            search_db(master_key, search)

        elif choice == "6":
            if not master_password_set or not master_key:
                print("Please unlock the master password first.")
                continue
            old_password = getpass.getpass("Enter current master password: ")
            new_password = getpass.getpass("Enter new master password: ")
            if check_password(new_password):
                if change_master_password(old_password, new_password):
                    master_key = load_master_key(new_password)
                    print("Master password changed successfully.")
                else:
                    print("Failed to change master password.")
            else:
                print("New password is invalid. Please try again.")

        elif choice == "7":
            if not master_password_set or not master_key:
                print("Please unlock the master password first.")
                continue
            modify_app_item(master_key)

        elif choice == "8":
            break

        else:
            print("Invalid choice. Please choose again.")


if __name__ == '__main__':
    main()
