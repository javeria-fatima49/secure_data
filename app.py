import streamlit as st
import hashlib
import json
import os
import time
import base64
from cryptography.fernet import Fernet
from datetime import datetime

DATA_FILE = "data.json"
KEY_FILE = "secret.key"

# Load or generate a persistent encryption key
def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

KEY = load_key()
cipher = Fernet(KEY)

def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def hash_passkey_pbkdf2(passkey, salt=None):
    if not salt:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac("sha256", passkey.encode(), salt, 100000)
    return base64.b64encode(salt).decode(), base64.b64encode(hashed).decode()

def validate_credentials(username, passkey):
    if not username or not passkey:
        return False, "Username and passkey cannot be empty."
    if len(passkey) < 8:
        return False, "Passkey must be at least 8 characters long."
    if not username.isalnum():
        return False, "Username must be alphanumeric."
    return True, ""

def register_user(username, passkey):
    if username in stored_data:
        return False, "🚫 User already exists."

    valid, msg = validate_credentials(username, passkey)
    if not valid:
        return False, msg

    salt, passkey_hash = hash_passkey_pbkdf2(passkey)
    stored_data[username] = {
        "salt": salt,
        "passkey_hash": passkey_hash,
        "data": [],
        "attempts": 0,
        "lock_time": None
    }
    save_data(stored_data)
    return True, "✅ Registered successfully!"

def login_user(username, passkey):
    user = stored_data.get(username)
    if not user:
        return False, "🚫 User not found."

    # Time-based lock
    if user["lock_time"]:
        if time.time() < user["lock_time"]:
            remaining = int(user["lock_time"] - time.time())
            return False, f"🔒 Account locked. Try again in {remaining} seconds."
        else:
            user["attempts"] = 0
            user["lock_time"] = None

    salt = base64.b64decode(user["salt"])
    _, hashed = hash_passkey_pbkdf2(passkey, salt)

    if hashed == user["passkey_hash"]:
        user["attempts"] = 0
        save_data(stored_data)
        return True, "✅ Login successful!"
    else:
        user["attempts"] += 1
        if user["attempts"] >= 3:
            user["lock_time"] = time.time() + 60 * (2 ** (user["attempts"] - 3))  # Exponential backoff
        save_data(stored_data)
        attempts_left = max(0, 3 - user["attempts"])
        return False, f"❌ Incorrect passkey! Attempts left: {attempts_left}"

def store_user_data(username, text):
    encrypted_text = cipher.encrypt(text.encode()).decode()
    stored_data[username]["data"].append({
        "encrypted": encrypted_text,
        "timestamp": datetime.now().isoformat()
    })
    save_data(stored_data)
    return encrypted_text

def retrieve_user_data(username, encrypted_text):
    user_data = stored_data.get(username, {}).get("data", [])
    for item in user_data:
        if item["encrypted"] == encrypted_text:
            try:
                decrypted = cipher.decrypt(encrypted_text.encode()).decode()
                return decrypted
            except Exception as e:
                st.error(f"❌ Decryption failed: {e}")
                return None
    return None

def reset_passkey(username, new_passkey):
    valid, msg = validate_credentials(username, new_passkey)
    if not valid:
        return False, msg

    salt, passkey_hash = hash_passkey_pbkdf2(new_passkey)
    stored_data[username]["salt"] = salt
    stored_data[username]["passkey_hash"] = passkey_hash
    save_data(stored_data)
    return True, "✅ Passkey reset successfully!"

# Streamlit app configuration
st.set_page_config(page_title="Secure Vault", layout="centered")
st.title("🔐 Secure Data Encryption System")

# Initialize session state
if "current_user" not in st.session_state:
    st.session_state.current_user = None

# Load stored data
stored_data = load_data()

# Menu for logged-out users
if not st.session_state.current_user:
    menu = ["Home", "Register", "Login", "Reset Passkey"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Home":
        st.subheader("🏠 Welcome to Secure Vault")
        st.markdown("""
        **🔐 Secure Data Encryption System** is your trusted solution for storing and retrieving sensitive information securely. 
        With state-of-the-art encryption and robust user authentication, your data is safe with us.

        ### ✨ Key Features
        - **Secure Registration & Login**: Create an account with a strong passkey and log in securely.
        - **Data Encryption**: Store your text data with military-grade encryption.
        - **Easy Retrieval**: Access your encrypted data anytime, anywhere.
        - **Passkey Reset**: Update your passkey securely if needed.
        - **Account Lockout**: Protection against unauthorized access with a smart lockout system.

        ### 🚀 Get Started
        1. **Register** a new account to begin.
        2. **Log in** to store or retrieve your encrypted data.
        3. Explore the **Store Data** and **Retrieve Data** tabs to manage your information securely.

        Ready to protect your data? Head to the **Register** or **Login** tab in the sidebar to start!
        """)
        st.markdown("---")
        st.info("💡 **Tip**: Use a strong passkey (minimum 8 characters) to ensure maximum security.")

    elif choice == "Register":
        st.subheader("📝 Register")
        with st.form("register_form"):
            new_user = st.text_input("Choose Username")
            new_pass = st.text_input("Choose Passkey", type="password")
            submit = st.form_submit_button("Register")
            if submit:
                if new_user and new_pass:
                    success, msg = register_user(new_user, new_pass)
                    if success:
                        st.success(msg)
                        st.session_state.register_form_clear = True
                    else:
                        st.error(msg)
                else:
                    st.warning("Fill in all fields.")

    elif choice == "Login":
        st.subheader("🔑 Login")
        with st.form("login_form"):
            user = st.text_input("Username")
            passwd = st.text_input("Passkey", type="password")
            submit = st.form_submit_button("Login")
            if submit:
                if user and passwd:
                    success, msg = login_user(user, passwd)
                    if success:
                        st.session_state.current_user = user
                        st.success(msg)
                        st.session_state.login_form_clear = True
                    else:
                        st.error(msg)
                else:
                    st.warning("Enter both fields.")

    elif choice == "Reset Passkey":
        st.subheader("🔑 Reset Passkey")
        with st.form("reset_form"):
            user = st.text_input("Username")
            new_pass = st.text_input("New Passkey", type="password")
            submit = st.form_submit_button("Reset Passkey")
            if submit:
                if user and new_pass:
                    if user in stored_data:
                        success, msg = reset_passkey(user, new_pass)
                        if success:
                            st.success(msg)
                            st.session_state.reset_form_clear = True
                        else:
                            st.error(msg)
                    else:
                        st.error("User not found.")
                else:
                    st.warning("Please fill in both fields.")

# Menu for logged-in users
else:
    st.success(f"👋 Welcome, {st.session_state.current_user}")
    tab = st.sidebar.selectbox("Menu", ["Store Data", "Retrieve Data", "View All My Saved Entries" , "Logout"])

    if tab == "Store Data":
        st.subheader("🔒 Store Data")
        with st.form("store_form"):
            plain = st.text_area("Enter text to encrypt:")
            submit = st.form_submit_button("Encrypt & Save")
            if submit:
                if plain:
                    encrypted = store_user_data(st.session_state.current_user, plain)
                    st.success("🔒 Encrypted & Saved:")
                    st.code(encrypted)
                    st.session_state.store_form_clear = True
                else:
                    st.warning("Text field is empty.")

    elif tab == "Retrieve Data":
        st.subheader("🔓 Retrieve Data")
        user_data = stored_data.get(st.session_state.current_user, {}).get("data", [])
        if user_data:
            encrypted_options = [f"{entry['encrypted']} ({entry['timestamp']})" for entry in user_data]
            selected = st.selectbox("Select encrypted text:", encrypted_options)
            encrypted_text = selected.split(" (")[0]
            if st.button("Decrypt"):
                decrypted = retrieve_user_data(st.session_state.current_user, encrypted_text)
                if decrypted:
                    st.success("🔓 Decrypted Data:")
                    st.code(decrypted)
                else:
                    st.error("❌ No match found.")
        else:
            st.warning("No saved entries found.")

    elif tab == "View All My Saved Entries":
        st.subheader("📜 Your Saved Entries")
        user_data = stored_data.get(st.session_state.current_user, {}).get("data", [])
        if user_data:
            for entry in user_data:
                st.write(f"🔑 Encrypted: {entry['encrypted']}")
                st.write(f"🕒 Timestamp: {entry['timestamp']}")
                st.markdown("---")
        else:
            st.warning("No saved entries found.")

    # Logout button
    if tab == "Logout":
        st.session_state.current_user = None
        st.success("You have successfully logged out.")
        st.rerun()