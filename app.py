import streamlit as st
import json
import os
import time
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac
import base64

# ----------------- UTILITY FUNCTIONS ------------------ #
# Generate and load Fernet key
def load_key():
    if os.path.exists("fernet.key"):
        with open("fernet.key", "rb") as file:
            return file.read()
    else:
        key = Fernet.generate_key()
        with open("fernet.key", "wb") as file:
            file.write(key)
        return key

cipher = Fernet(load_key())

# Load/Save JSON files
def load_json(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            return json.load(f)
    return {}

def save_json(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

# PBKDF2 Hashing (more secure)
def hash_passkey(passkey, salt=b'streamlit_salt'):
    hashed = pbkdf2_hmac('sha256', passkey.encode(), salt, 100000)
    return base64.b64encode(hashed).decode()

# ----------------- STATE SETUP ------------------ #
if "user" not in st.session_state:
    st.session_state.user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0
if "login_time" not in st.session_state:
    st.session_state.login_time = None

users = load_json("users.json")
data = load_json("data.json")

# ----------------- MAIN UI ------------------ #
st.set_page_config(page_title="Secure Data System", page_icon="🔒")
st.title("Advanced Secure Data Encryption System")

# --- User Profile --- (Sidebar)
if st.session_state.user:
    st.sidebar.markdown(f"Hello, {st.session_state.user}")
else:
    st.sidebar.markdown("Not logged in")

# --- Sidebar Navigation ---
menu = ["Home", "Store Data", "Retrieve Data"]
if st.session_state.user:
    menu += ["Change Password", "Activity Log", "Logout"]
else:
    menu += ["Login", "Signup"]

choice = st.sidebar.selectbox("Navigation", menu)

# ----------------- SIGNUP ------------------ #
if choice == "Signup":
    st.subheader("Create New Account")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")
    if st.button("Register"):
        if new_user in users:
            st.error("User already exists.")
        else:
            users[new_user] = hash_passkey(new_pass)
            save_json("users.json", users)
            st.success("Account created! You can now log in.")

# ----------------- LOGIN ------------------ #
elif choice == "Login":
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if time.time() < st.session_state.lockout_time:
            st.warning("Too many attempts. Try again later.")
        elif username in users and users[username] == hash_passkey(password):
            st.session_state.user = username
            st.session_state.failed_attempts = 0
            st.session_state.login_time = time.time()
            st.success(f"Welcome, {username}!")
        else:
            st.session_state.failed_attempts += 1
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + 30  # 30 seconds lock
                st.warning("Locked out for 30 seconds.")
            else:
                st.error("Invalid credentials.")

# ----------------- CHANGE PASSWORD ------------------ #
elif choice == "Change Password":
    if st.session_state.user:
        st.subheader("Change Your Password")
        old_pass = st.text_input("Enter Old Password", type="password")
        new_pass = st.text_input("Enter New Password", type="password")
        confirm_pass = st.text_input("Confirm New Password", type="password")

        if st.button("Change Password"):
            if new_pass == confirm_pass:
                if users.get(st.session_state.user) == hash_passkey(old_pass):
                    users[st.session_state.user] = hash_passkey(new_pass)
                    save_json("users.json", users)
                    st.success("Password successfully changed!")
                else:
                    st.error("Incorrect old password.")
            else:
                st.error("New passwords don't match.")
    else:
        st.warning("Please log in to change your password.")

# ----------------- ACTIVITY LOG ------------------ #
elif choice == "Activity Log":
    if st.session_state.user:
        st.subheader("Your Activity Log")
        st.write(f"Last login: {time.ctime(st.session_state.login_time)}")
    else:
        st.warning("Please log in to view your activity log.")

# ----------------- STORE DATA ------------------ #
elif choice == "Store Data":
    if st.session_state.user:
        st.subheader("Store Encrypted Data")
        text = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Enter a secret passkey", type="password")

        if st.button("Encrypt & Store"):
            if text and passkey:
                enc = cipher.encrypt(text.encode()).decode()
                hashed = hash_passkey(passkey)
                user_data = data.get(st.session_state.user, [])
                user_data.append({"encrypted": enc, "passkey": hashed})
                data[st.session_state.user] = user_data
                save_json("data.json", data)
                st.success("Data stored securely!")
                st.code(enc)
            else:
                st.error("All fields are required.")
    else:
        st.warning("Please login first.")

# ----------------- RETRIEVE DATA ------------------ #
elif choice == "Retrieve Data":
    if st.session_state.user:
        st.subheader("Retrieve Your Data")
        encrypted = st.text_area("Paste your encrypted text:")
        passkey = st.text_input("Enter your passkey", type="password")

        if st.button("Decrypt"):
            found = False
            user_data = data.get(st.session_state.user, [])
            for entry in user_data:
                if entry["encrypted"] == encrypted and entry["passkey"] == hash_passkey(passkey):
                    decrypted = cipher.decrypt(encrypted.encode()).decode()
                    st.success("Decrypted Data:")
                    st.code(decrypted)
                    found = True
                    break
            if not found:
                st.error("Incorrect passkey or data.")
    else:
        st.warning("Please login first.")

# ----------------- LOGOUT ------------------ #
elif choice == "Logout":
    st.session_state.user = None
    st.session_state.failed_attempts = 0
    st.session_state.lockout_time = 0
    st.session_state.login_time = None
    st.success("You have been logged out.")
    st.rerun()
