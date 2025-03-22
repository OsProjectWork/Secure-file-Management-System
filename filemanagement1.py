import os
import json
import base64
import hashlib
import re
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet

# Directory for storing secure files
UPLOAD_FOLDER = "secure_files"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
USER_DATA_FILE = "users.json"
session_key = None  # Session key for encryption/decryption

# Function to generate encryption key from password


# Function to encrypt files
def encrypt_file(filepath, key):
    try:
        cipher = Fernet(key)
        with open(filepath, "rb") as f:
            data = f.read()
        encrypted_data = cipher.encrypt(data)
        encrypted_filepath = filepath + ".enc"
        with open(encrypted_filepath, "wb") as f:
            f.write(encrypted_data)
        secure_delete(filepath)
        return encrypted_filepath
    except Exception as e:
        messagebox.showerror("Error", f"Failed to encrypt file: {e}")


# Load user data from JSON file
def load_users():
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# Save user data to JSON file
def save_users(users):
    with open(USER_DATA_FILE, "w") as f:
        json.dump(users, f)




# User registration function
def register_user():
    username = username_entry.get()
    password = password_entry.get()
    email = email_entry.get()
    
    if not is_valid_email(email):
        messagebox.showerror("Error", "Invalid email format! Email must end with @ and .com or .in")
        return
    
    users = load_users()
    if username in users:
        messagebox.showerror("Error", "Username already exists!")
        return
    users[username] = {"password": hashlib.sha256(password.encode()).hexdigest(), "email": email}
    save_users(users)
    messagebox.showinfo("Success", "User registered successfully!")

# User login function
def login_user():
    global session_key
    username = username_entry.get()
    password = password_entry.get()
    users = load_users()
    if username in users and users[username]["password"] == hashlib.sha256(password.encode()).hexdigest():
        session_key = generate_key(password)
        messagebox.showinfo("Success", "Login successful!")
    else:
        messagebox.showerror("Error", "Invalid credentials!")



