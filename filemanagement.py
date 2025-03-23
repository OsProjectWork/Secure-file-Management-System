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
def generate_key(password: str):
    key = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key)

# Function to securely delete files
def secure_delete(filepath):
    try:
        with open(filepath, "ba+") as f:
            length = f.tell()
            f.seek(0)
            f.write(os.urandom(length))
        os.remove(filepath)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to securely delete file: {e}")

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

# Function to decrypt files
def decrypt_file(filepath, key):
    try:
        cipher = Fernet(key)
        with open(filepath, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = cipher.decrypt(encrypted_data)
        decrypted_filepath = filepath.replace(".enc", "")
        with open(decrypted_filepath, "wb") as f:
            f.write(decrypted_data)
        return decrypted_filepath
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt file: {e}")

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

# Validate email format
def is_valid_email(email):
    return re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(com|in)$", email)

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

# User logout function
def logout_user():
    global session_key
    session_key = None
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    email_entry.delete(0, tk.END)
    messagebox.showinfo("Logout", "You have been logged out!")

# Function to upload and encrypt a file
def upload_and_encrypt():
    if not session_key:
        messagebox.showerror("Error", "Please log in first!")
        return
    filepath = filedialog.askopenfilename()
    if filepath:
        encrypted_filepath = encrypt_file(filepath, session_key)
        if encrypted_filepath:
            messagebox.showinfo("Success", f"File encrypted: {encrypted_filepath}")

