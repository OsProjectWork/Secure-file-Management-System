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

# Function to decrypt and download a file
def decrypt_and_download():
    if not session_key:
        messagebox.showerror("Error", "Please log in first!")
        return
    filepath = filedialog.askopenfilename()
    if filepath and filepath.endswith(".enc"):
        decrypted_filepath = decrypt_file(filepath, session_key)
        if decrypted_filepath:
            messagebox.showinfo("Success", f"File decrypted: {decrypted_filepath}")

# GUI setup
root = tk.Tk()
root.title("Secure File Management System")
root.geometry("600x700")
root.configure(bg="#1E1E1E")

main_frame = tk.Frame(root, padx=10, pady=10, bg="#1E1E1E")
main_frame.pack(fill=tk.BOTH, expand=True)

tk.Label(main_frame, text="Secure File Manager", font=("Arial", 18, "bold"), fg="#61AFEF", bg="#1E1E1E").pack(pady=10)

# Authentication frame
auth_frame = tk.LabelFrame(main_frame, text="User Authentication", fg="#ABB2BF", bg="#3E4451", padx=10, pady=10)
auth_frame.pack(fill=tk.X, pady=10)

tk.Label(auth_frame, text="Username:", fg="white", bg="#3E4451").pack()
username_entry = tk.Entry(auth_frame, bg="#ABB2BF")
username_entry.pack()

tk.Label(auth_frame, text="Password:", fg="white", bg="#3E4451").pack()
password_entry = tk.Entry(auth_frame, show="*", bg="#ABB2BF")
password_entry.pack()

tk.Label(auth_frame, text="Email:", fg="white", bg="#3E4451").pack()
email_entry = tk.Entry(auth_frame, bg="#ABB2BF")
email_entry.pack()

tk.Button(auth_frame, text="Register", command=register_user, bg="#61AFEF", fg="white").pack(pady=5)
tk.Button(auth_frame, text="Login", command=login_user, bg="#98C379", fg="white").pack()

# File encryption and decryption buttons
tk.Button(main_frame, text="Encrypt File", command=upload_and_encrypt, bg="#E06C75", fg="white").pack(pady=5)
tk.Button(main_frame, text="Decrypt File", command=decrypt_and_download, bg="#C678DD", fg="white").pack(pady=5)
tk.Button(main_frame, text="Logout", command=logout_user, bg="#D19A66", fg="white").pack(pady=5)

# Exit button
tk.Button(main_frame, text="Exit", command=root.quit, bg="#FF5555", fg="white").pack(pady=10)

root.mainloop()