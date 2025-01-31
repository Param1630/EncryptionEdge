from flask import Flask, render_template, request, redirect, url_for, flash
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from dotenv import load_dotenv

app = Flask(__name__)
load_dotenv()
app.config['SECRET_KEY'] = '37adbff8a00bce49a1b4dcd59f1205b20c9ab04848174e76caa4d97a586375ce'

# Function to derive a key from a password
def derive_key(password, salt=None):
    if not salt:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode())), salt

# Function to save the key to a file
def save_key(password):
    key, salt = derive_key(password)
    with open("encryption_key.key", "wb") as f:
        f.write(salt + key)
    return key

# Function to load the key from a file
def load_key(password):
    try:
        with open("encryption_key.key", "rb") as f:
            data = f.read()
            salt, stored_key = data[:16], data[16:]
        key, _ = derive_key(password, salt)
        if key == stored_key:
            return key
    except (FileNotFoundError, ValueError):
        pass
    return None

# Home page
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        action = request.form.get("action")
        text = request.form.get("text")
        password = request.form.get("password")

        if not text or not password:
            flash("Enter text and password.", "error")
            return redirect(url_for("home"))

        if action == "encrypt":
            key = load_key(password) or save_key(password)
            encrypted = Fernet(key).encrypt(text.encode()).decode()
            flash("Text encrypted!", "success")
            return render_template("index.html", result=encrypted, text=text)

        elif action == "decrypt":
            key = load_key(password)
            if not key:
                flash("Invalid password. Please try again.", "error")
                return render_template("index.html", result=text, text=text)  # Keep encrypted text
            try:
                decrypted = Fernet(key).decrypt(text.encode()).decode()
                flash("Text decrypted!", "success")
                return render_template("index.html", result=decrypted, text=text)
            except Exception:
                flash("Decryption failed. Invalid password or corrupted data.", "error")
                return render_template("index.html", result=text, text=text)  # Keep encrypted text

    return render_template("index.html")

# Reset functionality
@app.route("/reset", methods=["POST"])
def reset():
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run()