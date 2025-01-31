from flask import Flask, render_template, request, redirect, url_for, flash
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from dotenv import load_dotenv
import logging

app = Flask(__name__)
load_dotenv()

# Configure logging (essential for debugging on Vercel)
logging.basicConfig(level=logging.ERROR)  # Or logging.DEBUG for more detail

app.secret_key = os.getenv("FLASK_SECRET_KEY")  # Get secret key from environment variables

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

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        action = request.form.get("action")
        text = request.form.get("text")
        password = request.form.get("password")

        if not text or not password:
            flash("Enter text and password.", "error")
            return redirect(url_for("home"))

        try:
            if action == "encrypt":
                key, salt = derive_key(password)
                cipher = Fernet(key)
                encrypted = cipher.encrypt(text.encode())

                # Prepend the salt to the ciphertext (important!)
                combined = base64.urlsafe_b64encode(salt + encrypted).decode()
                flash("Text encrypted!", "success")
                return render_template("index.html", result=combined, text=text)

            elif action == "decrypt":
                combined = base64.urlsafe_b64decode(text.encode())
                salt = combined[:16]
                encrypted = combined[16:]
                key, _ = derive_key(password, salt) # Derive key using salt from combined data
                cipher = Fernet(key)
                decrypted = cipher.decrypt(encrypted).decode()
                flash("Text decrypted!", "success")
                return render_template("index.html", result=decrypted, text=text)

        except Exception as e:
            logging.exception("An error occurred:")  # Log the full traceback
            flash(f"An error occurred: {str(e)}", "error")
            return render_template("index.html", result=text, text=text)  # Keep input

    return render_template("index.html")

@app.route("/reset", methods=["POST"])
def reset():
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run()
