from flask import Flask, render_template, request, redirect, url_for, flash
import os
import base64
import logging
import binascii
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature, InvalidKey
from dotenv import load_dotenv
from flask_limiter import Limiter

# Initialize environment and logging
load_dotenv()
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "fallback-secret-key-for-dev")

limiter = Limiter(app=app, key_func=lambda: request.remote_addr)

@app.after_request
def add_csp(response):
    # Updated CSP header to allow images from the CDN and inline styles
    csp_policy = (
        "default-src 'self'; "
        "img-src 'self' https://cdn-icons-png.flaticon.com; "
        "style-src 'self' 'unsafe-inline';"
    )
    response.headers["Content-Security-Policy"] = csp_policy
    return response

# ================== Core Functions ==================
def derive_key(password, salt=None):
    """Derive encryption key with PBKDF2HMAC"""
    if not salt:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode())), salt

def add_padding(data):
    """Fix Base64 padding issues"""
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return data

# ================== Routes ==================
@app.route("/", methods=["POST"])
@limiter.limit("5/minute")
def home_post():
    return home()

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        action = request.form.get("action")
        text = request.form.get("text", "").strip()
        password = request.form.get("password", "").strip()

        # Input validation
        if not text or not password:
            flash("Both text and password are required", "error")
            return render_template("index.html", text=text)

        try:
            if action == "encrypt":
                key, salt = derive_key(password)
                cipher = Fernet(key)
                encrypted = cipher.encrypt(text.encode())
                combined = base64.urlsafe_b64encode(salt + encrypted).decode()
                flash("Encryption successful!", "success")
                return render_template("index.html", result=combined, text=text)

            elif action == "decrypt":
                text_padded = add_padding(text)
                combined = base64.urlsafe_b64decode(text_padded.encode())
                
                # Security checks
                if len(combined) < 16:
                    logger.error("Decryption failed: Insufficient data length")
                    flash("Invalid encrypted format", "error")
                    return render_template("index.html", text=text)
                
                salt = combined[:16]
                encrypted = combined[16:]
                
                key, _ = derive_key(password, salt)
                cipher = Fernet(key)
                decrypted = cipher.decrypt(encrypted).decode()
                flash("Decryption successful!", "success")
                return render_template("index.html", result=decrypted, text=text)

        except (binascii.Error, ValueError) as e:
            logger.error(f"Base64 error: {str(e)}")
            flash("Invalid encrypted text format", "error")
        except (InvalidSignature, InvalidKey):
            logger.error("Decryption failed: Invalid password")
            flash("Incorrect password or corrupted data", "error")
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}", exc_info=True)
            flash("Operation failed. Please try again.", "error")

        return render_template("index.html", text=text)

    return render_template("index.html")

@app.route("/reset", methods=["POST"])
def reset():
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
