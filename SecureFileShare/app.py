import os
import base64
import hashlib
from flask import Flask, request, render_template, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from dotenv import load_dotenv
from io import BytesIO

# Load .env variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", os.urandom(16))  # fallback if not set

UPLOAD_FOLDER = "uploads"
HASH_FILE = "file_hashes.txt"  # Store SHA256 hashes for integrity check
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Load AES key from .env or generate if missing
key_b64 = os.getenv("FILE_KEK_B64")
if not key_b64:
    AES_KEY = get_random_bytes(32)  # AES-256
    os.environ["FILE_KEK_B64"] = base64.b64encode(AES_KEY).decode()
else:
    AES_KEY = base64.b64decode(key_b64)

# AES-GCM encryption
def encrypt_file(file_data):
    cipher = AES.new(AES_KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    return cipher.nonce + tag + ciphertext  # store nonce + tag + data

# AES-GCM decryption
def decrypt_file(encrypted_data):
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# Save file hash for integrity check
def save_file_hash(filename, data):
    sha256 = hashlib.sha256(data).hexdigest()
    with open(HASH_FILE, "a") as f:
        f.write(f"{filename}:{sha256}\n")

def verify_file_hash(filename, data):
    sha256 = hashlib.sha256(data).hexdigest()
    if not os.path.exists(HASH_FILE):
        return False
    with open(HASH_FILE, "r") as f:
        for line in f:
            name, saved_hash = line.strip().split(":")
            if name == filename and saved_hash == sha256:
                return True
    return False

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part")
            return redirect(request.url)

        file = request.files["file"]
        if file.filename == "":
            flash("No selected file")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        file_data = file.read()

        # Encrypt before saving
        encrypted_data = encrypt_file(file_data)

        encrypted_filename = filename + ".enc"
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        with open(save_path, "wb") as f:
            f.write(encrypted_data)

        # Save hash for integrity
        save_file_hash(filename, file_data)

        flash(f"File '{filename}' uploaded & encrypted successfully.")
        return redirect(url_for("index"))

    # List encrypted files
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    decrypted_files = [f.replace(".enc", "") for f in files if f.endswith(".enc")]
    return render_template("index.html", files=decrypted_files)

@app.route("/download", methods=["POST"])
def download():
    filename = request.form.get("filename")
    encrypted_filename = filename + ".enc"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)

    if filename and os.path.exists(file_path):
        with open(file_path, "rb") as f:
            encrypted_data = f.read()

        try:
            decrypted_data = decrypt_file(encrypted_data)

            # Verify integrity
            if not verify_file_hash(filename, decrypted_data):
                flash("⚠ File integrity check failed!")
                return redirect(url_for("index"))

        except Exception as e:
            flash(f"Decryption failed: {str(e)}")
            return redirect(url_for("index"))

        # Send decrypted file as download
        return send_file(BytesIO(decrypted_data), as_attachment=True, download_name=filename)

    flash("File not found!")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)

# import os
# import base64
# from flask import Flask, request, render_template, send_file, flash, redirect, url_for
# from werkzeug.utils import secure_filename
# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# from dotenv import load_dotenv
# from io import BytesIO

# # Load .env variables
# load_dotenv()

# app = Flask(__name__)
# app.secret_key = os.getenv("FLASK_SECRET")

# UPLOAD_FOLDER = "uploads"
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# if not os.path.exists(UPLOAD_FOLDER):
#     os.makedirs(UPLOAD_FOLDER)

# # Load AES key from .env
# AES_KEY = base64.b64decode(os.getenv("FILE_KEK_B64"))

# # Padding/unpadding helpers
# def pad(data):
#     pad_len = AES.block_size - len(data) % AES.block_size
#     return data + bytes([pad_len] * pad_len)

# def unpad(data):
#     pad_len = data[-1]
#     return data[:-pad_len]

# # AES encryption
# def encrypt_file(file_data):
#     iv = get_random_bytes(16)
#     cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
#     encrypted = cipher.encrypt(pad(file_data))
#     return iv + encrypted  # Prepend IV for use in decryption

# # AES decryption
# def decrypt_file(encrypted_data):
#     iv = encrypted_data[:16]
#     cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
#     decrypted = cipher.decrypt(encrypted_data[16:])
#     return unpad(decrypted)

# @app.route("/", methods=["GET", "POST"])
# def index():
#     if request.method == "POST":
#         if "file" not in request.files:
#             flash("No file part")
#             return redirect(request.url)

#         file = request.files["file"]
#         if file.filename == "":
#             flash("No selected file")
#             return redirect(request.url)

#         filename = secure_filename(file.filename)
#         file_data = file.read()

#         # Encrypt before saving
#         encrypted_data = encrypt_file(file_data)

#         encrypted_filename = filename + ".enc"
#         save_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
#         with open(save_path, "wb") as f:
#             f.write(encrypted_data)

#         flash(f"File '{filename}' uploaded & encrypted successfully.")
#         return redirect(url_for("index"))

#     # List encrypted files
#     files = os.listdir(app.config['UPLOAD_FOLDER'])
#     decrypted_files = [f.replace(".enc", "") for f in files if f.endswith(".enc")]
#     return render_template("index.html", files=decrypted_files)

# @app.route("/download", methods=["POST"])
# def download():
#     filename = request.form.get("filename")
#     encrypted_filename = filename + ".enc"
#     file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)

#     if filename and os.path.exists(file_path):
#         with open(file_path, "rb") as f:
#             encrypted_data = f.read()

#         try:
#             decrypted_data = decrypt_file(encrypted_data)
#         except Exception:
#             flash("Decryption failed.")
#             return redirect(url_for("index"))

#         # Send decrypted file as download
#         return send_file(BytesIO(decrypted_data), as_attachment=True, download_name=filename)

#     flash("File not found!")
#     return redirect(url_for("index"))

# if __name__ == "__main__":
#     app.run(debug=True)
