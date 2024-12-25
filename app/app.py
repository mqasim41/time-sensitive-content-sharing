import os
import secrets
import string
import hashlib
import eventlet
import ssl

from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, flash, session
)
from flask_socketio import SocketIO, send
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from cryptography.fernet import Fernet

# Flask-WTF / CSRF
from flask_wtf import CSRFProtect, FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Email

from config.configuration import (
    FLASK_SECRET_KEY,
    SERIALIZER_SECRET_KEY,
    EMAIL,
    EMAIL_PASSWORD,
)

# -------------------------
# Flask App Initialization
# -------------------------
app = Flask(__name__)

# Use separate secret key for session cookies
app.secret_key = FLASK_SECRET_KEY

# Enable CSRF
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = FLASK_SECRET_KEY
csrf = CSRFProtect(app)

socketio = SocketIO(app)

# -------------------
# Flask-Mail Config
# -------------------
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=EMAIL,
    MAIL_PASSWORD=EMAIL_PASSWORD,
    MAIL_DEFAULT_SENDER=EMAIL
)
mail = Mail(app)

# --------------------------
# Time-Limited URL Serializer
# --------------------------
serializer = URLSafeTimedSerializer(SERIALIZER_SECRET_KEY)

# -----------------
# In-memory Stores
# -----------------
DATA_STORE = {}
OTP_STORE = {}

# --------------------
# Utility Functions
# --------------------
def generate_otp(length=6):
    """Generate a random 6-digit OTP using secrets (secure)."""
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def create_sha256_hash(message):
    """Create a SHA-256 hash for a given message (string)."""
    return hashlib.sha256(message.encode('utf-8')).hexdigest()

def encrypt_data(plaintext):
    """Encrypt plaintext using Fernet (symmetric encryption)."""
    key = Fernet.generate_key()
    f = Fernet(key)
    encrypted = f.encrypt(plaintext.encode('utf-8'))
    return key, encrypted

def decrypt_data(key, encrypted_data):
    """Attempt to decrypt data and handle errors."""
    f = Fernet(key)
    try:
        return f.decrypt(encrypted_data).decode('utf-8')
    except Exception:
        return None

# -------------
# Socket Events
# -------------
@socketio.on('message')
def handle_message(json):
    send({"data": json["data"], "sender": request.sid}, broadcast=True)

# -----------------
# Flask-WTF Forms
# -----------------
class GenerateForm(FlaskForm):
    data = StringField('Data', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Generate Secure URL')

class AccessForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired()])
    submit = SubmitField('Access Data')

# -------
# Routes
# -------
@app.route('/')
def home():
    """Render the home page with the form to generate secure URL."""
    form = GenerateForm()
    return render_template('home.html', form=form)

@app.route('/generate', methods=['POST'])
def generate_url():
    """
    1. Encrypt data
    2. Generate OTP
    3. Store them
    4. Send OTP by email
    5. Return a time-limited URL
    """
    form = GenerateForm()
    if not form.validate_on_submit():
        flash("Invalid input. Please fill out all fields correctly.", "danger")
        return redirect(url_for('home'))

    data = form.data.data
    email = form.email.data

    identifier = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))

    encryption_key, encrypted_data = encrypt_data(data)
    DATA_STORE[identifier] = encrypted_data

    otp = generate_otp()

    data_hash = create_sha256_hash(data)

    OTP_STORE[identifier] = {
        'otp': otp,
        'key': encryption_key,
        'hash': data_hash,
        'attempts': 0
    }

    # Create a time-limited URL (5 minutes) in 'access_data_form'
    secure_url_token = serializer.dumps(identifier)

    access_url = url_for('access_data_form', secure_url=secure_url_token, _external=True)

    try:
        msg = Message(
            subject="Your OTP for Secure Data Access",
            recipients=[email],
            body=(
                f"Your OTP is: {otp}\n\n"
                "Use this OTP on the data access page. "
                "Do not share this OTP with anyone."
            )
        )
        mail.send(msg)
    except Exception as e:
        print(f"Email send error: {e}")
        # Clean up
        DATA_STORE.pop(identifier, None)
        OTP_STORE.pop(identifier, None)
        flash("Failed to send email. Please check the email address and try again.", "danger")
        return redirect(url_for('home'))

    flash("Secure URL generated. An OTP has been sent to your email.", "success")
    return render_template('home.html', access_url=access_url, form=form)

@app.route('/access/<secure_url>', methods=['GET', 'POST'])
def access_data_form(secure_url):
    """
    Render a form to input OTP and retrieve the secured data (5-minute limit).
    """
    form = AccessForm()
    if request.method == 'POST':
        if not form.validate_on_submit():
            flash("Invalid form submission.", "danger")
            return redirect(url_for('access_data_form', secure_url=secure_url))

        otp_entered = form.otp.data
        if not otp_entered:
            flash("OTP is required.", "danger")
            return redirect(url_for('access_data_form', secure_url=secure_url))

        # Decode URL or fail if expired
        try:
            identifier = serializer.loads(secure_url, max_age=300)
        except Exception:
            flash("Invalid or expired URL.", "danger")
            return redirect(url_for('home'))

        record = OTP_STORE.get(identifier)
        if not record:
            flash("Data not found or already accessed.", "danger")
            return redirect(url_for('home'))

        # Rate-limiting logic
        record['attempts'] += 1
        if record['attempts'] > 3:
            # Too many attempts; destroy data
            DATA_STORE.pop(identifier, None)
            OTP_STORE.pop(identifier, None)
            flash("Too many invalid OTP attempts. Data destroyed.", "danger")
            return redirect(url_for('home'))

        if record['otp'] != otp_entered:
            flash("Invalid OTP.", "danger")
            return redirect(url_for('access_data_form', secure_url=secure_url))

        encrypted_data = DATA_STORE.pop(identifier, None)
        encryption_key = record['key']
        original_hash = record['hash']

        # Remove from OTP_STORE to ensure one-time access
        OTP_STORE.pop(identifier, None)

        if encrypted_data is None:
            flash("Data already accessed or invalid identifier.", "danger")
            return redirect(url_for('home'))

        decrypted_data = decrypt_data(encryption_key, encrypted_data)
        if not decrypted_data:
            flash("Integrity check failed. The data may have been altered.", "danger")
            return redirect(url_for('home'))

        # Compare new hash
        hashed_data = create_sha256_hash(decrypted_data)
        if hashed_data != original_hash:
            flash("Integrity check failed. The data may have been altered.", "danger")
            return redirect(url_for('home'))

        flash("Data retrieved successfully. Integrity verified.", "success")
        return render_template('data.html', data=decrypted_data)

    # If GET request, display the form
    return render_template('access.html', secure_url=secure_url, form=form)

@app.route('/test', methods=['GET'])
def test():
    """
    Example route that corrupts data in the DATA_STORE for demonstration.
    Disable or protect this in production.
    """

    if len(DATA_STORE) > 0:
        for identifier in DATA_STORE:
            DATA_STORE[identifier] = b"corrupted data"
    return jsonify({"message": "Data in memory has been corrupted."})

# -------------
# Main Entrypoint
# -------------
if __name__ == '__main__':
    # Enable template auto-reloading for local development
    app.config['TEMPLATES_AUTO_RELOAD'] = True

    # Optional: Run over HTTPS using a self-signed cert
    cert_file = 'cert.pem'
    key_file = 'key.pem'
    if os.path.exists(cert_file) and os.path.exists(key_file):
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)

        listener = eventlet.listen(('127.0.0.1', 5000))
        ssl_listener = eventlet.wrap_ssl(
            listener, 
            server_side=True, 
            certfile=cert_file, 
            keyfile=key_file
        )
        eventlet.wsgi.server(ssl_listener, app)
    else:
        # Fallback: HTTP
        app.run(host='127.0.0.1', port=5000, debug=True)
