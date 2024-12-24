from flask_socketio import SocketIO, emit, join_room, leave_room, send
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from config.configuration import SECRET_KEY, EMAIL, EMAIL_PASSWORD
import random
import string
import hashlib
import eventlet

app = Flask(__name__)

app.secret_key = SECRET_KEY
socketio = SocketIO(app)

# Configuration for Flask-Mail
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=EMAIL,
    MAIL_PASSWORD=EMAIL_PASSWORD,
    MAIL_DEFAULT_SENDER=EMAIL
)

mail = Mail(app)

serializer = URLSafeTimedSerializer(SECRET_KEY)

# In-memory stores for data and OTPs
DATA_STORE = {}
OTP_STORE = {}

def generate_otp(length=6):
    """Generate a random OTP consisting of digits."""
    return ''.join(random.choices(string.digits, k=length))

def create_sha256_hash(message):
    """Create a SHA-256 hash for a given message."""
    # Ensure the message is in bytes
    message_bytes = message.encode('utf-8')
    # Create the hash object
    hash_object = hashlib.sha256(message_bytes)
    # Get the hexadecimal representation of the hash
    hash_hex = hash_object.hexdigest()
    return hash_hex

@socketio.on('message')
def handle_message(json):
    send({"data": json["data"], "sender": request.sid}, broadcast=True)


@app.route('/')
def home():
    """Render the home page with the form to generate secure URL."""
    return render_template('home.html')

@app.route('/generate', methods=['POST'])
def generate_url():
    """Handle the form submission to generate a secure URL and send OTP via email."""
    data = request.form.get('data')
    email = request.form.get('email')

    if not data or not email:
        flash("Data and email are required.", "danger")
        return redirect(url_for('home'))

    # Generate unique identifier for the data
    identifier = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    DATA_STORE[identifier] = data

    # Generate OTP
    otp = generate_otp()
    OTP_STORE[identifier] = otp

    hashed_message = create_sha256_hash(data)

    # Create a time-limited URL
    secure_url = serializer.dumps(identifier)

    # Construct the access URL
    access_url = url_for('access_data_form', secure_url=secure_url, _external=True)

    # Send OTP via email
    try:
        msg = Message(
            subject="Your OTP for Secure Data Access",
            recipients=[email],
            body=f"Your OTP is: {otp}\nThe message hash is: {hashed_message}\nThe data access link has been dmed to you."
        )
        mail.send(msg)
    except Exception as e:
        print(e)
        # Clean up in case of email failure
        DATA_STORE.pop(identifier, None)
        OTP_STORE.pop(identifier, None)
        flash("Failed to send email. Please check the email address and try again.", "danger")
        return redirect(url_for('home'))

    flash("Secure URL generated and OTP sent to your email.", "success")
    return render_template('home.html', access_url=access_url)

@app.route('/access/<secure_url>', methods=['GET', 'POST'])
def access_data_form(secure_url):
    """Render the form to input OTP and access the secured data."""
    if request.method == 'POST':
        otp = request.form.get('otp')
        hash = request.form.get('hash')
        if not otp:
            flash("OTP and Hash is required.", "danger")
            return redirect(url_for('access_data_form', secure_url=secure_url))
        
        try:
            # Decode URL and check expiration (5-minute limit)
            identifier = serializer.loads(secure_url, max_age=300)
        except Exception as e:
            flash("Invalid or expired URL.", "danger")
            return redirect(url_for('home'))
        
        # Verify OTP
        if OTP_STORE.get(identifier) != otp:
            flash("Invalid OTP.", "danger")
            return redirect(url_for('access_data_form', secure_url=secure_url))
        
        # Retrieve and return data
        data = DATA_STORE.pop(identifier, None)
        OTP_STORE.pop(identifier, None)
        if data is None:
            flash("Data already accessed or invalid.", "danger")
            return redirect(url_for('home'))
        
        hashed_data = create_sha256_hash(data)

        if hashed_data != hash:
            flash("Integrity Failure. Message has been altered", "danger")
            return redirect(url_for('home'))
        
        flash("Data retrieved successfully. Both the hashes match.", "success")
        return render_template('data.html', data=data)
    
    return render_template('access.html', secure_url=secure_url)

if __name__ == '__main__':
    # Ensure that templates are auto-reloaded
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    eventlet.wsgi.server(eventlet.listen(('127.0.0.1', 5000)), app)

