from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from config.configuration import SECRET_KEY, EMAIL, EMAIL_PASSWORD
import random
import string
import os

app = Flask(__name__)

app.secret_key = SECRET_KEY

# Configuration for Flask-Mail
app.config.update(
    MAIL_SERVER='smtp.gmail.com',       # Replace with your SMTP server
    MAIL_PORT=587,                      # Replace with your SMTP port
    MAIL_USE_TLS=True,
    MAIL_USERNAME=EMAIL,   # Replace with your email
    MAIL_PASSWORD=EMAIL_PASSWORD,    # Replace with your email password or app-specific password
    MAIL_DEFAULT_SENDER=EMAIL  # Replace with your email
)

mail = Mail(app)

serializer = URLSafeTimedSerializer(SECRET_KEY)

# In-memory stores for data and OTPs
DATA_STORE = {}
OTP_STORE = {}

def generate_otp(length=6):
    """Generate a random OTP consisting of digits."""
    return ''.join(random.choices(string.digits, k=length))

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

    # Create a time-limited URL
    secure_url = serializer.dumps(identifier)

    # Construct the access URL
    access_url = url_for('access_data_form', secure_url=secure_url, _external=True)

    # Send OTP via email
    try:
        msg = Message(
            subject="Your OTP for Secure Data Access",
            recipients=[email],
            body=f"Your OTP is: {otp}\nUse the following link to access your data: {access_url}"
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
    return redirect(url_for('home'))

@app.route('/access/<secure_url>', methods=['GET', 'POST'])
def access_data_form(secure_url):
    """Render the form to input OTP and access the secured data."""
    if request.method == 'POST':
        otp = request.form.get('otp')
        if not otp:
            flash("OTP is required.", "danger")
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
        
        flash("Data retrieved successfully.", "success")
        return render_template('data.html', data=data)
    
    return render_template('access.html', secure_url=secure_url)

if __name__ == '__main__':
    # Ensure that templates are auto-reloaded
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.run(debug=True)
