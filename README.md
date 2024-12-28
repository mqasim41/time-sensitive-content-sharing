# Secure Data Sharing

### Department of Computing  
### Information Security  
### **BESE-12A**  

**Submitted By:**  
- **Muhammad Qasim** (365788)  
- **Ahmed Obaidullah** (372967)  

**Submitted To:**  
- **Ms. Hirra Anwar**

---

## 1. Introduction

In today's digital landscape, ensuring the security of data transmission and storage is paramount. This project presents a Flask-based web application designed to securely share data through encrypted storage and one-time password (OTP) authentication mechanisms. The primary security attributes addressed in this system are **Authentication** and **Integrity**, with **Confidentiality** serving as a secondary attribute using PKI-based methods. The motivation behind this project is to create a robust and secure data sharing platform that mitigates common security threats such as unauthorized access, data tampering, and brute-force attacks.

### **Selected Security Attributes**  
1. **Primary: Authentication**  
   Ensures that only authorized users can access the data through OTP verification.
2. **Secondary: Integrity**  
   Guarantees that the data remains unaltered during storage and transmission.
3. **Confidentiality (PKI-based)**  
   Protects the data from unauthorized disclosure using encryption mechanisms.

---

## 2. Design of the Security Mechanism/Protocol

The system architecture integrates multiple security measures to uphold the selected attributes. The design workflow includes data encryption, OTP generation and validation, time-limited access URLs, and integrity verification.

### **Sequence Diagram**
[Link to Sequence Diagram](#) <!-- Placeholder link -->

### **Key Components and Workflow**

1. **Data Encryption:**
   - Utilizes symmetric encryption to secure user data before storage.
   - Encryption keys are generated using secure random functions and stored temporarily in memory.
   - SSL certificates are used for asymmetric key transfer.

2. **OTP Generation and Email Transmission:**
   - Generates a secure OTP using cryptographic random functions.
   - Sends the OTP to the user's email using Flask-Mail to ensure that only the intended recipient can access the OTP.

3. **Time-Limited Access URLs:**
   - Creates a unique, time-sensitive URL using `itsdangerous.URLSafeTimedSerializer`.
   - The URL expires after a predefined period (5 minutes) to limit the window of opportunity for unauthorized access.

4. **Integrity Verification:**
   - Implements SHA-256 hashing to verify that the data remains unchanged from the time of encryption to retrieval.
   - Compares the original hash with a newly computed hash upon data access.

5. **Rate Limiting:**
   - Limits the number of OTP entry attempts to prevent brute-force attacks.
   - After exceeding the maximum number of attempts, the associated data is destroyed to prevent further exploitation.

### **Code Snippet: OTP Generation**

```python
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
```

---

## 3. Implementation Details

The application leverages several Python libraries and frameworks to implement the security mechanisms effectively.

### **Technologies Used**
- **Flask:** Serves as the primary web framework for handling routes and rendering templates.
- **Flask-WTF:** Provides form handling and CSRF protection.
- **Flask-Mail:** Manages email operations for OTP transmission.
- **Flask-SocketIO:** Enables real-time communication capabilities.
- **itsdangerous:** Facilitates the creation of time-limited tokens for secure URLs.
- **Cryptographic Utilities (`utils.utils`):** Custom functions for OTP generation, hashing, and data encryption/decryption.

### **Key Implementation Aspects**

1. **CSRF Protection:**
   - Enabled globally using Flask-WTF to protect all form submissions against cross-site request forgery attacks.

   ```python
   # Enable CSRF
   app.config['WTF_CSRF_ENABLED'] = True
   app.config['WTF_CSRF_SECRET_KEY'] = FLASK_SECRET_KEY
   csrf = CSRFProtect(app)
   ```

2. **Data Encryption and Decryption:**
   - Uses secure encryption algorithms to protect data before storage.
   - Ensures that only users with the correct encryption key can decrypt and access the data.

   ```python
   encryption_key, encrypted_data = encrypt_data(data)
   ```

3. **OTP Handling:**
   - Generates a secure OTP and associates it with the encrypted data.
   - Stores OTP and related metadata in an in-memory store (`OTP_STORE`) for validation during access.

4. **Time-Limited URLs:**
   - Utilizes `itsdangerous.URLSafeTimedSerializer` to create tokens that encode the unique identifier for data access.
   - Sets a maximum age (5 minutes) for the token to ensure timely access.

5. **Rate Limiting:**
   - Implements a counter for OTP entry attempts.
   - After three failed attempts, the system destroys the associated data to prevent brute-force attacks.

   ```python
   # Rate-limiting logic
   record['attempts'] += 1
   if record['attempts'] > 3:
       # Too many attempts; destroy data
       DATA_STORE.pop(identifier, None)
       OTP_STORE.pop(identifier, None)
       flash("Too many invalid OTP attempts. Data destroyed.", "danger")
       return redirect(url_for('home'))
   ```

### **Code Snippet: Integrity Verification**

```python
decrypted_data = decrypt_data(encryption_key, encrypted_data)
if not decrypted_data:
    flash("Integrity check failed. The data may have been altered.", "danger")
    return redirect(url_for('home'))

# Compare new hash
hashed_data = create_sha256_hash(decrypted_data)
if hashed_data != original_hash:
    flash("Integrity check failed. The data may have been altered.", "danger")
    return redirect(url_for('home'))
```

---

## 4. Demonstration of Security Attributes

### **A. Authentication**
- **Mechanism:** The system employs OTP-based authentication to verify user identity before granting access to the data.
- **Process:**
  1. Upon data submission, an OTP is generated and sent to the user's email.
  2. The user must enter the correct OTP within a limited time frame to access the data.

### **B. Integrity**
- **Mechanism:** SHA-256 hashing ensures that the data remains unchanged from encryption to retrieval.
- **Process:**
  1. After encrypting the data, a SHA-256 hash of the original data is stored.
  2. Upon data access, the decrypted data's hash is recalculated and compared with the stored hash.

### **C. Confidentiality**
- **Mechanism:** Data encryption ensures that only authorized parties with the correct decryption key can access the data.
- **Process:**
  1. Data is encrypted using a secure key before storage.
  2. The encryption key is required to decrypt and access the original data.

### **D. Time-Limited Access**
- **Mechanism:** Access URLs are valid only for a specific duration (5 minutes) to minimize the risk of unauthorized access.
- **Process:**
  1. A unique token is generated and embedded in the access URL.
  2. The token expires after 5 minutes, rendering the URL invalid thereafter.

### **E. Rate Limiting**
- **Mechanism:** Limits the number of OTP entry attempts to prevent brute-force attacks.
- **Process:**
  1. Tracks the number of failed OTP attempts.
  2. Upon exceeding the limit, associated data is destroyed to prevent further attempts.

---

## 5. Attack Scenario Considerations

### **A. Corrupt Data Attack**
- **Description:** An attacker attempts to tamper with the stored data to undermine its integrity.
- **Method:** The `/test` route is intentionally designed to corrupt data in `DATA_STORE` for testing purposes.
- **Impact:** When a user attempts to access the data, the integrity check detects the alteration, preventing access and alerting the user.

### **B. Brute-Force OTP Attack**
- **Description:** An attacker tries multiple OTP guesses to gain unauthorized access to the data.
- **Method:** By repeatedly submitting incorrect OTPs, the attacker aims to bypass authentication.
- **Impact:** The system's rate-limiting mechanism detects excessive failed attempts and destroys the associated data, mitigating the attack.

### **C. Man-in-the-Middle (MitM) Attack**
- **Description:** An attacker intercepts communication between the user and the server to capture sensitive information.
- **Mitigation:**  
  The application optionally runs over HTTPS using SSL certificates (`cert.pem` and `key.pem`).  
  Ensures encrypted data transmission, preventing eavesdropping.

---

## 6. Conclusion and Recommendations

### **Strengths**
1. **Robust Authentication:** The OTP-based system ensures that only users with access to the registered email can retrieve the data.
2. **Data Integrity:** SHA-256 hashing effectively detects any unauthorized alterations to the data.
3. **Time-Limited Access:** Restricts the window for potential attacks, enhancing overall security.
4. **Rate Limiting:** Protects against brute-force attacks by limiting OTP entry attempts.
5. **CSRF Protection:** Safeguards against cross-site request forgery attacks, ensuring secure form submissions.

### **Areas for Improvement**
1. **Persistent Storage:**
   - **Issue:** Currently, data and OTPs are stored in-memory, which is volatile and susceptible to data loss upon server restarts.
   - **Recommendation:** Implement a secure database (e.g., PostgreSQL, MongoDB) to persistently store encrypted data and OTPs with appropriate access controls.

2. **Enhanced Encryption:**
   - **Issue:** The current encryption method may not provide authenticated encryption.
   - **Recommendation:** Utilize AES-GCM or similar authenticated encryption schemes to provide both confidentiality and integrity at the encryption level.

3. **Comprehensive HTTPS Deployment:**
   - **Issue:** The application falls back to HTTP if SSL certificates are unavailable, exposing data to potential MitM attacks.
   - **Recommendation:** Enforce HTTPS in all deployment environments by obtaining valid SSL certificates and redirecting all HTTP traffic to HTTPS.

4. **Advanced Rate Limiting:**
   - **Issue:** Current rate limiting is simplistic and may not effectively counter distributed brute-force attempts.
   - **Recommendation:** Integrate IP-based rate limiting and monitoring tools to detect and mitigate distributed attacks.

5. **Logging and Monitoring:**
   - **Issue:** Limited logging mechanisms can hinder the detection of malicious activities.
   - **Recommendation:** Implement comprehensive logging of all critical actions and integrate monitoring systems to alert administrators of suspicious behaviors.

---

## 7. Contribution and Work Division

### **Ahmed Obaidullah**
- Designed and implemented the data encryption and decryption mechanisms.
- Developed the OTP generation logic and integrated Flask-Mail for email transmission.
- Created the rate-limiting functionality to prevent brute-force attacks.
- Conducted initial testing of authentication and integrity features.

### **Muhammad Qasim**
- Integrated Flask-WTF for CSRF protection and managed form validations.
- Developed the Flask-SocketIO real-time communication features.
- Implemented the time-limited URL generation using `itsdangerous`.
- Crafted the attack demonstration routes and conducted security testing.
- Compiled the project report and coordinated the presentation preparation.

---

## 8. References

1. [Flask Documentation](https://flask.palletsprojects.com/)  
2. [Flask-WTF Documentation](https://flask-wtf.readthedocs.io/)  
3. [Flask-Mail Documentation](https://pythonhosted.org/Flask-Mail/)  
4. [itsdangerous Documentation](https://itsdangerous.palletsprojects.com/)  
5. [Python Cryptography Library](https://cryptography.io/)  
6. [Eventlet Documentation](http://eventlet.net/)  
7. [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices/)  
8. [Flask-SocketIO Documentation](https://flask-socketio.readthedocs.io/)  

---
