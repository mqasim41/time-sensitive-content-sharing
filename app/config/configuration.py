from dotenv import load_dotenv
import os

# Load the .env file
load_dotenv()

# Access environment variables
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
SECRET_KEY = os.getenv('SECRET_KEY')
EMAIL = os.getenv('EMAIL')
FLASK_SECRET_KEY = os.getenv('FLASK_SECRET_KEY')
SERIALIZER_SECRET_KEY = os.getenv('SERIALIZER_SECRET_KEY')

# Optional: Print to verify the values (Remove in production)
if __name__ == "__main__":
    print("Database URL:", EMAIL_PASSWORD)
    print("Secret Key:", SECRET_KEY)
    print("Debug Mode:", EMAIL)
