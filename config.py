from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Define your PostgreSQL database connection variables using environment variables
POSTGRES_URL = os.getenv('POSTGRES_URL')
POSTGRES_PRISMA_URL = os.getenv('POSTGRES_PRISMA_URL')
POSTGRES_URL_NO_SSL = os.getenv('POSTGRES_URL_NO_SSL')
POSTGRES_URL_NON_POOLING = os.getenv('POSTGRES_URL_NON_POOLING')

POSTGRES_USER = os.getenv('POSTGRES_USER', 'default')  # Defaulting to 'default' if not specified
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD')
POSTGRES_HOST = os.getenv('POSTGRES_HOST')
POSTGRES_PORT = os.getenv('POSTGRES_PORT', '5432')  # Default PostgreSQL port
POSTGRES_DATABASE = os.getenv('POSTGRES_DATABASE')

# Optionally, you can define other configurations or constants for your Flask application
SECRET_KEY = os.getenv('SECRET_KEY', 'your_secret_key_here')
DEBUG = os.getenv('DEBUG', True)  # Set to True for development, False for production
