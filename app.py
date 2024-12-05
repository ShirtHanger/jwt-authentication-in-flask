# Add psycopg2 import
import psycopg2, psycopg2.extras

# Import .env file
from dotenv import load_dotenv
import os

# Add an import for the jwt library:
import jwt
# Import bcrypt for verification, then hash password and stuff
# Documentation https://github.com/pyca/bcrypt/
import bcrypt


    
# Add psycopg2 import
import psycopg2, psycopg2.extras

# Function to connect to SQL database
def get_db_connection():
    connection = psycopg2.connect(host='localhost',
                            database='flask_auth_db',
                            user=os.getenv('POSTGRES_USERNAME'),
                            password=os.getenv('POSTGRES_PASSWORD'))
    return connection



load_dotenv()

# Import custom middleware:
from auth_middleware import token_required

# Import the 'Flask' class from the 'flask' library.
# add an import for jsonify and request, and g
from flask import Flask, jsonify, request, g

# Initialize Flask
# We'll use the pre-defined global '__name__' variable to tell Flask where it is.
app = Flask(__name__)

# Define our route
# This syntax is using a Python decorator, which is essentially a succinct way to wrap a function in another function.
# http://127.0.0.1:5000/
@app.route('/')
def index():
  return "Hello, world!"

# Sign Token Route
# http://127.0.0.1:5000/sign-token
@app.route('/sign-token', methods=['GET'])
def sign_token():
    # return jsonify({ "message": "You are authorized!"})
    # Mock user object added
    user = {
        "id": 1,
        "username": "test",
        "password": "test"
    }
    token = jwt.encode(user, os.getenv('JWT_SECRET'), algorithm="HS256") # Collect and hash token
    # returns the token
    return jsonify({"token": token})


# Token verification route
# http://127.0.0.1:5000/verify-token
@app.route('/verify-token', methods=['POST'])
def verify_token():
    try:
        # return jsonify({"message": "Token is valid."})
        token = request.headers.get('Authorization').split(' ')[1] # Removed "Bearer " from token response
        decoded_token = jwt.decode(token, os.getenv('JWT_SECRET'), algorithms=["HS256"]) # Collect and hash token
        return jsonify({"user": decoded_token})
    except Exception as error:
        return jsonify({"error": error.message})


# Sign up route 
# http://127.0.0.1:5000/auth/signup

@app.route('/auth/signup', methods=['POST'])
def signup():
    # Try Except block for error handling
    try:
        new_user_data = request.get_json() # Create user data
        connection = get_db_connection() # Connect to database
        cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute("SELECT * FROM users WHERE username = %s;", (new_user_data["username"],))
        
        existing_user = cursor.fetchone() # Check if username is already taken
        if existing_user:
            cursor.close() # If so, close sign up
            return jsonify({"error": "Username already taken"}), 400
        
        # If not, proceed to hash provided password
        hashed_password = bcrypt.hashpw(bytes(new_user_data["password"], 'utf-8'), bcrypt.gensalt())
        # Hides the hashed password from response as well, just incase
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s) RETURNING username", (new_user_data["username"], hashed_password.decode('utf-8')))
        
        # Properly creates a new user, and commits it to database
        created_user = cursor.fetchone()
        connection.commit()
        connection.close()
        token = jwt.encode(created_user, os.getenv('JWT_SECRET'))
        return jsonify({"token": token, "user": created_user}), 201
    
    # Error handling
    except Exception as error: 
        return jsonify({"error": str(error)}), 401


# Sign in route 
# http://127.0.0.1:5000/auth/signin      
@app.route('/auth/signin', methods=["POST"])
def signin():
    try:
        sign_in_form_data = request.get_json()
        connection = get_db_connection()  # Connect to database
        cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute("SELECT * FROM users WHERE username = %s;", (sign_in_form_data["username"],))
        
        # Check if user exists in database
        existing_user = cursor.fetchone()
        if existing_user is None: # If no user, close out
            return jsonify({"error": "Invalid username, user does not exist."}), 401
        
        # Otherwise, check if the provided password matches database password
        password_is_valid = bcrypt.checkpw(bytes(sign_in_form_data["password"], 'utf-8'), bytes(existing_user["password"], 'utf-8'))
        if not password_is_valid: # Close out if no match
            return jsonify({"error": "Invalid password."}), 401

        # Send back and authorization token
        token = jwt.encode({"username": existing_user["username"], "id": existing_user["id"]}, os.getenv('JWT_SECRET'))
        return jsonify({"token": token}), 201


    # Error handling
    except Exception as error:
        return jsonify({"error": "Invalid credentials, other error"}), 401
    finally:
        connection.close()

# VIP Lounge route 
# http://127.0.0.1:5000/vip-lounge 
@app.route('/vip-lounge')
@token_required # User must be logged in to be able to access this page, token must exist
def vip_lounge():
    return f"Welcome to the party, {g.user['username']}"

# Run our application, by default on port 5000
# http://127.0.0.1:5000/
app.run()
