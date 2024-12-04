# Import .env file
from dotenv import load_dotenv
import os

# Add an import for the jwt library:
import jwt

load_dotenv()



# Import the 'Flask' class from the 'flask' library.
# add an import for jsonify and request
from flask import Flask, jsonify, request

# Initialize Flask
# We'll use the pre-defined global '__name__' variable to tell Flask where it is.
app = Flask(__name__)

# Define our route
# This syntax is using a Python decorator, which is essentially a succinct way to wrap a function in another function.
@app.route('/')
def index():
  return "Hello, world!"

# Sign in route
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
@app.route('/verify-token', methods=['POST'])
def verify_token():
    try:
        # return jsonify({"message": "Token is valid."})
        token = request.headers.get('Authorization').split(' ')[1] # Removed "Bearer " from token response
        decoded_token = jwt.decode(token, os.getenv('JWT_SECRET'), algorithms=["HS256"]) # Collect and hash token
        return jsonify({"user": decoded_token})
    except Exception as error:
        return jsonify({"error": error.message})


# Run our application, by default on port 5000
app.run()
