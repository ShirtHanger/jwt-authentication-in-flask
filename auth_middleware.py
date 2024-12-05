from functools import wraps
from flask import request, jsonify, g
import jwt
import os


# This can be modified to take the ID of a user, so we can check for SPECIFIC users
# Roles and permissions!
def token_required(f):
    @wraps(f)
    
    def decorated_function(*args, **kwargs):
        # This means there must be an authoerization header
        authorization_header = request.headers.get('Authorization')
        # check if there is a header before attempting to decode it
        if authorization_header is None:
            return jsonify({"error": "Not logged in. Unauthorized"}), 401
        
        try:
            # remove the 'Bearer' portion of the Auth header string
            token = authorization_header.split(' ')[1]
            # Gets token data
            token_data = jwt.decode(token, os.getenv('JWT_SECRET'), algorithms=["HS256"])
            g.user = token_data # Gets some data from user I think
            
            # decode will throw an error if the token is invalid, triggering the except block automatically
            jwt.decode(token, os.getenv('JWT_SECRET'), algorithms=["HS256"])
            
        except Exception as error:
            return jsonify({"error": str(error)}), 500
        
        
        return f(*args, **kwargs)
    return decorated_function


