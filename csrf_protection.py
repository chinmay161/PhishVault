from functools import wraps
from flask import request, abort, session

def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            csrf_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
            
            if not csrf_token or csrf_token != session.get('csrf_token'):
                abort(403, description="CSRF token validation failed")
                
        return f(*args, **kwargs)
    return decorated_function