# auth_routes.py
from flask import Blueprint, current_app, request, jsonify, render_template, redirect, url_for
from flask_login import login_user, current_user
from flask_mail import Message
from werkzeug.security import generate_password_hash, check_password_hash
from models import PasswordResetToken, Token, db, User
from datetime import datetime, timedelta

auth_bp = Blueprint('auth', __name__)

# Route for handling signup form submission
@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        # Render the signup page
        return render_template('signup.html')
    
    if request.method == 'POST':
        # Handle signup form submission
        data = request.form
        email = data.get('signupEmail')
        password = data.get('signupPassword')
        confirm_password = data.get('confirmPassword')

        if not email or not password or not confirm_password:
            return jsonify({'error': 'All fields are required'}), 400

        if password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'error': 'Email already registered'}), 400

        password_hash = generate_password_hash(password)
        new_user = User(email=email, password_hash=password_hash, is_active=False)
        db.session.add(new_user)
        db.session.commit()

        # Generate and store a verification token
        token = Token.generate_token(new_user.id)
        verification_link = f"http://localhost:5000/auth/verify/{token}"

        # Send verification email using Mailtrap
        send_verification_email(email, verification_link)

        return jsonify({'message': 'Signup successful! Please verify your email.'}), 201

# Route for verifying email
@auth_bp.route('/verify/<token>', methods=['GET'])
def verify_email(token):
    # Find the token in the database
    token_record = Token.query.filter_by(token=token).first()
    if not token_record or token_record.is_expired():
        return jsonify({'error': 'Invalid or expired token'}), 400

    # Activate the user account
    user = token_record.user
    user.is_active = True
    db.session.delete(token_record)  # Delete the token after use
    db.session.commit()

    return redirect(url_for('auth.login_page'))

# Route for rendering the login page
@auth_bp.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

# Route for handling login form submission
@auth_bp.route('/login', methods=['POST'])
def login():

    if current_user.is_authenticated:  # Check if the user is already logged in
        return jsonify({'error': 'User already logged in'}), 400
    
    data = request.form
    email = data.get('loginEmail')
    password = data.get('loginPassword')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Invalid email or password'}), 401

    if not user.is_active:
        return jsonify({'error': 'Please verify your email first'}), 403

    login_user(user)  # Flask-Login handles session management

    return jsonify({'message': 'Login successful'}), 200

# Helper function to send verification email
def send_verification_email(email, verification_link):
    mail = current_app.extensions['mail']  # Access mail via current_app
    msg = Message("Verify Your Email", recipients=[email])
    msg.body =   f"Please click the following link to verify your email: {verification_link}"
    msg.html = f"<p>Please click the following link to verify your email: <a href='{verification_link}'>Verify</a></p>"
    mail.send(msg)

# Route for rendering the Forgot Password page
@auth_bp.route('/forgot-password', methods=['GET'])
def forgot_password_page():
    return render_template('forgot_password.html' )

# Route for handling Forgot Password form submission
@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.form
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    # Find the user by email
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'If the email exists, a reset link will be sent.'}), 200

    # Generate and store a password reset token
    token = PasswordResetToken.generate_token(user.id)
    reset_link = f"http://localhost:5000/auth/reset-password/{token}"

    # Send password reset email
    send_password_reset_email(email, reset_link)

    return jsonify({'message': 'If the email exists, a reset link will be sent.'}), 200

# Helper function to send password reset email
def send_password_reset_email(email, reset_link):
    mail = current_app.extensions['mail']
    msg = Message("Password Reset", recipients=[email])
    msg.body = f"Please click the following link to reset your password: {reset_link}"
    msg.html = f"<p>Please click the following link to reset your password: <a href='{reset_link}'>Reset Password</a></p>"
    mail.send(msg)

# Route for rendering the Reset Password page
@auth_bp.route('/reset-password/<token>', methods=['GET'])
def reset_password_page(token):
    # Find the token in the database
    token_record = PasswordResetToken.query.filter_by(token=token).first()
    if not token_record or token_record.is_expired():
        return jsonify({'error': 'Invalid or expired token'}), 400

    # Render the password reset form with the token
    return render_template('reset_password.html', token=token)

# Route for handling Reset Password form submission
@auth_bp.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    # Find the token in the database
    token_record = PasswordResetToken.query.filter_by(token=token).first()
    if not token_record or token_record.is_expired():
        return jsonify({'error': 'Invalid or expired token'}), 400

    # Get the user associated with the token
    user = token_record.user

    # Get the new password from the form
    data = request.form
    new_password = data.get('newPassword')
    confirm_password = data.get('confirmPassword')

    if not new_password or not confirm_password:
        return jsonify({'error': 'All fields are required'}), 400

    if new_password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400

    # Update the user's password
    user.password_hash = generate_password_hash(new_password)
    db.session.delete(token_record)  # Delete the token after use
    db.session.commit()

    return jsonify({'message': 'Password reset successful'}), 200