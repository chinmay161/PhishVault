# models.py
import secrets
from flask_sqlalchemy import SQLAlchemy
import uuid
from datetime import datetime, timedelta
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user')
    is_active = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.Index('idx_email', 'email'),
        db.Index('idx_role', 'role'),
    )

    def __repr__(self):
        return f"<User {self.email}>"

class Token(db.Model):
    __tablename__ = 'tokens'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

    user = db.relationship('User', backref=db.backref('tokens', lazy=True))

    def is_expired(self):
        return datetime.utcnow() > self.expires_at

    @staticmethod
    def generate_token(user_id):
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=24)  # Token valid for 24 hours
        new_token = Token(user_id=user_id, token=token, expires_at=expires_at)
        db.session.add(new_token)
        db.session.commit()
        return token
    
class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)  # Links to the User model
    token = db.Column(db.String(255), unique=True, nullable=False)  # The actual token string
    expires_at = db.Column(db.DateTime, nullable=False)  # Expiration time for the token

    user = db.relationship('User', backref=db.backref('password_reset_tokens', lazy=True))

    def is_expired(self):
        """Check if the token has expired."""
        return datetime.utcnow() > self.expires_at

    @staticmethod
    def generate_token(user_id):
        """Generate a new password reset token for a user and store it in the database."""
        token = secrets.token_urlsafe(32)  # Generate a secure random token
        expires_at = datetime.utcnow() + timedelta(hours=1)  # Token valid for 1 hour
        new_token = PasswordResetToken(user_id=user_id, token=token, expires_at=expires_at)
        db.session.add(new_token)
        db.session.commit()
        return token
    
