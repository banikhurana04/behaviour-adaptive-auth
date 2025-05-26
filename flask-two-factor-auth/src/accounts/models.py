from datetime import datetime
import pyotp
from flask_login import UserMixin
from src import bcrypt, db
from config import Config


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_two_factor_authentication_enabled = db.Column(db.Boolean, default=False, nullable=False)
    secret_token = db.Column(db.String(32), unique=True)

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password  # ← already hashed in views.py
        self.created_at = datetime.now()
        self.secret_token = pyotp.random_base32()

    def get_authentication_setup_uri(self):
        return pyotp.totp.TOTP(self.secret_token).provisioning_uri(
            name=self.username,
            issuer_name=Config.APP_NAME
        )

    def is_otp_valid(self, user_otp):
        totp = pyotp.TOTP(self.secret_token)
        return totp.verify(user_otp)

    def __repr__(self):
        return f"<User {self.username}>"


class BehaviorProfile(db.Model):
    __tablename__ = "behavior_profiles"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    avg_movements = db.Column(db.Float)
    avg_keystrokes = db.Column(db.Float)
    avg_scrolls = db.Column(db.Float)


class LoginHistory(db.Model):
    __tablename__ = "login_history"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(512))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    location = db.Column(db.String(128))
    is_suspicious = db.Column(db.Boolean, default=False)
