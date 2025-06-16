from datetime import datetime
import pyotp
from flask_login import UserMixin
from src import bcrypt, db
from config import Config

# ====================================
# User Model
# ====================================

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    salt = db.Column(db.LargeBinary, nullable=False)   # ✅ <-- newly added
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_two_factor_authentication_enabled = db.Column(db.Boolean, default=False, nullable=False)
    secret_token = db.Column(db.String(32), unique=True)

    # Relationships
    password_entries = db.relationship("VaultEntry", backref="user", lazy=True, cascade="all, delete-orphan")
    behavior_profile = db.relationship("BehaviorProfile", uselist=False, backref="user", lazy=True, cascade="all, delete-orphan")
    login_history = db.relationship('LoginHistory', back_populates='user', lazy=True, cascade="all, delete-orphan", passive_deletes=True)

    def __init__(self, username, email, password, salt):
        self.username = username
        self.email = email
        self.password = password
        self.salt = salt
        self.created_at = datetime.utcnow()
        self.secret_token = pyotp.random_base32()

    def get_authentication_setup_uri(self):
        return pyotp.TOTP(self.secret_token).provisioning_uri(
            name=self.username,
            issuer_name=Config.APP_NAME
        )

    def is_otp_valid(self, user_otp):
        totp = pyotp.TOTP(self.secret_token)
        return totp.verify(user_otp)

    def __repr__(self):
        return f"<User {self.username}>"


# ====================================
# Behavior Profile Model
# ====================================

class BehaviorProfile(db.Model):
    __tablename__ = "behavior_profiles"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True)
    avg_movements = db.Column(db.Float)
    avg_keystrokes = db.Column(db.Float)
    avg_scrolls = db.Column(db.Float)

    def __repr__(self):
        return f"<BehaviorProfile for user_id {self.user_id}>"


# ====================================
# Login History Model
# ====================================

class LoginHistory(db.Model):
    __tablename__ = "login_history"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(256))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    location = db.Column(db.String(100))
    is_suspicious = db.Column(db.Boolean, default=False)

    user = db.relationship('User', back_populates='login_history')

    def __repr__(self):
        return f"<LoginHistory {self.timestamp} for user_id {self.user_id}>"


# ✅ Don't forget to import VaultEntry as before:
from src.vault.models import VaultEntry
