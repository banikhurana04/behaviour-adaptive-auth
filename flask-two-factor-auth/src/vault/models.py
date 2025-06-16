from src.db import db

class VaultEntry(db.Model):
    __tablename__ = 'password_entries'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    app_name = db.Column(db.String(100), nullable=False)
    app_username = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.LargeBinary, nullable=False)
