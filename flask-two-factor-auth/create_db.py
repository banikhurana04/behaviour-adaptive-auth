from src import app, db
from src.accounts.models import User, BehaviorProfile, LoginHistory

with app.app_context():
    db.create_all()
    print("Database tables created successfully!")
