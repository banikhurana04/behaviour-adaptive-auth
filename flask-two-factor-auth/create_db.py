from src import create_app  # import the factory
from src.db import db
from src.accounts.models import User, BehaviorProfile, LoginHistory

app = create_app()

with app.app_context():
    db.create_all()
    print("Database tables created successfully!")
