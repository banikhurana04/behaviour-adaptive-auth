from src import create_app
from src.db import db

app = create_app()

with app.app_context():
    db.drop_all()
    print("All tables dropped successfully!")
