from extensions import db
from app import app
from models.db_models import User, JournalEntry

with app.app_context():
    db.create_all()
    print("Database created successfully!")
