from datetime import datetime
from extensions import db

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    picture = db.Column(db.String(255), nullable=True)
    is_google_user = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Corrected relationship using back_populates for clarity
    entries = db.relationship('JournalEntry', back_populates='author', lazy=True)

    def __repr__(self):
        return f'<User {self.name}>'

class JournalEntry(db.Model):
    __tablename__ = 'journal_entries' # Made table name more explicit

    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    sentiment = db.Column(db.String(50))
    emotion = db.Column(db.String(50))
    suggestion = db.Column(db.Text)
    date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # --- CRITICAL FIXES ARE HERE ---
    # 1. ForeignKey now correctly points to the 'users' table name.
    # 2. Added nullable=False because an entry must have an author.
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Defines the other side of the relationship for User.entries
    author = db.relationship('User', back_populates='entries')

    def __repr__(self):
        return f'<JournalEntry {self.id}>'