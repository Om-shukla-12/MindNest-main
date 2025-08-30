#!/usr/bin/env python3
"""
Migration script to add is_google_user and created_at fields to existing users.
Run this script after updating the User model to ensure existing users have the new fields.
"""

import os
import sys
from datetime import datetime

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models.db_models import User

def migrate_users():
    """Migrate existing users to include new fields."""
    with app.app_context():
        try:
            # Get all users
            users = User.query.all()
            print(f"Found {len(users)} users to migrate...")
            
            for user in users:
                # Set default values for existing users
                if not hasattr(user, 'is_google_user') or user.is_google_user is None:
                    # Check if user has a picture (likely Google user) or specific email pattern
                    if user.picture or user.email != "local@example.com":
                        user.is_google_user = True
                        print(f"Marked {user.name} ({user.email}) as Google user")
                    else:
                        user.is_google_user = False
                        print(f"Marked {user.name} ({user.email}) as local user")
                
                if not hasattr(user, 'created_at') or user.created_at is None:
                    user.created_at = datetime.utcnow()
                    print(f"Set creation date for {user.name}")
            
            # Commit changes
            db.session.commit()
            print("Migration completed successfully!")
            
        except Exception as e:
            print(f"Error during migration: {e}")
            db.session.rollback()

if __name__ == "__main__":
    migrate_users()