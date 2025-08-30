# ---------------------- Imports ----------------------
import os
from functools import wraps
from collections import Counter
from flask import Flask, render_template, request, redirect, url_for, session, abort, Response
from dotenv import load_dotenv

# Google Sign-In verification
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

# Local project imports
from extensions import db
from services.nlp_analysis import analyze_text
from models.db_models import JournalEntry
from models.db_models import User

#export
import csv
import io
# ---------------------- Configuration ----------------------

# Load environment variables from .env file
load_dotenv()

# Flask app setup
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///journal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv("FLASK_SECRET_KEY")
db.init_app(app)


USERNAME = 'user'
PASSWORD = 'pass123'

# ---------------------- Utility ----------------------

def login_required(f):
    """Decorator to ensure a user is logged in before accessing a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ---------------------- Core Routes ----------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # This block handles the simple username/password form
        if request.form.get('username') == USERNAME and request.form.get('password') == PASSWORD:
            
            user = User.query.filter_by(email="local@example.com").first()
            if not user:
                user = User(
                    name="Local Test User",
                    email="local@example.com",
                    is_google_user=False
                )
                db.session.add(user)
                db.session.commit()

            session.clear()
            session['logged_in'] = True
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_email'] = user.email
            session['user_picture'] = None
            # Adds the required user_id to the session for the local user
           
            print("SESSION AFTER LOGIN:", session)
            return redirect(url_for('home'))
        else:
            error = 'Invalid username or password.'

    google_client_id = os.getenv("GOOGLE_CLIENT_ID")
    return render_template('login.html', error=error, google_client_id=google_client_id)



@app.route('/')
@app.route('/home')
@login_required
def home():
    user = {
        "name": session.get('user_name'),
        "email": session.get('user_email'),
        "picture": session.get('user_picture')
    }
    return render_template('index.html', user=user)



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/verify-google-token', methods=['POST'])
def verify_google_token():
    """Receives an ID token from the client, verifies it, and manages the user session."""
    try:
        token = request.json.get('token')
        if not token:
            return {"success": False, "message": "Token is missing"}, 400

        google_client_id = os.getenv("GOOGLE_CLIENT_ID")

        # Verify the token with Google
        id_info = id_token.verify_oauth2_token(
            token, 
            google_requests.Request(),
            google_client_id,
            clock_skew_in_seconds=10
        )

        # Check if user exists in our database
        user = User.query.filter_by(email=id_info.get('email')).first()

        if not user:
            # User does not exist, create a new one
            print(f"Creating new user for email: {id_info.get('email')}")
            user = User(
                name=id_info.get('name'),
                email=id_info.get('email'),
                picture=id_info.get('picture'), # Corrected field name
                is_google_user=True
            )
            db.session.add(user)
            db.session.commit()
        else:
            # User exists, ensure they are marked as a Google user
            if not user.is_google_user:
                user.is_google_user = True
                db.session.commit()
        
        # Create a new session for the user
        session.clear()
        session['logged_in'] = True
        session['user_id'] = user.id  # This is your app's local user ID
        session['user_name'] = user.name
        session['user_email'] = user.email
        session['user_picture'] = user.picture
        
        return {"success": True}
    
    except ValueError as e:
        print(f"TOKEN VERIFICATION FAILED: {e}")
        return {"success": False, "message": "Invalid or expired token", "details": str(e)}, 401
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return {"success": False, "message": "An internal error occurred"}, 500

# ---------------------- Journal Feature Routes (Corrected) ----------------------

from services.media_client import get_media_recommendations
from services.music import get_music_recommendations


@app.route('/analyze', methods=['POST'])
@login_required
def analyze():
    entry_text = request.form['entry']
    if not entry_text.strip():
        return redirect(url_for('home'))

    # 🧠 Run NLP analysis
    result = analyze_text(entry_text)
    detected_mood = result['mood']

    # 🎶 Get Spotify playlists dynamically
    music_recs = get_music_recommendations(detected_mood)

    # 🎥 Get YouTube video recommendations
    video_recs = get_media_recommendations(detected_mood, region="IN")[:2] 
    

    # 📝 Save journal entry
    new_entry = JournalEntry(
        text=entry_text,
        user_id=session['user_id'],
        sentiment=result['sentiment'],
        emotion=result['mood'],
        suggestion=result['suggestion']
    )
    db.session.add(new_entry)
    db.session.commit()
    
    return render_template(
        'result.html',
        result=result,
        text=entry_text,
        music_recs=music_recs,
        video_recs=video_recs
    )


@app.route('/history')
@login_required
def history():
    entries = JournalEntry.query.filter_by(user_id=session['user_id']).order_by(JournalEntry.date.desc()).all()
    return render_template('history.html', entries=entries)

@app.route('/delete/<int:entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
    entry = JournalEntry.query.get_or_404(entry_id)
    if entry.user_id != session['user_id']:
        abort(403) # Forbidden
        
    db.session.delete(entry)
    db.session.commit()
    return '', 204

@app.route('/edit/<int:entry_id>', methods=['GET', 'POST'])
@login_required
def edit_entry(entry_id):
    entry = JournalEntry.query.get_or_404(entry_id)
    if entry.user_id != session['user_id']:
        abort(403) # Forbidden

    if request.method == 'POST':
        entry.text = request.form['entry']
        result = analyze_text(entry.text)
        entry.sentiment = result['sentiment']
        entry.emotion = result['mood']
        entry.suggestion = result['suggestion']
        db.session.commit()
        return redirect(url_for('history'))
        
    return render_template('edit.html', entry=entry)

@app.route('/dashboard')
@login_required
def dashboard():
    print("SESSION BEFORE DASHBOARD:", session)
    entries = JournalEntry.query.filter_by(
        user_id=session['user_id']
    ).order_by(JournalEntry.date.asc()).all()

    dates = [entry.date.strftime('%Y-%m-%d') for entry in entries]
    moods = [entry.sentiment for entry in entries]
    emotions = [entry.emotion for entry in entries]
    
    return render_template('dashboard.html', dates=dates, moods=moods, emotions=emotions)

@app.route('/users')
@login_required
def users():
    google_users = User.query.filter_by(is_google_user=True).order_by(User.created_at.desc()).all()
    local_users = User.query.filter_by(is_google_user=False).order_by(User.created_at.desc()).all()


@app.route('/export/csv')
@login_required
def export_csv():
    # 1. Fetch all of the user's journal entries
    entries = JournalEntry.query.filter_by(user_id=session['user_id']).order_by(JournalEntry.date.asc()).all()

    # 2. Use io.StringIO to create a text file in memory
    string_io = io.StringIO()
    csv_writer = csv.writer(string_io)

    # 3. Write the header row
    csv_writer.writerow(['Date', 'Sentiment', 'Emotion', 'Text', 'Suggestion'])

    # 4. Write a row for each journal entry
    for entry in entries:
        csv_writer.writerow([
            entry.date.strftime('%Y-%m-%d %H:%M:%S'),
            entry.sentiment,
            entry.emotion,
            entry.text,
            entry.suggestion
        ])

    # 5. Prepare the data to be sent back as a file
    output = string_io.getvalue()
    string_io.close()

    # 6. Create a Flask Response to send the file to the user
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=journal_history.csv"}
    )
    
# ---------------------- Run App ----------------------

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)