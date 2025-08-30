# services/emotion_playlists.py
import random

# Dictionary of emotion → playlist keyword variations
emotion_playlist_keywords = {
    "sadness": [
        "sad acoustic playlist",
        "deep emotional piano",
        "lofi sad beats",
        "heartbreak indie songs",
        "melancholy soft playlist"
    ],
    "joy": [
        "happy upbeat indie",
        "summer vibes playlist",
        "feel good pop anthems",
        "dance joyful tracks",
        "bright cheerful songs"
    ],
    "anger": [
        "angry rock playlist",
        "metal rage music",
        "hardcore rap aggressive",
        "punk anger tracks",
        "heavy bass aggressive songs"
    ],
    "nervousness": [
        "fast paced lofi",
        "anxious instrumental beats",
        "tense thriller background",
        "nervous ambient playlist",
        "heartbeat drum tracks"
    ],
    "desire": [
        "romantic r&b playlist",
        "passionate love songs",
        "intense emotional ballads",
        "sultry jazz vibes",
        "desire chillhop tracks"
    ],
    "default": [
        "chill lofi beats",
        "study instrumental playlist",
        "neutral calm vibes",
        "background jazz music",
        "soft ambient playlist"
    ]
}

def get_random_playlist_keyword(emotion: str) -> str:
    """Return a random playlist keyword for a given emotion, defaulting if unknown."""
    if emotion in emotion_playlist_keywords:
        return random.choice(emotion_playlist_keywords[emotion])
    return random.choice(emotion_playlist_keywords["default"])
