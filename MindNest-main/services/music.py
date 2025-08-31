import requests
import base64
import os

# Load credentials from environment (safe practice)
SPOTIFY_CLIENT_ID = os.getenv("SPOTIFY_CLIENT_ID")
SPOTIFY_CLIENT_SECRET = os.getenv("SPOTIFY_CLIENT_SECRET")

def get_access_token():
    """
    Fetches a Spotify access token using Client Credentials Flow.
    """
    auth_string = f"{SPOTIFY_CLIENT_ID}:{SPOTIFY_CLIENT_SECRET}"
    auth_bytes = auth_string.encode("utf-8")
    auth_base64 = base64.b64encode(auth_bytes).decode("utf-8")

    url = "https://accounts.spotify.com/api/token"
    headers = {"Authorization": f"Basic {auth_base64}"}
    data = {"grant_type": "client_credentials"}

    response = requests.post(url, headers=headers, data=data)
    response.raise_for_status()
    return response.json()["access_token"]

def get_music_recommendations(mood: str, limit: int = 2):
    """
    Searches Spotify for playlists related to a mood (e.g., happy, sad).
    """
    token = get_access_token()
    if not token:
        return []
    url = f"https://api.spotify.com/v1/search?q={mood}%20mood&type=playlist&limit={limit}"
    headers = {"Authorization": f"Bearer {token}"}

    response = requests.get(url, headers=headers)
    response.raise_for_status()
    data = response.json()

    playlists = []
    for item in data.get("playlists", {}).get("items", []):
        if item:
            playlists.append({
                "title": item["name"],
                "id": item["id"],  # embed needs this
                "url": item["external_urls"]["spotify"]
            })
    
    return playlists
