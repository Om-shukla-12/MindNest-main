from googleapiclient.discovery import build
import random
import os
from urllib.parse import urlparse, parse_qs

YOUTUBE_API_KEY = os.getenv("YOUTUBE_API_KEY")

def extract_youtube_id(url):
    """Extracts YouTube video ID from a URL."""
    if "youtube.com/watch" in url:
        query = urlparse(url)
        return parse_qs(query.query).get("v", [None])[0]
    elif "youtu.be" in url:
        return url.split("/")[-1]
    return None

def get_trending_videos(region="US", max_results=10):
    youtube = build("youtube", "v3", developerKey=YOUTUBE_API_KEY)
    request = youtube.videos().list(
        part="snippet",
        chart="mostPopular",
        maxResults=max_results,
        regionCode=region
    )
    response = request.execute()

    videos = []
    for item in response["items"]:
        video_id = item["id"]
        videos.append({
            "id": video_id,  # ✅ for embed
            "title": item["snippet"]["title"],
            "thumbnail": item["snippet"]["thumbnails"]["medium"]["url"],
            "url": f"https://www.youtube.com/watch?v={video_id}"
        })
    return videos

def get_emotion_videos(emotion):
    emotion_map = {
        "happy": ["upbeat music", "funny videos", "motivational speech"],
        "sad": ["relaxing music", "inspirational talk", "uplifting songs"],
        "angry": ["calming meditation", "peaceful nature sounds"],
        "anxious": ["guided meditation", "soothing music", "yoga"],
        "neutral": ["trending news", "popular playlists"]
    }
    query = random.choice(emotion_map.get(emotion, ["popular music"]))

    youtube = build("youtube", "v3", developerKey=YOUTUBE_API_KEY)
    request = youtube.search().list(
        part="snippet",
        q=query,
        type="video",
        maxResults=5
    )
    response = request.execute()

    videos = []
    for item in response["items"]:
        video_id = item["id"]["videoId"]
        videos.append({
            "id": video_id,  # ✅ for embed
            "title": item["snippet"]["title"],
            "thumbnail": item["snippet"]["thumbnails"]["medium"]["url"],
            "url": f"https://www.youtube.com/watch?v={video_id}"
        })
    return videos

def get_media_recommendations(emotion, region="IN"):
    trending = get_trending_videos(region=region, max_results=2)
    emotion_based = get_emotion_videos(emotion)
    combined = trending + emotion_based
    random.shuffle(combined)
    return combined
