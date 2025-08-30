# process_dataset.py
import pandas as pd
import pprint

# --- CONFIGURATION ---
# 1. IMPORTANT: Change this to the exact name of the CSV file you downloaded from Kaggle.
CSV_FILE_NAME = 'tracks.csv'

# 2. Set the number of recommendations to generate for each emotion.
NUM_RECS_PER_EMOTION = 6

# --- SCRIPT LOGIC ---
print(f"Loading dataset from '{CSV_FILE_NAME}'...")
try:
    df = pd.read_csv(CSV_FILE_NAME)
    # Check if the required columns exist in the DataFrame.
    if 'track_id' in df.columns:
        ID_COLUMN_NAME = 'track_id'
    elif 'id' in df.columns:
        ID_COLUMN_NAME = 'id'
    else:
        print("ERROR: Could not find an 'id' or 'track_id' column in the CSV file.")
        exit()
    print("Dataset loaded successfully.")
except FileNotFoundError:
    print(f"ERROR: The file '{CSV_FILE_NAME}' was not found in this directory.")
    print("Please make sure the CSV file is in the same folder as this script.")
    exit()

# Define the audio feature profiles for each emotion.
# These rules filter the large dataset to find songs that match a mood.
emotion_profiles = {
    "sadness": df[(df['valence'] < 0.3) & (df['energy'] < 0.4) & (df['acousticness'] > 0.6)],
    "joy": df[(df['valence'] > 0.7) & (df['energy'] > 0.7) & (df['danceability'] > 0.6)],
    "anger": df[(df['valence'] < 0.4) & (df['energy'] > 0.8)],
    "nervousness": df[(df['valence'] < 0.4) & (df['energy'] < 0.3) & (df['instrumentalness'] > 0.5)],
    "excitement": df[(df['valence'] > 0.6) & (df['energy'] > 0.8) & (df['danceability'] > 0.7)],
    "default": df[(df['valence'].between(0.4, 0.6)) & (df['energy'].between(0.3, 0.5))]
}

# --- GENERATE THE DICTIONARY ---
final_music_recs = {}
print("\nGenerating recommendations for each emotion...")

for emotion, filtered_df in emotion_profiles.items():
    if not filtered_df.empty and len(filtered_df) >= NUM_RECS_PER_EMOTION:
        # Get random samples and format them into the required dictionary structure.
        samples = filtered_df.sample(n=NUM_RECS_PER_EMOTION)
        final_music_recs[emotion] = [{"id": track_id} for track_id in samples[ID_COLUMN_NAME]]
        print(f"  - Generated {NUM_RECS_PER_EMOTION} recommendations for '{emotion}'.")
    else:
        print(f"  - Could not find enough tracks for '{emotion}'. Using a fallback.")
        final_music_recs[emotion] = [{"id": "5qap5aO4i9A"}] # Fallback track: "Weightless"

# --- PRINT THE FINAL RESULT ---
# Use pprint to make the dictionary easy to copy and paste.
print("\n--- ✅ SUCCESS! COPY THE DICTIONARY BELOW ---")
print("\nLOCAL_MUSIC_RECS = \\")
pprint.pprint(final_music_recs)