# services/nlp_analyzer.py

import random
from transformers import pipeline

# ---------------------- 1. Initialize Models ----------------------
print("Initializing NLP models... This may take a moment on first startup.")

sentiment_analyzer = pipeline("sentiment-analysis", model="distilbert-base-uncased-finetuned-sst-2-english")
emotion_classifier = pipeline("text-classification", model="SamLowe/roberta-base-go_emotions", top_k=None)
# This model will now be used for more descriptive sentence generation
topic_extractor = pipeline("text2text-generation", model="google/flan-t5-base")

print("NLP models initialized successfully.")


# ---------------------- 2. Logic Core ----------------------
# This section remains the same
SUGGESTION_MAP = {
    "sadness": {
        "empathetic_text": [
            "It sounds like you're going through a really tough time. It's completely okay to feel this way, and thank you for sharing it.",
            "Reading this, it's clear you're carrying a heavy weight right now. Thank you for trusting this space with your feelings.",
            "It takes courage to write about feelings like this. Please know that it's valid to feel exactly as you do."
        ],
        "actionable_suggestion": [
            "Try a self-compassion exercise, like writing down one kind thing about yourself or placing a hand on your heart and taking three deep breaths.",
            "Engage with something comforting, like wrapping yourself in a warm blanket or listening to a favorite album.",
            "Consider reaching out to a friend or family member you trust, even just to say hello."
        ]
    },
    "nervousness": {
        "empathetic_text": [
            "It sounds like there's a lot on your mind right now. That feeling of anxiety is tough, but let's try to find a moment of calm.",
            "These feelings of worry are completely understandable. Let's work through them together.",
            "It's clear you're dealing with a lot of pressure. Let's try a small exercise to ground ourselves."
        ],
        "actionable_suggestion": [
            "Try the 5-4-3-2-1 grounding method: name 5 things you can see, 4 you can touch, 3 you can hear, 2 you can smell, and 1 you can taste.",
            "Try 'Box Breathing' for one minute: Inhale for 4 seconds, hold for 4, exhale for 4, and hold for 4. This can help regulate your nervous system.",
            "Write down all your worries on a piece of paper. Getting them out of your head can make them feel more manageable."
        ]
    },
    "joy": {
        "empathetic_text": [
            "This is wonderful to read! It's so important to acknowledge and celebrate these moments of happiness.",
            "Thank you for sharing this bright spot! Let's hold onto this wonderful feeling.",
            "Reading this brought a smile to my face. It's fantastic that you had this positive experience."
        ],
        "actionable_suggestion": [
            "Take a minute to really savor this feeling. What does it feel like in your body? Try to remember it for later.",
            "Share this good news with someone! Spreading joy often amplifies it for everyone.",
            "Capture this moment. Write down a few more details about why it feels so good, or take a picture related to the happy event."
        ]
    },
    "desire": {
        "empathetic_text": [
            "It's clear that this is something you want very deeply. Acknowledging that strong desire is the first step.",
            "That feeling of wanting something is a powerful motivator. Thank you for sharing what's on your mind.",
            "Desire points us toward what we truly value. It's insightful to sit with that feeling and understand what it's telling you."
        ],
        "actionable_suggestion": [
            "Try breaking down what you desire into one small, achievable step you could take this week. Small actions can make a big goal feel more real.",
            "Consider writing down *why* you want this. Understanding the root of the desire can bring a lot of clarity and focus.",
            "Channel that wanting energy into planning. Spend 15 minutes outlining the steps that could lead you toward this goal."
        ]
    },
    "gratitude": {
        "empathetic_text": [
            "It's wonderful to see you acknowledging the good things. Gratitude is such a powerful feeling.",
            "Holding onto moments of gratitude can be so uplifting. Thanks for sharing this one.",
            "What a lovely thing to be thankful for. It's great that you're taking a moment to recognize it."
        ],
        "actionable_suggestion": [
            "Share this feeling. Tell someone what you're grateful for—it can brighten their day, too.",
            "Try 'gratitude journaling' right now. Write down two other small things from your day that brought you this feeling.",
            "Take a moment to simply sit with this feeling of thankfulness and let it sink in. No need to do anything else."
        ]
    },

    "anger": {
        "empathetic_text": [
            "Anger is a completely valid and normal emotion. It's a signal that a boundary may have been crossed or that something is unjust.",
            "It's okay to feel angry about this. Let's find a constructive way to process that powerful energy.",
            "Thank you for sharing this. Acknowledging anger, rather than suppressing it, is a healthy first step."
        ],
        "actionable_suggestion": [
            "Try to channel that physical energy. Go for a brisk walk, do some quick exercise, or even just clench and unclench your fists to release the tension safely.",
            "Consider writing down everything you're angry about in a 'brain dump'. You don't have to show it to anyone; the act of writing it out can be a release.",
            "Listen to some high-energy music. Sometimes, matching the energy of the emotion with music can help you process and move through it."
        ]
    },

    "remorse": {
        "empathetic_text": [
            "Feelings of remorse can be very heavy. It's a sign that you care deeply about your actions and their outcomes.",
            "It's brave to confront feelings of regret. Thank you for being so honest in this space.",
            "That feeling of wishing you could have done something differently is a powerful part of being human."
        ],
        "actionable_suggestion": [
            "Focus on self-forgiveness. Write down one thing you've learned from the situation, as every experience is a chance to grow.",
            "Think about what is within your control right now. Can you make amends, or can you plan to act differently in the future?",
            "Remind yourself that everyone makes mistakes. Try talking to yourself with the same kindness you would offer a good friend in the same situation."
        ]
    },
    "default": {
        "empathetic_text": ["Thank you for sharing your thoughts today. Taking the time to journal is a wonderful act of self-care."],
        "actionable_suggestion": ["As you reflect, consider one small thing you're looking forward to this week."]
    }
}
# Aliases
# In services/nlp_analyzer.py

# Aliases
SUGGESTION_MAP["disappointment"] = SUGGESTION_MAP["sadness"]
SUGGESTION_MAP["grief"] = SUGGESTION_MAP["sadness"]
SUGGESTION_MAP["remorse"] = SUGGESTION_MAP["sadness"]
SUGGESTION_MAP["embarrassment"] = SUGGESTION_MAP["sadness"]

SUGGESTION_MAP["excitement"] = SUGGESTION_MAP["joy"]
SUGGESTION_MAP["gratitude"] = SUGGESTION_MAP["joy"]
SUGGESTION_MAP["love"] = SUGGESTION_MAP["joy"]
SUGGESTION_MAP["optimism"] = SUGGESTION_MAP["joy"]
SUGGESTION_MAP["admiration"] = SUGGESTION_MAP["joy"]
SUGGESTION_MAP["approval"] = SUGGESTION_MAP["joy"]
SUGGESTION_MAP["caring"] = SUGGESTION_MAP["joy"]
SUGGESTION_MAP["pride"] = SUGGESTION_MAP["joy"]
SUGGESTION_MAP["relief"] = SUGGESTION_MAP["joy"]
SUGGESTION_MAP["amusement"] = SUGGESTION_MAP["joy"]
SUGGESTION_MAP["surprise"] = SUGGESTION_MAP["joy"]

SUGGESTION_MAP["fear"] = SUGGESTION_MAP["nervousness"]
SUGGESTION_MAP["annoyance"] = SUGGESTION_MAP["nervousness"]

SUGGESTION_MAP["disgust"] = SUGGESTION_MAP["anger"]
SUGGESTION_MAP["disapproval"] = SUGGESTION_MAP["anger"]

# Ensure desire has its own entry or an alias
SUGGESTION_MAP["desire"] = SUGGESTION_MAP.get("desire", SUGGESTION_MAP["default"])

SUGGESTION_MAP["neutral"] = SUGGESTION_MAP["default"]
SUGGESTION_MAP["curiosity"] = SUGGESTION_MAP["default"]
SUGGESTION_MAP["realization"] = SUGGESTION_MAP["default"]
SUGGESTION_MAP["confusion"] = SUGGESTION_MAP["default"]

# ---------------------- 3. Functions  ----------------------

#  an advanced prompt to generate a full sentence.
def generate_empathetic_sentence(journal_text):
    """
    Uses a generative model to create a full empathetic sentence that
    acknowledges the user's specific situation without repeating it.
    """
    prompt = f"""
    You are an empathetic companion. Your task is to read a user's journal entry and write a single, new sentence that paraphrases their core feeling or situation.

    **CRITICAL RULE:** You must NOT copy any phrases or full sentences from the user's entry. Your sentence must be your own words.Always speak in the second person (use "you" and "your").Do NOT use the first person ("I", "me", "my").Do NOT share your own opinions, feelings, or plans.Do NOT copy sentences from the user's entry.

    [Example]
    User's Entry: "I studied all week for the test but I still failed. I feel like a total idiot."
    Your Empathetic Paraphrase: "It sounds incredibly discouraging to have worked so hard and not gotten the result you hoped for."

    [User's Entry]
    "{journal_text}"

    [Your Empathetic Paraphrase]
    """
    try:
        # Increased token limit to allow for a full, descriptive sentence.
        outputs = topic_extractor(prompt, max_new_tokens=50, num_beams=5, early_stopping=True)
        return outputs[0]['generated_text'].strip()
    except Exception as e:
        print(f"Empathetic sentence generation failed: {e}")
        return ""

# This function remains the same, but will receive the new, longer snippet.
def get_empathetic_suggestion(emotion, personalized_snippet):
    suggestion_data = SUGGESTION_MAP.get(emotion, SUGGESTION_MAP.get("default", {}))
    chosen_intro = random.choice(suggestion_data.get('empathetic_text', [""]))
    chosen_action = random.choice(suggestion_data.get('actionable_suggestion', [""]))
    
    # We add an extra space only if the snippet exists, to keep formatting clean.
    full_suggestion = f"{chosen_intro}{' ' + personalized_snippet if personalized_snippet else ''} {chosen_action}"
    
    return full_suggestion

# ✨ UPDATED LOGIC: This function now calls the new sentence generator.
def analyze_text(text):
    """
    Function to analyze text using the final hybrid approach.
    """
    if not text or not text.strip():
        # No changes to empty input handling
        default_suggestion_data = SUGGESTION_MAP["default"]
        chosen_intro = random.choice(default_suggestion_data['empathetic_text'])
        chosen_action = random.choice(default_suggestion_data['actionable_suggestion'])
        return {
            "text": text, "mood": "Neutral", "sentiment": "NEUTRAL",
            "suggestion": f"{chosen_intro} {chosen_action}"
        }

    # Step 1: Core analysis
    sentiment_label = sentiment_analyzer(text)[0]['label']
    emotion_result = emotion_classifier(text)
    primary_emotion = emotion_result[0][0]['label'] if emotion_result and emotion_result[0] else "neutral"

    # Step 2: Generate the new, full empathetic sentence.
    empathetic_sentence = generate_empathetic_sentence(text)
    
    # Safety check for overly long or repetitive sentences.
    if len(empathetic_sentence.split()) > 30 or empathetic_sentence.lower() in text.lower():
        empathetic_sentence = ""

    # Step 3: Get the full suggestion using the new sentence
    suggestion = get_empathetic_suggestion(primary_emotion, empathetic_sentence)

    # Step 4: Return the final dictionary
    return {
        "text": text,
        "mood": primary_emotion.capitalize(),
        "sentiment": sentiment_label,
        "suggestion": suggestion
    }