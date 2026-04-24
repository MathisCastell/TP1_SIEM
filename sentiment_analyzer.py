from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
from datetime import datetime

analyzer = SentimentIntensityAnalyzer()

def analyze_sentiment(text):
    if len(text.split()) < 3:
        return {
            "score": 0.0,
            "label": "neutre",
            "timestamp": datetime.now().isoformat()
        }

    scores = analyzer.polarity_scores(text)
    compound = scores["compound"]

    if compound > 0.05:
        label = "positif"
    elif compound < -0.05:
        label = "negatif"
    else:
        label = "neutre"

    return {
        "score": compound,
        "label": label,
        "timestamp": datetime.now().isoformat()
    }


if __name__ == "__main__":
    tests = [
        "I love this amazing day!",
        "I hate everything about this",
        "The weather is okay",
        "Hi",
    ]
    for t in tests:
        result = analyze_sentiment(t)
        print(f"Texte: '{t}' => {result}")