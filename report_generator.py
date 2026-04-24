import json
import os
import base64
from datetime import datetime
from collections import Counter
from io import BytesIO

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns
import numpy as np

from wordcloud import WordCloud

SENTIMENT_PATH = os.path.join(os.getcwd(), "data", "sentiments.json")
KEYSTROKE_PATH = os.path.join(os.getcwd(), "data", "keystrokes.json")
ALERT_PATH = os.path.join(os.getcwd(), "data", "alerts.json")
SENSITIVE_PATH = os.path.join(os.getcwd(), "data", "sensitive_detections.json")
LOG_PATH = os.path.join(os.getcwd(), "data", "log.txt")
OUTPUT_DIR = os.path.join(os.getcwd(), "data", "reports")

os.makedirs(OUTPUT_DIR, exist_ok=True)


def load_json(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return []


def fig_to_base64(fig):
    buf = BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight")
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode("utf-8")
    plt.close(fig)
    return b64


def generate_sentiment_chart():
    data = load_json(SENTIMENT_PATH)
    if not data:
        return None

    timestamps = []
    scores = []
    for entry in data:
        try:
            ts = datetime.fromisoformat(entry["timestamp"])
            timestamps.append(ts)
            scores.append(entry["score"])
        except (KeyError, ValueError):
            continue

    if not timestamps:
        return None

    fig, ax = plt.subplots(figsize=(12, 5))

    ax.plot(timestamps, scores, color="#2196F3", linewidth=1.5, marker="o", markersize=3)

    ax.fill_between(timestamps, scores, 0,
                    where=[s > 0.05 for s in scores],
                    color="#4CAF50", alpha=0.3, label="Positif")
    ax.fill_between(timestamps, scores, 0,
                    where=[s < -0.05 for s in scores],
                    color="#F44336", alpha=0.3, label="Negatif")

    ax.axhline(y=0.05, color="#4CAF50", linestyle="--", linewidth=0.8, alpha=0.5)
    ax.axhline(y=-0.05, color="#F44336", linestyle="--", linewidth=0.8, alpha=0.5)
    ax.axhline(y=0, color="gray", linestyle="-", linewidth=0.5, alpha=0.5)

    ax.set_title("Evolution des sentiments dans le temps", fontsize=14, fontweight="bold")
    ax.set_xlabel("Temps")
    ax.set_ylabel("Score de sentiment")
    ax.set_ylim(-1.1, 1.1)
    ax.legend()
    ax.grid(True, alpha=0.3)

    fig.autofmt_xdate()

    save_path = os.path.join(OUTPUT_DIR, "sentiment_chart.png")
    fig.savefig(save_path, dpi=150, bbox_inches="tight")
    return fig_to_base64(fig)


def generate_delay_histogram():
    data = load_json(KEYSTROKE_PATH)
    if not data:
        return None

    delays = []
    for entry in data:
        d = entry.get("inter_key_delay", 0)
        if 0 < d < 5:
            delays.append(d)

    if not delays:
        return None

    fig, ax = plt.subplots(figsize=(10, 5))

    sns.histplot(delays, bins=50, kde=True, color="#673AB7", ax=ax)

    mean_delay = np.mean(delays)
    ax.axvline(x=mean_delay, color="#FF9800", linestyle="--", linewidth=2,
               label=f"Moyenne: {mean_delay:.3f}s")

    ax.set_title("Distribution des delais inter-touches", fontsize=14, fontweight="bold")
    ax.set_xlabel("Delai (secondes)")
    ax.set_ylabel("Frequence")
    ax.legend()
    ax.grid(True, alpha=0.3)

    save_path = os.path.join(OUTPUT_DIR, "delay_histogram.png")
    fig.savefig(save_path, dpi=150, bbox_inches="tight")
    return fig_to_base64(fig)


def generate_activity_heatmap():
    data = load_json(KEYSTROKE_PATH)
    if not data:
        return None

    days = ["Lundi", "Mardi", "Mercredi", "Jeudi", "Vendredi", "Samedi", "Dimanche"]
    matrix = np.zeros((24, 7))

    for entry in data:
        try:
            ts = datetime.fromisoformat(entry["timestamp"])
            hour = ts.hour
            day = ts.weekday()
            matrix[hour][day] += 1
        except (KeyError, ValueError):
            continue

    if matrix.sum() == 0:
        return None

    fig, ax = plt.subplots(figsize=(10, 8))

    sns.heatmap(matrix, xticklabels=days, yticklabels=range(24),
                cmap="YlOrRd", annot=False, fmt=".0f", ax=ax,
                cbar_kws={"label": "Nombre de frappes"})

    ax.set_title("Heatmap d'activite horaire", fontsize=14, fontweight="bold")
    ax.set_xlabel("Jour de la semaine")
    ax.set_ylabel("Heure")

    save_path = os.path.join(OUTPUT_DIR, "activity_heatmap.png")
    fig.savefig(save_path, dpi=150, bbox_inches="tight")
    return fig_to_base64(fig)


def generate_sensitive_piechart():
    data = load_json(SENSITIVE_PATH)
    if not data:
        return None

    types = [entry.get("type", "inconnu") for entry in data]
    counts = Counter(types)

    if not counts:
        return None

    fig, ax = plt.subplots(figsize=(8, 8))

    colors = ["#F44336", "#2196F3", "#FF9800", "#4CAF50", "#9C27B0"]
    labels = list(counts.keys())
    sizes = list(counts.values())

    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, autopct="%1.1f%%",
        colors=colors[:len(labels)],
        startangle=90, pctdistance=0.85
    )

    centre_circle = plt.Circle((0, 0), 0.70, fc="white")
    ax.add_artist(centre_circle)

    ax.set_title("Proportion de donnees sensibles detectees", fontsize=14, fontweight="bold")

    save_path = os.path.join(OUTPUT_DIR, "sensitive_piechart.png")
    fig.savefig(save_path, dpi=150, bbox_inches="tight")
    return fig_to_base64(fig)


def generate_anomaly_timeline():
    data = load_json(ALERT_PATH)
    if not data:
        return None

    timestamps = []
    delays = []
    for entry in data:
        try:
            ts = datetime.fromisoformat(entry["timestamp"])
            timestamps.append(ts)
            delay = entry.get("details", {}).get("inter_key_delay", 0)
            delays.append(delay)
        except (KeyError, ValueError):
            continue

    if not timestamps:
        return None

    fig, ax = plt.subplots(figsize=(12, 5))

    ax.scatter(timestamps, delays, color="#F44336", s=80, marker="x",
               linewidths=2, label="Anomalie detectee", zorder=5)

    ax.set_title("Timeline des anomalies detectees", fontsize=14, fontweight="bold")
    ax.set_xlabel("Temps")
    ax.set_ylabel("Delai inter-touches (s)")
    ax.legend()
    ax.grid(True, alpha=0.3)

    fig.autofmt_xdate()

    save_path = os.path.join(OUTPUT_DIR, "anomaly_timeline.png")
    fig.savefig(save_path, dpi=150, bbox_inches="tight")
    return fig_to_base64(fig)


def generate_wordcloud():
    if not os.path.exists(LOG_PATH):
        return None

    with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    text = text.replace("****", "").replace("\n", " ")
    text = text.strip()

    if len(text) < 10:
        return None

    stopwords = {"le", "la", "les", "de", "du", "des", "un", "une", "et", "est",
                 "en", "que", "qui", "dans", "pour", "pas", "sur", "au", "ce",
                 "il", "ne", "se", "son", "mon", "ton", "the", "is", "a", "to",
                 "and", "of", "in", "it", "my", "this", "that", "je", "tu"}

    wc = WordCloud(
        width=800, height=400,
        background_color="white",
        colormap="viridis",
        stopwords=stopwords,
        max_words=50,
        min_word_length=3
    ).generate(text)

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.imshow(wc, interpolation="bilinear")
    ax.axis("off")
    ax.set_title("Nuage de mots des frappes", fontsize=14, fontweight="bold")

    save_path = os.path.join(OUTPUT_DIR, "wordcloud.png")
    fig.savefig(save_path, dpi=150, bbox_inches="tight")
    return fig_to_base64(fig)


def generate_text_summary():
    sentiments = load_json(SENTIMENT_PATH)
    keystrokes = load_json(KEYSTROKE_PATH)
    alerts = load_json(ALERT_PATH)
    sensitive = load_json(SENSITIVE_PATH)

    total_frappes = len(keystrokes)
    total_alertes = len(alerts)
    total_sensibles = len(sensitive)
    total_phrases = len(sentiments)

    if sentiments:
        scores = [s["score"] for s in sentiments]
        avg_sentiment = np.mean(scores)
        positifs = sum(1 for s in sentiments if s["label"] == "positif")
        negatifs = sum(1 for s in sentiments if s["label"] == "negatif")
        neutres = sum(1 for s in sentiments if s["label"] == "neutre")
    else:
        avg_sentiment = 0
        positifs = negatifs = neutres = 0

    if keystrokes:
        delays = [k["inter_key_delay"] for k in keystrokes if 0 < k["inter_key_delay"] < 5]
        avg_delay = np.mean(delays) if delays else 0
        avg_wpm = (1 / avg_delay) * 12 if avg_delay > 0 else 0
    else:
        avg_delay = 0
        avg_wpm = 0

    if sensitive:
        types_sensibles = Counter([s["type"] for s in sensitive])
        types_str = ", ".join([f"{v} {k}" for k, v in types_sensibles.items()])
    else:
        types_str = "aucune"

    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        words = text.split()
        word_counts = Counter(words)
        common_words = [w for w, c in word_counts.most_common(20) if len(w) >= 3 and w not in {"les", "des", "une", "the", "and", "est"}]
        top_words = ", ".join(common_words[:10])
    else:
        top_words = "aucune donnee"

    summary = f"""RAPPORT D'ANALYSE COMPORTEMENTALE
{'='*50}
Date de generation : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}

STATISTIQUES GENERALES
- Nombre total de frappes enregistrees : {total_frappes}
- Nombre de phrases analysees : {total_phrases}
- Vitesse de frappe moyenne estimee : {avg_wpm:.0f} mots/minute
- Delai moyen inter-touches : {avg_delay:.3f} secondes

ANALYSE DE SENTIMENTS
- Score moyen de sentiment : {avg_sentiment:.3f}
- Phrases positives : {positifs}
- Phrases negatives : {negatifs}
- Phrases neutres : {neutres}

DONNEES SENSIBLES
- Nombre total de detections : {total_sensibles}
- Types detectes : {types_str}

ANOMALIES
- Nombre total d'alertes : {total_alertes}

MOTS LES PLUS FREQUENTS
- {top_words}
"""
    return summary


def generate_html_report():
    print("Generation des graphiques...")

    charts = {}

    print("  -> Sentiment chart...")
    charts["sentiment"] = generate_sentiment_chart()

    print("  -> Delay histogram...")
    charts["delay"] = generate_delay_histogram()

    print("  -> Activity heatmap...")
    charts["heatmap"] = generate_activity_heatmap()

    print("  -> Sensitive piechart...")
    charts["sensitive"] = generate_sensitive_piechart()

    print("  -> Anomaly timeline...")
    charts["anomaly"] = generate_anomaly_timeline()

    print("  -> Word cloud...")
    charts["wordcloud"] = generate_wordcloud()

    print("Generation du resume textuel...")
    summary = generate_text_summary()

    print("Construction du rapport HTML...")

    html_template = """<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'analyse comportementale</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #1a237e;
            border-bottom: 3px solid #1a237e;
            padding-bottom: 15px;
            text-align: center;
        }}
        h2 {{
            color: #283593;
            border-bottom: 1px solid #e0e0e0;
            padding-bottom: 10px;
            margin-top: 40px;
        }}
        .summary {{
            background: #e8eaf6;
            padding: 20px;
            border-radius: 8px;
            white-space: pre-line;
            font-family: 'Consolas', monospace;
            font-size: 13px;
            line-height: 1.6;
        }}
        .chart-container {{
            text-align: center;
            margin: 30px 0;
        }}
        .chart-container img {{
            max-width: 100%;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
        }}
        .no-data {{
            color: #999;
            font-style: italic;
            text-align: center;
            padding: 40px;
            background: #fafafa;
            border-radius: 4px;
        }}
        .footer {{
            text-align: center;
            color: #999;
            margin-top: 40px;
            font-size: 12px;
        }}
        .metadata {{
            text-align: center;
            color: #666;
            margin-bottom: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Rapport d'analyse comportementale clavier</h1>
        <p class="metadata">Genere le {date} | TP1 IA & Cybersecurite — Mathis</p>

        <h2>Resume</h2>
        <div class="summary">{summary}</div>

        <h2>Evolution des sentiments</h2>
        {sentiment_section}

        <h2>Distribution des delais inter-touches</h2>
        {delay_section}

        <h2>Heatmap d'activite horaire</h2>
        {heatmap_section}

        <h2>Donnees sensibles detectees</h2>
        {sensitive_section}

        <h2>Timeline des anomalies</h2>
        {anomaly_section}

        <h2>Nuage de mots</h2>
        {wordcloud_section}

        <div class="footer">
            Rapport genere automatiquement — AI Keylogger Analysis Tool
        </div>
    </div>
</body>
</html>"""

    def make_section(b64):
        if b64:
            return f'<div class="chart-container"><img src="data:image/png;base64,{b64}" alt="graphique"></div>'
        return '<div class="no-data">Pas assez de donnees pour generer ce graphique.</div>'

    html = html_template.format(
        date=datetime.now().strftime("%d/%m/%Y a %H:%M:%S"),
        summary=summary,
        sentiment_section=make_section(charts["sentiment"]),
        delay_section=make_section(charts["delay"]),
        heatmap_section=make_section(charts["heatmap"]),
        sensitive_section=make_section(charts["sensitive"]),
        anomaly_section=make_section(charts["anomaly"]),
        wordcloud_section=make_section(charts["wordcloud"])
    )

    report_path = os.path.join(OUTPUT_DIR, "rapport_analyse.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\nRapport genere avec succes : {report_path}")
    return report_path


if __name__ == "__main__":
    generate_html_report()