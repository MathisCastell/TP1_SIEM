import re
import math
from collections import Counter
from datetime import datetime

PATTERNS = {
    "email": r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    "carte_bancaire": r'\b(?:\d{4}[\s\-]?){3}\d{4}\b',
    "telephone_fr": r'\b(?:0[67][\s.\-]?(?:\d{2}[\s.\-]?){4}|\+33[\s.\-]?[67][\s.\-]?(?:\d{2}[\s.\-]?){4})\b',
    "numero_secu": r'\b[12]\d{2}(?:0[1-9]|1[0-2])\d{2}\d{3}\d{3}\d{2}\b',
}

def detect_regex(text):
    detections = []
    for data_type, pattern in PATTERNS.items():
        matches = re.finditer(pattern, text)
        for match in matches:
            detections.append({
                "type": data_type,
                "value": match.group(),
                "start": match.start(),
                "end": match.end(),
                "method": "regex",
                "timestamp": datetime.now().isoformat()
            })
    return detections


def calculate_entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy


def extract_string_features(text):
    length = len(text)
    if length == 0:
        return [0, 0, 0, 0, 0, 0]

    uppercase_ratio = sum(1 for c in text if c.isupper()) / length
    digit_ratio = sum(1 for c in text if c.isdigit()) / length
    special_ratio = sum(1 for c in text if not c.isalnum()) / length
    entropy = calculate_entropy(text)
    has_mixed = 1 if (any(c.isupper() for c in text) and any(c.islower() for c in text) and any(c.isdigit() for c in text)) else 0

    return [length, uppercase_ratio, digit_ratio, special_ratio, entropy, has_mixed]


def is_password_like(text):
    text = text.strip()
    if len(text) < 8:
        return False
    if " " in text:
        return False

    features = extract_string_features(text)
    length, uppercase_ratio, digit_ratio, special_ratio, entropy, has_mixed = features

    score = 0
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if has_mixed:
        score += 2
    if special_ratio > 0:
        score += 1
    if entropy > 3.0:
        score += 1
    if entropy > 4.0:
        score += 1

    return score >= 3


def detect_sensitive(text):
    detections = detect_regex(text)

    words = text.split()
    for word in words:
        already_detected = False
        for d in detections:
            if word in d["value"] or d["value"] in word:
                already_detected = True
                break
        if not already_detected and is_password_like(word):
            detections.append({
                "type": "mot_de_passe_probable",
                "value": word,
                "start": text.find(word),
                "end": text.find(word) + len(word),
                "method": "heuristique",
                "timestamp": datetime.now().isoformat()
            })

    return detections


def mask_sensitive(text, detections):
    sorted_detections = sorted(detections, key=lambda d: d["start"], reverse=True)
    masked = text
    for d in sorted_detections:
        original = d["value"]
        if d["type"] == "email":
            parts = original.split("@")
            mask = parts[0][0] + "****@" + parts[1]
        elif d["type"] == "carte_bancaire":
            clean = re.sub(r'[\s\-]', '', original)
            mask = "****-****-****-" + clean[-4:]
        elif d["type"] == "telephone_fr":
            mask = "** ** ** ** " + original[-2:]
        elif d["type"] == "numero_secu":
            mask = "* ** ** *** *** " + original[-2:]
        else:
            mask = "*" * len(original)
        masked = masked[:d["start"]] + mask + masked[d["end"]:]
    return masked


if __name__ == "__main__":
    tests = [
        "Mon email est mathis.dupont@gmail.com et mon tel 06 12 34 56 78",
        "Carte: 4970 1234 5678 9012 merci",
        "Mon mot de passe est Tr0ub4dor&3 ne le dis a personne",
        "Bonjour je vais bien merci",
        "Secu: 185073512345678",
        "password: G7#kLm9@vXp2!qR",
        "il fait beau aujourd'hui",
    ]

    for text in tests:
        print(f"\n--- Texte: '{text}'")
        detections = detect_sensitive(text)
        if detections:
            for d in detections:
                print(f"  [{d['type']}] '{d['value']}' (methode: {d['method']})")
            masked = mask_sensitive(text, detections)
            print(f"  Masque: '{masked}'")
        else:
            print("  Aucune donnee sensible detectee")