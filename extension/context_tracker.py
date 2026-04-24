import win32gui
import win32process
import psutil

def get_active_window():
    try:
        hwnd = win32gui.GetForegroundWindow()
        window_title = win32gui.GetWindowText(hwnd)

        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        try:
            process = psutil.Process(pid)
            process_name = process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            process_name = "inconnu"

        return {
            "window_title": window_title if window_title else "Sans titre",
            "process_name": process_name
        }
    except Exception:
        return {
            "window_title": "inconnu",
            "process_name": "inconnu"
        }


if __name__ == "__main__":
    import time
    print("Test du context tracker (5 secondes, change de fenetre pour voir)...")
    for i in range(10):
        info = get_active_window()
        print(f"  [{i}] {info['process_name']} - {info['window_title']}")
        time.sleep(0.5)