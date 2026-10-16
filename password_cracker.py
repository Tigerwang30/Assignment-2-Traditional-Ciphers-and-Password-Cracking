import hashlib
import itertools
import time

def load_shadow(file_path):
    users = {}
    with open(file_path, "r") as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) >= 2:
                username = parts[0]
                password_hash = parts[1]
                users[username] = password_hash
    return users

def load_dict(file_path):
    with open(file_path, "r") as f:
        return {line.strip(): None for line in f}

LENGTH_TO_ALGOS = {32: ['md5'], 40: ['sha1'], 56: ['sha224', 'sha3_224'],
                    64: ['sha256', 'sha3_256'], 96: ['sha384', 'sha3_384'],
                    128: ['sha512', 'sha3_512']}

def identify_algos(hash_str):
    return LENGTH_TO_ALGOS.get(len(hash_str), [])

def hash_matches(password, hash_str):
    for algo in identify_algos(hash_str):
        hasher = hashlib.new(algo)
        hasher.update(password.encode())
        if hasher.hexdigest() == hash_str:
            return True
    return False

def crack_plain(username, password_hash, dictionary):
    for password in dictionary.keys():
        if hash_matches(password, password_hash):
            return password
    return None

def crack_salted(username, password_hash, dictionary):
    algos = identify_algos(password_hash)
    if not algos:
        return None

    for password in dictionary.keys():
        for algo in algos:
            base = hashlib.new(algo)
            base.update(password.encode())
            for saltInt in range(100000):
                salt = f"{saltInt:05d}"
                h = base.copy()
                h.update(salt.encode())
                if h.hexdigest() == password_hash:
                    return password
    return None

def caeser_shift(text, shift):
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)

def crack_caesar(username, password_hash, dictionary):
    for word in dictionary.keys():
        for shiftInt in range(26):
            shifted_word = caeser_shift(word, shiftInt)
            if hash_matches(shifted_word, password_hash):
                return word
    return None

LEET_MAP = {
    'a': ['a', '4'],
    'e': ['e', '3'],
    'i': ['i', '1'],
    'o': ['o', '0'],
    's': ['s', '5'],
    't': ['t', '7'],
}

def generate_leet_variations(word):
    options = []
    for ch in word:
        leet_chars = LEET_MAP.get(ch)
        if leet_chars:
            options.append(list(dict.fromkeys(leet_chars + [ch])))
        else:
            options.append([ch])
    return {''.join(combo) for combo in itertools.product(*options)}

def crack_leetspeak(username, password_hash, dictionary):
    for word in dictionary.keys():
        leet_variations = generate_leet_variations(word)
        for variation in leet_variations:
            if hash_matches(variation, password_hash):
                return word
    return None

# cipher -> plaintext mapping recovered from encrypted.txt via analysis.py's
# frequency analysis; user7's password was substituted with the same cipher
# before hashing, so cracking it means re-encoding dictionary words with the
# plaintext -> cipher direction (the inverse of this map) and hashing those.
CIPHER_TO_PLAIN = {
    's': 'a', 'b': 'z', 'c': 't', 'd': 'i', 'n': 'e', 'f': 's', 'g': 'b',
    'h': 'p', 'i': 'g', 'j': 'l', 'k': 'y', 'l': 'u', 'm': 'x', 'o': 'n',
    'p': 'q', 'q': 'c', 'r': 'm', 't': 'f', 'u': 'd', 'v': 'h', 'w': 'v',
    'x': 'w', 'y': 'r', 'z': 'o', 'e': 'k', 'a': 'j',
}
PLAIN_TO_CIPHER = {plain: cipher for cipher, plain in CIPHER_TO_PLAIN.items()}

def encode_with_cipher(word, plain_to_cipher):
    return ''.join(plain_to_cipher.get(ch, ch) for ch in word.lower())

def crack_substitution_cipher(username, password_hash, dictionary, plain_to_cipher):
    for word in dictionary.keys():
        encoded = encode_with_cipher(word, plain_to_cipher)
        if hash_matches(encoded, password_hash):
            return word
    return None

def main():
    shadow_file = input("Enter the path to the shadow file: ")
    dict_file = input("Enter the path to the dictionary file: ")

    users = load_shadow(shadow_file)
    dictionary = load_dict(dict_file)

    results = {}
    for username, password_hash in users.items():
        if username == "user7":
            start = time.time()
            password = crack_substitution_cipher(username, password_hash, dictionary, PLAIN_TO_CIPHER)
            elapsed = time.time() - start
            if password is not None:
                print(f"Cracked: {username}:{password} ({elapsed:.2f}s)")
                results[username] = password
            else:
                print(f"Could not crack: {username} ({elapsed:.2f}s)")
            continue

        start = time.time()
        password = crack_plain(username, password_hash, dictionary)
        if password is None:
            password = crack_caesar(username, password_hash, dictionary)
        if password is None:
            password = crack_leetspeak(username, password_hash, dictionary)
        if password is None:
            password = crack_salted(username, password_hash, dictionary)
        elapsed = time.time() - start

        if password is not None:
            print(f"Cracked: {username}:{password} ({elapsed:.2f}s)")
            results[username] = password
        else:
            print(f"Could not crack: {username} ({elapsed:.2f}s)")

    with open("passwords.txt", "w") as f:
        for username, password in results.items():
            f.write(f"{username}:{password}\n")

if __name__ == "__main__":
    main()
