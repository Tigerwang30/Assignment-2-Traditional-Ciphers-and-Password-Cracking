def get_letter_freq(text):
    freq = {}
    for ch in text.lower():
        if ch.isalpha():
            freq[ch] = freq.get(ch, 0) + 1
    return dict(sorted(freq.items(), key=lambda item: item[1], reverse=True))

def apply_mapping(text, mapping):
    result = []
    for ch in text:
        lower = ch.lower()
        if lower in mapping:
            sub = mapping[lower]
            result.append(sub.upper() if ch.isupper() else sub)
        else:
            result.append(ch)
    return ''.join(result)

def invert_mapping(mapping):
    return {v: k for k, v in mapping.items()}

def build_mapping_from_guess(guess, actual):
    mapping = {}
    for g, a in zip(guess, actual):
        if g.isalpha() and a.isalpha():
            mapping[g.lower()] = a.lower()
    return mapping

def decrypt_file(file_path, mapping, output_path):
    with open(file_path, "r") as f, open(output_path, "w") as out:
        for line in f:
            decrypted = apply_mapping(line.rstrip("\n"), mapping)
            out.write(decrypted + "\n")

def analyze_file(file_path):
    with open(file_path, "r") as f:
        text = f.read()
    freq = get_letter_freq(text)
    print("Letter Frequency (descending):")
    for ch, count in freq.items():
        print(f"{ch}: {count}")
    return freq

# Real cipher -> plaintext mapping, worked out from the frequency analysis above
# plus word-pattern guesses (single-letter words "I"/"a", "T" from "T-shirt", etc.)
# and cross-checked against dictionary.txt-style English words.
CIPHER_TO_PLAIN = {
    's': 'a', 'b': 'z', 'c': 't', 'd': 'i', 'n': 'e', 'f': 's', 'g': 'b',
    'h': 'p', 'i': 'g', 'j': 'l', 'k': 'y', 'l': 'u', 'm': 'x', 'o': 'n',
    'p': 'q', 'q': 'c', 'r': 'm', 't': 'f', 'u': 'd', 'v': 'h', 'w': 'v',
    'x': 'w', 'y': 'r', 'z': 'o', 'e': 'k', 'a': 'j',
}

def main():
    file_path = "encrypted.txt"
    analyze_file(file_path)
    decrypt_file(file_path, CIPHER_TO_PLAIN, "plaintext.txt")
    print("Wrote decrypted text to plaintext.txt")

if __name__ == "__main__":
    main()
