"""
generator.py
Secure random password generation using Python's `secrets` module
(cryptographically strong, unlike `random`).
"""

import secrets
import string

AMBIGUOUS_CHARS = "Il1O0"
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/"


def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """
    Generate a random password.

    Guarantees at least one character from each selected character set,
    then fills the rest randomly and shuffles using a CSPRNG.
    """
    if length < 4:
        raise ValueError("Password length must be at least 4 characters.")

    pools = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append(SYMBOLS)

    if not pools:
        raise ValueError("At least one character set must be enabled.")

    if exclude_ambiguous:
        pools = ["".join(c for c in pool if c not in AMBIGUOUS_CHARS) for pool in pools]
        pools = [p for p in pools if p]  # drop any pool emptied out

    if length < len(pools):
        raise ValueError(
            f"Password length must be at least {len(pools)} to include all selected character sets."
        )

    all_chars = "".join(pools)

    # Guarantee representation from every selected pool.
    password_chars = [secrets.choice(pool) for pool in pools]

    remaining = length - len(password_chars)
    password_chars += [secrets.choice(all_chars) for _ in range(remaining)]

    # Secure shuffle (Fisher-Yates using a CSPRNG).
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)


def generate_passphrase(num_words: int = 4, separator: str = "-", word_list=None) -> str:
    """
    Generate a memorable passphrase from a word list (Diceware-style).
    Falls back to a small built-in word list if none is provided.
    """
    if word_list is None:
        word_list = _DEFAULT_WORDS
    if num_words < 3:
        raise ValueError("Use at least 3 words for a reasonably strong passphrase.")
    words = [secrets.choice(word_list) for _ in range(num_words)]
    return separator.join(words)


_DEFAULT_WORDS = [
    "anchor", "basil", "comet", "delta", "ember", "falcon", "granite", "harbor",
    "indigo", "jungle", "kettle", "lantern", "meadow", "nimbus", "oracle", "pebble",
    "quartz", "ribbon", "saffron", "tundra", "umber", "violet", "willow", "yonder",
    "zephyr", "bramble", "cinder", "drizzle", "ferret", "glacier", "hollow", "ivy",
]
