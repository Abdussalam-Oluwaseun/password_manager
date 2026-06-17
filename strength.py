"""
strength.py
Scores password strength using entropy estimation plus checks for
common passwords, dictionary words, sequences, and repeated characters.
"""

import math
import re

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "letmein",
    "monkey", "111111", "iloveyou", "admin", "welcome", "password1",
    "123123", "1234567", "1234567890", "dragon", "sunshine", "master",
    "football", "shadow", "michael", "trustno1", "superman", "qazwsx",
    "baseball", "michael", "ninja", "mustang", "starwars", "freedom",
}

LABELS = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong", "Excellent"]


def estimate_entropy(password: str) -> float:
    """Rough entropy estimate in bits, based on character pool size and length."""
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool_size += 32
    if pool_size == 0 or not password:
        return 0.0
    return len(password) * math.log2(pool_size)


def has_sequential_chars(password: str, run: int = 3) -> bool:
    """Detects ascending sequences like 'abc' or '123'."""
    lowered = password.lower()
    for i in range(len(lowered) - run + 1):
        chunk = lowered[i:i + run]
        if all(ord(chunk[j]) - ord(chunk[j - 1]) == 1 for j in range(1, len(chunk))):
            return True
    return False


def has_repeated_chars(password: str, run: int = 3) -> bool:
    """Detects the same character repeated `run` times in a row."""
    for i in range(len(password) - run + 1):
        if len(set(password[i:i + run])) == 1:
            return True
    return False


def check_strength(password: str) -> dict:
    """
    Returns a dict with: score (0-6), max_score, label, entropy_bits,
    and a list of feedback strings.
    """
    feedback = []
    score = 0

    if not password:
        return {
            "score": 0,
            "max_score": 6,
            "label": LABELS[0],
            "entropy_bits": 0.0,
            "feedback": ["Password is empty."],
        }

    length = len(password)
    if length < 8:
        feedback.append("Too short — use at least 12 characters.")
    elif length < 12:
        feedback.append("Consider 12+ characters for stronger security.")
        score += 1
    else:
        score += 2

    entropy = estimate_entropy(password)
    if entropy >= 80:
        score += 3
    elif entropy >= 60:
        score += 2
    elif entropy >= 40:
        score += 1

    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        feedback.append("This is a commonly used password — easily guessable.")
        score = 0
    elif any(common in lowered for common in COMMON_PASSWORDS if len(common) >= 4):
        feedback.append("Contains a common word or pattern.")
        score = max(score - 2, 0)

    if has_sequential_chars(password):
        feedback.append("Avoid sequential characters (e.g. 'abc', '123').")
        score = max(score - 1, 0)

    if has_repeated_chars(password):
        feedback.append("Avoid repeating the same character several times in a row.")
        score = max(score - 1, 0)

    if not re.search(r"[A-Z]", password):
        feedback.append("Add uppercase letters.")
    if not re.search(r"[a-z]", password):
        feedback.append("Add lowercase letters.")
    if not re.search(r"[0-9]", password):
        feedback.append("Add numbers.")
    if not re.search(r"[^a-zA-Z0-9]", password):
        feedback.append("Add symbols.")

    score = max(0, min(score, 6))
    label = LABELS[score]

    if not feedback:
        feedback.append("Strong password — no issues detected.")

    return {
        "score": score,
        "max_score": 6,
        "label": label,
        "entropy_bits": round(entropy, 1),
        "feedback": feedback,
    }
