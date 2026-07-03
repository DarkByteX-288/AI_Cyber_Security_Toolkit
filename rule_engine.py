"""
Rule-based password analysis engine.
Analyzes passwords for various strength indicators.
"""
import re
from typing import Dict, Any, List


# Common weak passwords list
COMMON_PASSWORDS = {
    'password', '123456', 'password123', 'admin', 'letmein', 'welcome',
    'monkey', 'dragon', 'master', 'qwerty', 'login', 'princess', 'abc123',
    'password1', 'iloveyou', 'sunshine', 'trustno1', 'superman', 'shadow',
    'michael', 'football', 'baseball', 'soccer', 'hockey', 'batman',
    'starwars', 'pokemon', 'summer', 'winter', 'spring', 'autumn',
    'killer', 'george', 'harley', 'computer', 'internet', 'secure',
    'passw0rd', 'admin123', 'root', 'toor', 'changeme', 'default'
}


def analyze_password(password: str) -> Dict[str, Any]:
    """
    Perform comprehensive rule-based analysis of a password.
    
    Args:
        password: The password string to analyze
        
    Returns:
        Dictionary containing all analysis results
    """
    if not password:
        return {
            'length': 0,
            'uppercase_count': 0,
            'lowercase_count': 0,
            'digit_count': 0,
            'special_count': 0,
            'repeated_chars': 0,
            'sequential_patterns': [],
            'keyboard_patterns': [],
            'is_common': False,
            'score': 0
        }
    
    # Basic character counts
    length = len(password)
    uppercase_count = len(re.findall(r'[A-Z]', password))
    lowercase_count = len(re.findall(r'[a-z]', password))
    digit_count = len(re.findall(r'[0-9]', password))
    special_count = len(re.findall(r'[^A-Za-z0-9]', password))
    
    # Repeated characters analysis
    repeated_chars = 0
    char_counts = {}
    for char in password:
        char_counts[char] = char_counts.get(char, 0) + 1
    repeated_chars = sum(1 for count in char_counts.values() if count > 1)
    
    # Sequential patterns (3+ consecutive characters)
    sequential_patterns = []
    sequences = ['abcdefghijklmnopqrstuvwxyz', '0123456789', 'qwertyuiop', '!@#$%^&*()']
    for seq in sequences:
        for i in range(len(seq) - 2):
            if seq[i:i+3].lower() in password.lower():
                sequential_patterns.append(seq[i:i+3])
            elif seq[i:i+3][::-1].lower() in password.lower():
                sequential_patterns.append(seq[i:i+3][::-1])
    
    # Keyboard patterns (adjacent keys)
    keyboard_patterns = []
    keyboard_rows = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890']
    for row in keyboard_rows:
        for i in range(len(row) - 2):
            if row[i:i+3].lower() in password.lower():
                keyboard_patterns.append(row[i:i+3])
    
    # Common password check
    is_common = password.lower() in COMMON_PASSWORDS
    
    # Calculate score
    score = _calculate_score(
        length, uppercase_count, lowercase_count, 
        digit_count, special_count, repeated_chars,
        sequential_patterns, keyboard_patterns, is_common
    )
    
    return {
        'length': length,
        'uppercase_count': uppercase_count,
        'lowercase_count': lowercase_count,
        'digit_count': digit_count,
        'special_count': special_count,
        'repeated_chars': repeated_chars,
        'sequential_patterns': list(set(sequential_patterns)),
        'keyboard_patterns': list(set(keyboard_patterns)),
        'is_common': is_common,
        'score': score
    }


def _calculate_score(length: int, uppercase_count: int, lowercase_count: int,
                     digit_count: int, special_count: int, repeated_chars: int,
                     sequential_patterns: list, keyboard_patterns: list,
                     is_common: bool) -> int:
    """Calculate overall password strength score (0-100)."""
    score = 0
    
    # Length scoring
    if length >= 12:
        score += 25
    elif length >= 8:
        score += 15
    elif length >= 6:
        score += 10
    else:
        score += max(0, length * 2)
    
    # Character variety scoring
    if uppercase_count > 0:
        score += 10
    if lowercase_count > 0:
        score += 10
    if digit_count > 0:
        score += 10
    if special_count > 0:
        score += 15
    
    # Penalty for repeated characters
    score -= repeated_chars * 2
    
    # Penalty for patterns
    score -= len(sequential_patterns) * 5
    score -= len(keyboard_patterns) * 3
    
    # Heavy penalty for common passwords
    if is_common:
        score -= 40
    
    return max(0, min(100, score))


def get_strength_class(score: int) -> str:
    """Convert score to strength class."""
    if score >= 80:
        return 'very strong'
    elif score >= 60:
        return 'strong'
    elif score >= 40:
        return 'moderate'
    else:
        return 'weak'