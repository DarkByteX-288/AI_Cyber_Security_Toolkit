"""
Entropy calculation module for password strength evaluation.
Calculates Shannon entropy in bits for password analysis.
"""
import math
from collections import Counter


def calculate_entropy(password: str) -> float:
    """
    Calculate Shannon entropy of a password in bits.
    
    Args:
        password: The password string to analyze
        
    Returns:
        Entropy value in bits (float)
    """
    if not password:
        return 0.0
    
    # Count character frequencies
    char_counts = Counter(password)
    password_length = len(password)
    
    # Calculate entropy: H = -sum(p(x) * log2(p(x)))
    entropy = 0.0
    for count in char_counts.values():
        probability = count / password_length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    # Multiply by length to get total entropy bits
    total_entropy = entropy * password_length
    
    return round(total_entropy, 2)


def get_entropy_strength(entropy_bits: float) -> str:
    """
    Determine strength class based on entropy bits.
    
    Args:
        entropy_bits: Entropy value in bits
        
    Returns:
        Strength class string: 'weak', 'moderate', 'strong', or 'very strong'
    """
    if entropy_bits < 20:
        return 'weak'
    elif entropy_bits < 30:
        return 'moderate'
    elif entropy_bits < 40:
        return 'strong'
    else:
        return 'very strong'