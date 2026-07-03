"""
Password recommendation engine.
Generates specific, contextual suggestions for password improvement.
"""
from typing import List, Dict, Any


def generate_recommendations(analysis: dict) -> List[str]:
    """
    Generate specific recommendations for password improvement.
    
    Args:
        analysis: Password analysis results from rule_engine
        
    Returns:
        List of at least 5 recommendation strings
    """
    recommendations = []
    
    length = analysis['length']
    has_upper = analysis['uppercase_count'] > 0
    has_lower = analysis['lowercase_count'] > 0
    has_digit = analysis['digit_count'] > 0
    has_special = analysis['special_count'] > 0
    is_common = analysis['is_common']
    repeated_chars = analysis['repeated_chars']
    sequential_patterns = analysis['sequential_patterns']
    keyboard_patterns = analysis['keyboard_patterns']
    
    # Length recommendation
    if length < 12:
        recommendations.append(f"Increase password length to at least 12 characters (currently {length})")
    else:
        recommendations.append("Password length is adequate (12+ characters)")
    
    # Uppercase recommendation
    if not has_upper:
        recommendations.append("Add uppercase letters (A-Z) to increase complexity")
    
    # Lowercase recommendation
    if not has_lower:
        recommendations.append("Add lowercase letters (a-z) to increase complexity")
    
    # Digit recommendation
    if not has_digit:
        recommendations.append("Include numbers (0-9) for better security")
    
    # Special character recommendation
    if not has_special:
        recommendations.append("Add special characters (!@#$%^&* etc.) for maximum protection")
    
    # Repeated characters warning
    if repeated_chars > 2:
        recommendations.append(f"Reduce repeated characters ({repeated_chars} found) - they make passwords easier to crack")
    elif repeated_chars > 0:
        recommendations.append(f"Avoid repeating characters - consider using unique characters instead")
    
    # Sequential patterns warning
    if sequential_patterns:
        recommendations.append(f"Remove sequential patterns: {', '.join(sequential_patterns)} - these are easy to guess")
    
    # Keyboard patterns warning
    if keyboard_patterns:
        recommendations.append(f"Avoid keyboard patterns: {', '.join(keyboard_patterns)} - use random key combinations instead")
    
    # Common password warning
    if is_common:
        recommendations.append("This is a very common password - choose something completely unique")
    
    # Ensure at least 5 recommendations
    default_recommendations = [
        "Use a passphrase with multiple unrelated words",
        "Consider using a password manager to generate and store unique passwords",
        "Avoid using personal information (names, birthdays, etc.)",
        "Enable two-factor authentication for additional security"
    ]
    
    while len(recommendations) < 5:
        for rec in default_recommendations:
            if rec not in recommendations:
                recommendations.append(rec)
                if len(recommendations) >= 5:
                    break
    
    return recommendations[:min(len(recommendations), 10)]  # Return max 10 recommendations