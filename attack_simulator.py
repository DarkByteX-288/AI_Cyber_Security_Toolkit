"""
Attack simulation module for password cracking estimation.
Estimates time to crack passwords using various attack methods.
"""
import math
from typing import Dict, Any


def simulate_attack(analysis: dict) -> Dict[str, Any]:
    """
    Simulate various attack methods on a password.
    
    Args:
        analysis: Password analysis results from rule_engine
        
    Returns:
        Dictionary containing attack simulation results
    """
    length = analysis['length']
    has_upper = analysis['uppercase_count'] > 0
    has_lower = analysis['lowercase_count'] > 0
    has_digit = analysis['digit_count'] > 0
    has_special = analysis['special_count'] > 0
    is_common = analysis['is_common']
    
    # Calculate keyspace size
    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += 32  # Common special characters
    
    if charset_size == 0:
        charset_size = 26  # Default to lowercase
    
    # Dictionary attack count (common passwords)
    dictionary_attempts = 1000000 if is_common else 0
    
    # Brute force estimate (keyspace-based) - capped for SQLite
    keyspace = charset_size ** length
    # SQLite INTEGER max is ~9.2e18, so cap at 1e15 for safety
    brute_force_estimate = min(keyspace, 10**15)
    
    # Hybrid attack speed (patterns + dictionary)
    hybrid_speed = 1000000  # 1M attempts per second
    
    # Pattern detection
    pattern_detected = (
        len(analysis['sequential_patterns']) > 0 or 
        len(analysis['keyboard_patterns']) > 0 or 
        is_common
    )
    
    # Time to crack calculation
    if is_common:
        # Common passwords are cracked instantly
        time_to_crack_seconds = 1.0
    else:
        # Time based on brute force
        time_to_crack_seconds = keyspace / hybrid_speed
    
    # Convert to hours for very large numbers
    time_to_crack_hours = time_to_crack_seconds / 3600
    
    return {
        'dictionary_attempts': dictionary_attempts,
        'brute_force_estimate': brute_force_estimate,
        'hybrid_speed': hybrid_speed,
        'pattern_detected': pattern_detected,
        'time_to_crack_seconds': round(time_to_crack_seconds, 2),
        'time_to_crack_hours': round(time_to_crack_hours, 2)
    }


def get_risk_level(time_to_crack_hours: float) -> str:
    """Determine risk level based on time to crack."""
    if time_to_crack_hours < 0.001:  # Less than a minute
        return 'critical'
    elif time_to_crack_hours < 1:  # Less than an hour
        return 'high'
    elif time_to_crack_hours < 24:  # Less than a day
        return 'medium'
    else:
        return 'low'


def estimate_keyspace(length: int, charset_size: int) -> int:
    """Estimate the keyspace size for a password."""
    return charset_size ** length