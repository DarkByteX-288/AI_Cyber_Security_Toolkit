"""
Machine Learning model for password strength classification.
Uses Scikit-Learn to classify passwords as weak/moderate/strong/very strong.
"""
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from typing import Tuple, List
import os


# Hardcoded dataset with 30+ password samples
# Format: (features, label) where label: 0=weak, 1=moderate, 2=strong, 3=very strong
PASSWORD_DATASET = [
    # Weak passwords (label 0)
    ((8, 1, 1, 0, 0, 2, 0, 0, False), 0),  # password
    ((6, 0, 1, 1, 0, 0, 0, 0, True), 0),   # 123456
    ((8, 1, 1, 0, 0, 0, 1, 0, True), 0),   # passw0rd
    ((7, 1, 1, 0, 0, 1, 0, 0, True), 0),   # qwerty
    ((6, 0, 1, 2, 0, 0, 0, 0, True), 0),   # abc123
    ((8, 1, 1, 0, 0, 0, 1, 0, True), 0),   # letmein
    ((8, 0, 1, 2, 0, 0, 0, 0, True), 0),   # summer
    ((8, 1, 1, 0, 0, 0, 1, 0, True), 0),   # monkey
    ((8, 1, 1, 0, 0, 0, 1, 0, True), 0),   # dragon
    ((6, 0, 1, 3, 0, 0, 0, 0, True), 0),   # 1234567
    ((8, 1, 1, 0, 0, 0, 1, 0, True), 0),   # master
    ((8, 0, 1, 2, 0, 0, 0, 0, True), 0),   # login
    
    # Moderate passwords (label 1)
    ((8, 1, 1, 2, 0, 0, 0, 0, False), 1),  # Pass123
    ((9, 1, 1, 2, 0, 0, 0, 0, False), 1),  # Test1234
    ((10, 1, 1, 2, 1, 0, 0, 0, False), 1), # Hello123!
    ((11, 1, 1, 2, 1, 0, 0, 0, False), 1), # Password1!
    ((8, 1, 1, 1, 1, 0, 0, 0, False), 1),  # Abc123!@
    ((9, 1, 1, 2, 1, 0, 0, 0, False), 1),  # Secure1!
    ((10, 1, 1, 3, 1, 0, 0, 0, False), 1), # Strong123!
    ((8, 1, 1, 1, 2, 0, 0, 0, False), 1),  # Pass!12
    ((9, 1, 1, 2, 2, 0, 0, 0, False), 1),  # Test!123
    ((7, 1, 1, 2, 2, 0, 0, 0, False), 1),  # Hi!123
    
    # Strong passwords (label 2)
    ((12, 1, 1, 2, 2, 0, 0, 0, False), 2), # Str0ng!Pass
    ((14, 1, 1, 3, 3, 0, 0, 0, False), 2), # MyV3ryStr0ng!
    ((12, 1, 1, 3, 2, 0, 0, 0, False), 2), # C0mpl3x!Pass
    ((13, 1, 1, 3, 2, 0, 1, 0, False), 2), # Pr0fect!Pass
    ((11, 1, 1, 3, 3, 0, 0, 0, False), 2), # G00d!Str0ng
    ((12, 1, 1, 2, 3, 0, 0, 0, False), 2), # B3st!P@ssword
    ((10, 1, 1, 2, 3, 0, 0, 0, False), 2), # G00d!Pass!
    ((13, 2, 1, 3, 2, 0, 0, 0, False), 2), # Upp3rL0wer!
    ((12, 1, 2, 3, 2, 0, 0, 0, False), 2), # LcUcHyStRoNg!
    ((11, 1, 1, 3, 3, 0, 0, 1, False), 2), # K3y!Bo4rd!
    
    # Very strong passwords (label 3)
    ((16, 2, 2, 4, 4, 0, 0, 0, False), 3), # Xk9#mP2$vL5@nQ8!
    ((18, 2, 2, 5, 5, 0, 0, 0, False), 3), # Qw3rty!Uiop@Asd2f
    ((15, 2, 2, 4, 4, 0, 1, 0, False), 3), # Zx1cv!Bn2mQ7#
    ((17, 2, 2, 5, 5, 0, 0, 0, False), 3), # MyP@ssw0rd!2024#Sec
    ((14, 2, 2, 4, 4, 0, 0, 0, False), 3), # S3cur3P@ss!2024
    ((16, 2, 2, 4, 4, 0, 0, 0, False), 3), # V3ry$tr0ng!@#2024
    ((15, 2, 2, 4, 4, 0, 1, 0, False), 3), # Pr0!It3s@Vc$Up
    ((18, 2, 2, 5, 5, 0, 0, 0, False), 3), # An0th3r$ecur3!@#Pass
    ((17, 2, 2, 5, 5, 0, 0, 0, False), 3), # Th1s!s@V3ry$tr0ng
    ((16, 2, 2, 4, 4, 0, 0, 1, False), 3), # MyC0mpl3x!$ecur3!
]


def extract_features(analysis: dict) -> List[int]:
    """Extract feature vector from analysis results for ML model."""
    return [
        analysis['length'],
        analysis['uppercase_count'],
        analysis['lowercase_count'],
        analysis['digit_count'],
        analysis['special_count'],
        analysis['repeated_chars'],
        len(analysis['sequential_patterns']),
        len(analysis['keyboard_patterns']),
        analysis['is_common']
    ]


def train_model() -> RandomForestClassifier:
    """Train and return a Random Forest classifier on the dataset."""
    X = np.array([item[0] for item in PASSWORD_DATASET])
    y = np.array([item[1] for item in PASSWORD_DATASET])
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    
    return model


def load_or_train_model(model_path: str = 'trained_model.pkl') -> RandomForestClassifier:
    """Load existing model or train a new one."""
    if os.path.exists(model_path):
        try:
            with open(model_path, 'rb') as f:
                return pickle.load(f)
        except (pickle.UnpicklingError, EOFError, AttributeError, ImportError, OSError):
            os.remove(model_path)

    model = train_model()
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    return model


def predict_strength(model: RandomForestClassifier, analysis: dict) -> str:
    """Predict password strength class using the ML model."""
    features = np.array([extract_features(analysis)])
    prediction = model.predict(features)[0]
    
    strength_map = {0: 'weak', 1: 'moderate', 2: 'strong', 3: 'very strong'}
    return strength_map[prediction]


def get_model_accuracy(model: RandomForestClassifier) -> float:
    """Get accuracy of the trained model."""
    X = np.array([item[0] for item in PASSWORD_DATASET])
    y = np.array([item[1] for item in PASSWORD_DATASET])
    return model.score(X, y)