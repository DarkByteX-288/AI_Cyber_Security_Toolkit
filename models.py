"""
SQLAlchemy database models for the cybersecurity dashboard.
Defines User, PasswordAnalysis, and AttackLog tables.
"""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    """User authentication model with Werkzeug password hashing."""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.username}>'

class PasswordAnalysis(db.Model):
    """Stores password analysis results."""
    __tablename__ = 'password_analysis'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)  # SHA256 hash of password
    score = db.Column(db.Integer, nullable=False)
    strength_class = db.Column(db.String(20), nullable=False)
    entropy_bits = db.Column(db.Float, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)
    crack_time_seconds = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('analyses', lazy=True))
    
    def __repr__(self):
        return f'<PasswordAnalysis score={self.score} strength={self.strength_class}>'

class AttackLog(db.Model):
    """Logs attack simulation results."""
    __tablename__ = 'attack_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey('password_analysis.id'), nullable=False)
    dictionary_attempts = db.Column(db.Integer, nullable=False)
    brute_force_estimate = db.Column(db.BigInteger, nullable=False)
    hybrid_speed = db.Column(db.Integer, nullable=False)
    pattern_detected = db.Column(db.Boolean, nullable=False)
    time_to_crack_hours = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    analysis = db.relationship('PasswordAnalysis', backref=db.backref('attack_logs', lazy=True))
    
    def __repr__(self):
        return f'<AttackLog dict={self.dictionary_attempts} hours={self.time_to_crack_hours}>'