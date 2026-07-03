"""
Main Flask application for the AI-Driven Password Strength Evaluator.
Integrates all modules for comprehensive password analysis.
"""
import os
import hashlib
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, PasswordAnalysis, AttackLog
from rule_engine import analyze_password, get_strength_class
from entropy import calculate_entropy, get_entropy_strength
from ml_model import load_or_train_model, predict_strength, extract_features
from attack_simulator import simulate_attack, get_risk_level
from recommendation_engine import generate_recommendations

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = BASE_DIR / "database.db"
DEFAULT_MODEL_PATH = BASE_DIR / "trained_model.pkl"

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', f"sqlite:///{DEFAULT_DB_PATH}")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)

# Create tables
with app.app_context():
    try:
        db.create_all()
    except Exception as exc:
        if "malformed" in str(exc).lower() and DEFAULT_DB_PATH.exists():
            DEFAULT_DB_PATH.unlink()
            db.create_all()
        else:
            raise
    # Train and save ML model
    load_or_train_model(str(DEFAULT_MODEL_PATH))

# Home route
@app.route('/')
def index():
    return render_template('index.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'][:80]  # Limit input length
        password = request.form['password']
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        # Create user with hashed password
        password_hash = generate_password_hash(password)
        user = User(username=username, password_hash=password_hash)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'][:80]
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

# Dashboard route
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        flash('Please login to access dashboard', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    analysis_results = None
    recommendations = None
    
    if request.method == 'POST':
        password = request.form['password']
        
        # Analyze password
        analysis = analyze_password(password)
        
        # Calculate entropy
        entropy_bits = calculate_entropy(password)
        
        # Get ML prediction
        model = load_or_train_model(str(DEFAULT_MODEL_PATH))
        ml_strength = predict_strength(model, analysis)
        
        # Determine overall strength class (use ML as primary)
        strength_class = ml_strength
        
        # Simulate attack
        attack_results = simulate_attack(analysis)
        
        # Get risk level
        risk_level = get_risk_level(attack_results['time_to_crack_hours'])
        
        # Generate recommendations
        recommendations = generate_recommendations(analysis)
        
        # Calculate final score (weighted average)
        score = int(analysis['score'] * 0.4 + 100 * {'weak': 0.25, 'moderate': 0.5, 'strong': 0.75, 'very strong': 1.0}[strength_class])
        score = min(100, max(0, score))
        
        # Store analysis in database
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        analysis_record = PasswordAnalysis(
            user_id=user.id,
            password_hash=password_hash,
            score=score,
            strength_class=strength_class,
            entropy_bits=entropy_bits,
            risk_level=risk_level,
            crack_time_seconds=attack_results['time_to_crack_seconds']
        )
        db.session.add(analysis_record)
        db.session.commit()
        
        # Store attack log
        attack_log = AttackLog(
            analysis_id=analysis_record.id,
            dictionary_attempts=attack_results['dictionary_attempts'],
            brute_force_estimate=attack_results['brute_force_estimate'],
            hybrid_speed=attack_results['hybrid_speed'],
            pattern_detected=attack_results['pattern_detected'],
            time_to_crack_hours=attack_results['time_to_crack_hours']
        )
        db.session.add(attack_log)
        db.session.commit()
        
        analysis_results = {
            'score': score,
            'strength_class': strength_class,
            'entropy_bits': entropy_bits,
            'risk_level': risk_level,
            'crack_time_seconds': attack_results['time_to_crack_seconds'],
            'crack_time_hours': attack_results['time_to_crack_hours'],
            'analysis': analysis,
            'attack_results': attack_results
        }
    
    return render_template('dashboard.html', 
                          user=user, 
                          analysis_results=analysis_results,
                          recommendations=recommendations)

if __name__ == '__main__':
    app.run(debug=True)