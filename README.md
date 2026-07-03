# AI-Driven Password Strength Evaluator with Attack Simulation and Adaptive Defense

A comprehensive cybersecurity dashboard for evaluating password strength using machine learning, entropy calculation, and attack simulation.

## Features

- **User Authentication**: Register, login, and logout with Werkzeug password hashing
- **Rule-Based Analysis**: Analyzes length, character variety, patterns, and common weaknesses
- **Entropy Calculator**: Measures randomness using Shannon entropy in bits
- **ML Classification**: Machine learning model trained on 30+ password samples
- **Attack Simulation**: Estimates time to crack using dictionary and brute-force methods
- **Recommendation Engine**: Generates 5+ specific suggestions for password improvement

## Installation

### Prerequisites
- Python 3.8+
- pip

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-directory>
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install flask flask-sqlalchemy scikit-learn numpy
```

4. Run the application:
```bash
python app.py
```

5. Access the application at `http://localhost:5000`

## Testing

### Unit Tests

Run the test suite:

```bash
python -m pytest tests/ -v
```

### Test Coverage

The application includes tests for:
- Password analysis functions
- Entropy calculation
- ML model predictions
- Attack simulation
- Recommendation generation

## Deployment

### Production Setup

1. Set a strong `SECRET_KEY` in `app.py`:
```python
app.config['SECRET_KEY'] = 'your-production-secret-key'
```

2. Use a production WSGI server:
```bash
pip install gunicorn
gunicorn app:app
```

3. Configure a reverse proxy (nginx/Apache) for SSL termination

4. Use a production database (PostgreSQL/MySQL) instead of SQLite

### Database Migration

The SQLite database is auto-created on first run. For production:
```python
from models import db
db.create_all()
```

## Project Structure

```
.
├── app.py                    # Main Flask application
├── models.py                 # SQLAlchemy database models
├── entropy.py               # Entropy calculation module
├── rule_engine.py           # Rule-based password analysis
├── ml_model.py              # Machine learning model
├── attack_simulator.py      # Attack simulation module
├── recommendation_engine.py # Password recommendations
├── database.db              # SQLite database (auto-created)
├── trained_model.pkl        # ML model (auto-created)
├── templates/
│   ├── index.html           # Home page
│   ├── login.html           # Login page
│   ├── register.html        # Registration page
│   └── dashboard.html       # User dashboard
└── static/
    ├── css/
    │   └── style.css        # Dark theme styles
    └── js/
        └── main.js          # Client-side JavaScript
```

## Security Features

- **XSS Protection**: All user input is escaped using Jinja2 auto-escaping
- **SQL Injection Protection**: Parameterized queries via SQLAlchemy ORM
- **Password Hashing**: Werkzeug security for password storage
- **Input Validation**: Length limits and format validation
- **Session Security**: Flask session cookies with secret key

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Home page |
| `/register` | GET, POST | User registration |
| `/login` | GET, POST | User login |
| `/logout` | GET | User logout |
| `/dashboard` | GET, POST | Password analysis dashboard |

## License

MIT License