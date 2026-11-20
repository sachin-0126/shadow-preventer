import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'shadow_preventer_crimathon_saveetha_sec_2026_key_99824')
    DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'shadow_preventer.db')
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 7200  # 2 hours
    INACTIVITY_WARN_MIN_DAYS = 3
    INACTIVITY_WARN_MAX_DAYS = 5
