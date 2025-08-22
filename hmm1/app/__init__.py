# ==========================================
# app/__init__.py
"""
Application factory and configuration
"""
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_jwt_extended import JWTManager
from flask_cors import CORS

# Initialize extensions
db = SQLAlchemy()
socketio = SocketIO(cors_allowed_origins="*")
jwt = JWTManager()

def create_app(config_name='development'):
    """Create and configure Flask application"""
    app = Flask(__name__)
    
    # Load configuration
    from app.config import config
    app.config.from_object(config[config_name])
    
    # Ensure database directory exists
    db_path = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if db_path.startswith('sqlite:///'):
        db_file = db_path.replace('sqlite:///', '')
        db_dir = os.path.dirname(db_file)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
    
    # Initialize extensions with app
    db.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")
    jwt.init_app(app)
    CORS(app)
    
    # Import models to ensure they're registered
    with app.app_context():
        from app.models import database
        
        # Create tables
        try:
            db.create_all()
            print("Database tables created successfully")
        except Exception as e:
            print(f"Database creation error: {e}")
    
    # Register blueprints
    from app.api.auth import auth_bp
    from app.api.calibration import calibration_bp
    from app.api.dashboard import dashboard_bp
    from app.api.challenge import challenge_bp
    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(calibration_bp, url_prefix='/api/calibration')
    app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')
    app.register_blueprint(challenge_bp, url_prefix='/api/challenge')
    
    # Register WebSocket handlers
    from app.api.websockets import register_websocket_handlers
    register_websocket_handlers(socketio)
    
    # Register template routes
    @app.route('/')
    def index():
        return app.send_static_file('login.html')
    
    @app.route('/login')
    def login():
        return app.send_static_file('login.html')
    
    @app.route('/calibration')
    def calibration():
        return app.send_static_file('calibration.html')
    
    @app.route('/dashboard')
    def dashboard():
        return app.send_static_file('dashboard.html')
    
    @app.route('/challenge')
    def challenge():
        return app.send_static_file('challenge.html')
    
    return app