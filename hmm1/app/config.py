import os
from datetime import timedelta

# Get the base directory
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Base configuration class"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-secret-key-change-in-production'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'a-super-secret-jwt-key-change-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'connect_args': {'check_same_thread': False}  # For SQLite
    }

    # Model Configuration
    MODELS_BASE_PATH = os.environ.get('MODELS_PATH') or 'models/saved'

    @staticmethod
    def init_app(app):
        pass

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    # Create database directory if it doesn't exist
    db_dir = os.path.join(basedir, 'database')
    os.makedirs(db_dir, exist_ok=True)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + os.path.join(db_dir, 'auth_system_dev.db')

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or 'sqlite:///:memory:'

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    # Create database directory if it doesn't exist
    db_dir = os.path.join(basedir, 'database')
    os.makedirs(db_dir, exist_ok=True)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(db_dir, 'auth_system.db')

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}