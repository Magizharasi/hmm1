# run.py
"""
Main application entry point for the Continuous Authentication Agent
"""
import os
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('auth_agent.log'),
        logging.StreamHandler()
    ]
)

def create_database_directory():
    """Ensure database directory exists"""
    try:
        app_dir = os.path.dirname(os.path.abspath(__file__))
        db_dir = os.path.join(app_dir, 'app', 'database')
        os.makedirs(db_dir, exist_ok=True)
        print(f"Database directory ensured: {db_dir}")
        return True
    except Exception as e:
        print(f"Failed to create database directory: {e}")
        return False

def main():
    """Main application function"""
    try:
        # Ensure database directory exists
        if not create_database_directory():
            sys.exit(1)
        
        # Import after ensuring directory structure
        from app import create_app, socketio
        
        # Create the Flask app
        config_name = os.environ.get('FLASK_ENV', 'development')
        app = create_app(config_name)
        
        # The database is already initialized in create_app()
        print("Application initialized successfully")
        
        # Run the application with SocketIO support
        socketio.run(
            app,
            debug=config_name == 'development',
            host='127.0.0.1',
            port=5000,
            allow_unsafe_werkzeug=True
        )
        
    except Exception as e:
        logging.error(f"Application startup failed: {e}")
        print(f"Error starting application: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()