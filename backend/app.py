# app.py

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
import datetime
import sqlite3
import json
import os
import logging
import openai
import atexit
from config import DevelopmentConfig, ProductionConfig
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Determine the environment (default to 'development' if not set)
env = os.getenv('APP_ENV', 'development')

# Load the appropriate configuration
if env == 'development':
    app.config.from_object(DevelopmentConfig)
else:
    app.config.from_object(ProductionConfig)

# Initialize CORS with the correct origins based on environment
CORS(app, supports_credentials=True, origins=app.config['CORS_ORIGINS'])

# Configure logging
logging.basicConfig(level=logging.DEBUG if os.getenv('APP_ENV') == 'development' else logging.INFO)
logger = logging.getLogger(__name__)

# Add logging to confirm environment
logger.info(f"Flask application is running in {app.config['ENV']} mode.")

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize the scheduler
scheduler = BackgroundScheduler()

logging.basicConfig(level=logging.DEBUG if app.debug else logging.INFO)
logger = logging.getLogger(__name__)

# Global flag to ensure dev login runs only once
dev_login_done = False

# Define the User class
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        return User(id=user['id'], username=user['username'], password_hash=user['password'])
    return None

# Function to get a database connection
def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

# Initialize the database
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Enable WAL mode
    cursor.execute('PRAGMA journal_mode=WAL;')

    # Enforce foreign keys
    cursor.execute('PRAGMA foreign_keys = ON;')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            query TEXT NOT NULL,
            frequency TEXT NOT NULL,  -- 'daily' or 'weekly'
            last_run DATETIME,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS searches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        search_id INTEGER,
        name TEXT,
        url TEXT,
        snippet TEXT,
        summary TEXT,
        FOREIGN KEY (search_id) REFERENCES searches (id)
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alert_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id INTEGER,
        result_data TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (alert_id) REFERENCES alerts (id)
    )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            result_id INTEGER,
            feedback TEXT,
            comment TEXT,
            FOREIGN KEY (result_id) REFERENCES results (id)
        )
    ''')
    conn.commit()
    conn.close()

# Auto-login development user
@app.before_request
def auto_login_dev_user():
    global dev_login_done
    # Only run once, and only if in development
    if not dev_login_done and app.config['APP_ENV'] == 'development':
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                user = conn.execute('SELECT * FROM users WHERE username = ?', ('dev_user',)).fetchone()

                if not user:
                    password_hash = generate_password_hash('devpass')
                    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('dev_user', password_hash))
                    conn.commit()
                    user_id = cursor.lastrowid
                    user_obj = User(id=user_id, username='dev_user', password_hash=password_hash)
                    logger.debug("Dev user created and logged in.")
                else:
                    user_obj = User(id=user['id'], username=user['username'], password_hash=user['password'])
                    logger.debug("Dev user found and logged in.")

                login_user(user_obj)
                dev_login_done = True
        except Exception as e:
            logger.error(f"Error in auto_login_dev_user: {e}")
            # Optionally, handle the error (e.g., send notification, halt the request)



def run_scheduled_alerts():
    with app.app_context():
        conn = get_db_connection()
        alerts = conn.execute('SELECT * FROM alerts').fetchall()
        for alert in alerts:
            user_id = alert['user_id']
            query = alert['query']
            frequency = alert['frequency']
            last_run = alert['last_run']
            now = datetime.datetime.utcnow()
            should_run = False

            if last_run is None:
                should_run = True
            else:
                last_run = datetime.datetime.strptime(last_run, '%Y-%m-%d %H:%M:%S')
                delta = now - last_run
                if frequency == 'daily' and delta.days >= 1:
                    should_run = True
                elif frequency == 'weekly' and delta.days >= 7:
                    should_run = True

            if should_run:
                try:
                    # Run the search and process results
                    results = bing_news_search(query)
                    processed_results = process_news_results(results)

                    # Save the results to the alert_results table
                    for result in processed_results:
                        conn.execute('''
                            INSERT INTO alert_results (alert_id, result_data)
                            VALUES (?, ?)
                        ''', (alert['id'], json.dumps(result)))

                    # Update last_run timestamp
                    conn.execute('UPDATE alerts SET last_run = ? WHERE id = ?', (now.strftime('%Y-%m-%d %H:%M:%S'), alert['id']))
                    conn.commit()
                except Exception as e:
                    print(f"Error processing alert {alert['id']}: {e}")
                    # Optionally, log the error or handle it as needed
        conn.close()

scheduler.add_job(func=run_scheduled_alerts, trigger='interval', minutes=60)
scheduler.start()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())

def bing_news_search(query):
    url = "https://api.bing.microsoft.com/v7.0/news/search"
    headers = {"Ocp-Apim-Subscription-Key": BING_API_KEY}
    params = {
        "q": query,
        "freshness": "Week",  # Options: 'Day', 'Week', 'Month'
        "sortBy": "Date",    # Sort results by date
        "count": 10,         # Number of results to return
        "textDecorations": True,
        "textFormat": "HTML"
    }
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()

def process_news_results(results):
    if 'value' in results:
        news_items = results['value']
        processed_results = []
        for item in news_items:
            result = {
                'name': item.get('name'),
                'url': item.get('url'),
                'snippet': item.get('description'),
                'datePublished': item.get('datePublished'),
                'provider': item.get('provider')[0]['name'] if item.get('provider') else None
            }
            processed_results.append(result)
        return processed_results
    else:
        return []

def clarify_intent(query):
    # Using GPT-4 and a minimal prompt
    messages = [
        {"role": "user", "content": f"Is the following query ambiguous? Reply with 'Yes' or 'No'.\n\nQuery: '{query}'"}
    ]
    response = openai.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        max_tokens=5,
        temperature=0
    )
    answer = response.choices[0].message.content
    return answer

def summarize_text(text):
    # Using GPT-4 and a minimal prompt
    messages = [
        {"role": "user", "content": f"Summarize the following text in 2-3 sentences:\n\n{text}"}
    ]
    response = openai.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        max_tokens=150,
        temperature=0.7
    )
    summary = response.choices[0].message.content
    print(summary)
    return summary

@app.route('/check-auth', methods=['GET'])
def check_auth():
    if current_user.is_authenticated:
        return jsonify({'isAuthenticated': True, 'user': {'id': current_user.id, 'username': current_user.username}})
    else:
        return jsonify({'isAuthenticated': False})

@app.route('/api/alerts', methods=['GET'])
@login_required
def get_alerts():
    conn = get_db_connection()
    alerts = conn.execute('SELECT * FROM alerts WHERE user_id = ?', (current_user.id,)).fetchall()
    conn.close()
    return jsonify([dict(alert) for alert in alerts])

@app.route('/api/alerts', methods=['POST'])
@login_required
def create_alert():
    data = request.get_json()
    query = data.get('query')
    frequency = data.get('frequency')  # 'daily' or 'weekly'
    conn = get_db_connection()
    # Check if user has less than 10 alerts
    count = conn.execute('SELECT COUNT(*) FROM alerts WHERE user_id = ?', (current_user.id,)).fetchone()[0]
    if count >= 10:
        return jsonify({'error': 'Maximum of 10 alerts reached'}), 400
    conn.execute('INSERT INTO alerts (user_id, query, frequency) VALUES (?, ?, ?)', (current_user.id, query, frequency))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Alert created successfully'})

@app.route('/api/alerts/<int:alert_id>', methods=['DELETE'])
@login_required
def delete_alert(alert_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM alerts WHERE id = ? AND user_id = ?', (alert_id, current_user.id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Alert deleted successfully'})


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    password_hash = generate_password_hash(password)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Username already taken'}), 400

    # Create a User object for the newly registered user
    user_obj = User(id=user_id, username=username, password_hash=password_hash)
    login_user(user_obj)
    conn.close()

    return jsonify({'message': 'User registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if user and check_password_hash(user['password'], password):
        user_obj = User(id=user['id'], username=user['username'], password_hash=user['password'])
        login_user(user_obj)
        return jsonify({'message': 'Logged in successfully'})
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'})

@app.route('/search', methods=['POST'])
def search():
    data = request.get_json()
    query = data.get('query')
    
    # Intent Clarification
    # needs_clarification = clarify_intent(query)
    # if needs_clarification.lower() == 'yes':
    #     return jsonify({'clarification_needed': True, 'message': 'Please provide more context for your query.'})

    # Save the search query
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO searches (query) VALUES (?)', (query,))
    search_id = cursor.lastrowid

    # Perform Bing News Search
    try:
        results = bing_news_search(query)
        processed_results = process_news_results(results)
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

    # Summarize and Save Results
    for result in processed_results:
        summary = summarize_text(result['snippet'])
        result['summary'] = summary
        cursor.execute('''
            INSERT INTO results (search_id, name, url, snippet, summary)
            VALUES (?, ?, ?, ?, ?)
        ''', (search_id, result['name'], result['url'], result['snippet'], summary))

    conn.commit()
    conn.close()

    return jsonify({'results': processed_results})

@app.route('/api/alert-results', methods=['GET'])
@login_required
def get_alert_results():
    conn = get_db_connection()
    results = conn.execute('''
        SELECT ar.*, a.query
        FROM alert_results ar
        JOIN alerts a ON ar.alert_id = a.id
        WHERE a.user_id = ?
        ORDER BY ar.timestamp DESC
    ''', (current_user.id,)).fetchall()
    conn.close()
    return jsonify([dict(result) for result in results])


@app.route('/feedback', methods=['POST'])
def feedback():
    data = request.get_json()
    result_id = data.get('result_id')
    feedback_type = data.get('feedback')  # 'like' or 'dislike'
    comment = data.get('comment', '')     # Optional

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO feedback (result_id, feedback, comment)
        VALUES (?, ?, ?)
    ''', (result_id, feedback_type, comment))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Feedback received'})

if __name__ == '__main__':
    init_db()
    # Run the app with debug mode based on configuration
    app.run(debug=app.config['DEBUG'])




