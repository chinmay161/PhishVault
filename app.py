from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, login_required, logout_user, current_user
from flask_mail import Mail
from models import db, User
from auth_routes import auth_bp
from phishing_routes import phishing_bp
from dotenv import load_dotenv
import os

load_dotenv()
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Flask-Mail configuration for Mailtrap
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')  # Mailtrap SMTP server
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))  # Mailtrap SMTP port
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # Your Mailtrap username
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Your Mailtrap password
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')  # Default sender email

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "auth.login"  # Redirects to login page if not logged in


# Initialize extensions
mail = Mail(app)
db.init_app(app)

# Secret key for JWT and other security-related features
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(phishing_bp, url_prefix='/')

# Create database tables
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)  # Retrieves user from the database

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))  # Redirect to home page after logout

if __name__ == '__main__':
    app.run(debug=True)
