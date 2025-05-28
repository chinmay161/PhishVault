from email.policy import Policy
from flask import Flask, flash, render_template, request, redirect, url_for, session
from flask_login import LoginManager, login_required, logout_user, current_user
from flask_mail import Mail
from models import Link, PolicyDocument, db, User
from auth_routes import auth_bp
from phishing_routes import phishing_bp
from dashboard_routes import dashboard_bp
from admin_routes import admin_bp
from dotenv import load_dotenv
import os
from flask_migrate import Migrate
import uuid
from extensions import socketio

load_dotenv()
app = Flask(__name__)


socketio.init_app(app) 

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Flask-Mail configuration for Mailtrap
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')  # Mailtrap SMTP server
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))  # Mailtrap SMTP port
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # Your Mailtrap username
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Your Mailtrap password
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')  # Default sender email

app.config.update(
    SECRET_KEY=os.getenv('FLASK_SECRET_KEY', 'super-secret-key'),  # Must set a proper secret
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True if os.getenv('FLASK_ENV') == 'production' else False,
    SESSION_COOKIE_SAMESITE='Lax'
)

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
app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
app.register_blueprint(admin_bp, url_prefix='/admin')

# Create database tables
with app.app_context():
    db.create_all()

migrate = Migrate(app, db)

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
    return db.session.get(User, user_id)  # Retrieves user from the database

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))  # Redirect to home page after logout

@app.route('/terms')
def public_terms():
    db.session.expire_all()
    document = PolicyDocument.query.filter_by(document_type='tos').first()
    return render_template('terms_of_service.html', document=document)

@app.route('/privacy')
def public_privacy():
    db.session.expire_all()
    document = PolicyDocument.query.filter_by(document_type='privacy').first()
    return render_template('privacy_policy.html', document=document)

@app.context_processor
def inject_csrf():
    def generate_csrf_token():
        if 'csrf_token' not in session:
            session['csrf_token'] = str(uuid.uuid4())
        return session['csrf_token']
    return {'csrf_token': generate_csrf_token}

@app.context_processor
def inject_links():
    visible_links = Link.query.filter_by(is_visible=True).all()
    return {'links': visible_links}

@app.context_processor
def utility_processor():
    def get_link_icon(link_name):
        icons = {
            'github': 'github.svg',
            'twitter': 'twitter.svg',
            'linkedin': 'linkedin.svg',
            'facebook': 'facebook.svg',
            # Add more mappings
        }
        default_icon = 'default-link.svg'
        icon_file = icons.get(link_name.lower(), default_icon)
        return f'<img src="/static/icons/{icon_file}" class="link-svg">'
    
    return {'get_link_icon': get_link_icon}

if os.getenv('FLASK_ENV') == 'development':
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.jinja_env.auto_reload = True

with app.app_context():
    db.create_all()

    default_docs = {
        'tos': "<h1>Terms of Service - Initial Content</h1><p>Edit this content in the admin panel</p>",
        'privacy': "<h1>Privacy Policy - Initial Content</h1><p>Edit this content in the admin panel</p>"
    }

    for doc_type, content in default_docs.items():
        if not PolicyDocument.query.filter_by(document_type=doc_type).first():
            new_doc = PolicyDocument(document_type=doc_type, content=content)
            db.session.add(new_doc)
            print(f"Created default {doc_type} document.")

    db.session.commit()


if __name__ == '__main__':
    socketio.run(app, debug=True)