from flask import Flask, request, jsonify, render_template, redirect, url_for, session, abort, Response
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp, URL
from models import db, User, init_db
from utils import preprocess_query, is_injection, notify_admin, get_blocked_ips, log_login_attempt, test_url_phishing
import tensorflow as tf
import pickle
import bcrypt
from flask_cors import CORS
import logging
import json
from io import StringIO
import csv
from datetime import timedelta, datetime
import joblib
import os
import traceback
import numpy as np
import bleach
import re
from urllib.parse import urlparse

app = Flask(__name__)  
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SECRET_KEY'] = 'your_secret_key'
db.init_app(app)

# Rate limiting with in-memory storage
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
limiter.init_app(app)

# Load LSTM model and tokenizer (SQL Injection)
try:
    model = tf.keras.models.load_model('lstm_model.h5')
    with open('tokenizer.pkl', 'rb') as f:
        tokenizer = pickle.load(f)
except Exception as e:
    logging.error(f'Failed to load LSTM model or tokenizer: {e}')
    raise

# Load phishing model
try:
    phishing_model = joblib.load('phishing_model.pkl')
    phishing_scaler = joblib.load('scaler.pkl')
    phishing_feature_names = joblib.load('feature_names.pkl')
except FileNotFoundError as e:
    logging.error(f'Phishing model file missing: {e}')
    raise

# Load XSS model and tokenizer
try:
    xss_model = tf.keras.models.load_model('xss_bilstm_model (1).h5')
    with open('xss_tokenizer.pkl', 'rb') as f:
        xss_tokenizer = pickle.load(f)
except Exception as e:
    logging.error(f'Failed to load XSS model or tokenizer: {e}')
    raise

def preprocess_xss_input(input_string, tokenizer):
    """Preprocess input for XSS detection."""
    sequence = tokenizer.texts_to_sequences([input_string])
    padded_sequence = tf.keras.preprocessing.sequence.pad_sequences(sequence, maxlen=100)
    return padded_sequence

def detect_xss(input_string):
    """Detect XSS using the loaded model and keyword check."""
    if not input_string:
        return False, None
    processed = preprocess_xss_input(input_string, xss_tokenizer)
    prediction = xss_model.predict(processed, verbose=0)[0][0]
    js_keywords = ['alert', 'eval', 'prompt', 'confirm', 'onerror', 'onload']
    is_xss = prediction > 0.3 or any(keyword in input_string.lower() for keyword in js_keywords)
    return is_xss, "Potential XSS detected" if is_xss else None

def sanitize_input(input_string):
    """Sanitize input using bleach to remove dangerous HTML/JS."""
    if not input_string:
        return input_string
    return bleach.clean(input_string, tags=['p', 'strong', 'em'], attributes={}, strip=True, strip_comments=True)

def detect_text_phishing(text):
    """Detect phishing in ad text using keyword-based rules."""
    phishing_keywords = ['free', 'win', 'urgent', 'login', 'account', 'verify', 'prize', 'now', 'click']
    return any(keyword in text.lower() for keyword in phishing_keywords) and re.search(r'\b(http|https)://', text)

def detect_image_phishing(image_url):
    """Detect phishing in image URLs based on domain reputation (simplified)."""
    parsed_url = urlparse(image_url)
    suspicious_domains = ['scam', 'free', 'win', 'fake']
    domain = parsed_url.netloc.lower()
    return any(suspicious in domain for suspicious in suspicious_domains)

# Logging setup
logging.basicConfig(filename='sql_injection.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20), Regexp('^[a-zA-Z0-9_]+$', message='Username must be alphanumeric with underscores.')])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=50)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8), Regexp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]+$', message='Password must include uppercase, lowercase, number, and special character.')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Register')

class AdForm(FlaskForm):
    url = StringField('Ad URL', validators=[DataRequired(), URL(), Length(max=200)])
    text = StringField('Ad Text', validators=[DataRequired(), Length(max=100)])
    image = StringField('Image URL', validators=[DataRequired(), URL(), Length(max=200)])
    ad_type = SelectField('Ad Type', choices=[('auto', 'Auto-Detect'), ('safe', 'Safe'), ('phishing', 'Phishing')], validators=[DataRequired()])
    is_popup = SelectField('Is Popup Ad?', choices=[('no', 'No'), ('yes', 'Yes')], validators=[DataRequired()])
    submit = SubmitField('Save Ad')

# Load and save ads
def load_ads():
    try:
        with open('ads.json', 'r') as f:
            ads_data = json.load(f)
        return ads_data.get('regular', []), ads_data.get('popup', None)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f'Error loading ads: {e}')
        return [
            {'id': '1', 'text': 'Visit Google!', 'url': 'https://www.google.com', 'image': 'https://images.unsplash.com/photo-1611162617474-5b21e879e275?ixlib=rb-4.0.3&auto=format&fit=crop&w=200&h=300', 'is_phishing': False, 'probability': 0.0},
            {'id': '2', 'text': 'Free Login Page!', 'url': 'http://fake-login-page.com/login.php', 'image': 'https://images.unsplash.com/photo-1620712943543-bcc4688e7485?ixlib=rb-4.0.3&auto=format&fit=crop&w=200&h=300', 'is_phishing': True, 'probability': 0.95},
            {'id': '3', 'text': 'Learn at BUE', 'url': 'https://learn1.bue.edu.eg/login/index.php', 'image': 'https://images.unsplash.com/photo-1516321310768-61f0f3ddce88?ixlib=rb-4.0.3&auto=format&fit=crop&w=200&h=300', 'is_phishing': False, 'probability': 0.0}
        ], {'id': '4', 'text': 'Win a Free iPhone!', 'url': 'http://scam-offer.com/iphone', 'image': 'https://images.unsplash.com/photo-1607936854279-55e8a4c64888?ixlib=rb-4.0.3&auto=format&fit=crop&w=400&h=300', 'is_phishing': True, 'probability': 0.98}

def save_ads(regular_ads, popup_ad):
    try:
        with open('ads.json', 'w') as f:
            json.dump({'regular': regular_ads, 'popup': popup_ad}, f, indent=2)
    except Exception as e:
        logging.error(f'Error saving ads: {e}')

@app.before_request
def block_ip():
    client_ip = request.remote_addr
    blocked_ips = get_blocked_ips()
    if client_ip in blocked_ips:
        logging.info(f'Blocked access attempt from {client_ip}')
        abort(403, description="Your IP is blocked due to suspicious activity.")

@app.route('/')
def index():
    ads, popup_ad = load_ads()
    return render_template('index.html', ads=ads, popup_ad=popup_ad)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = sanitize_input(form.username.data.strip())
        email = sanitize_input(form.email.data.strip().lower())
        first_name = sanitize_input(form.first_name.data.strip())
        last_name = sanitize_input(form.last_name.data.strip())
        password = form.password.data
        ip_address = request.remote_addr

        # Check for SQL injection
        inputs = [username, email, first_name, last_name, password]
        if any(is_injection(inp) for inp in inputs):
            notify_admin(f'Registration attempt: Username: {username}, Email: {email}', ip_address, block_ip=True)
            log_login_attempt(username, ip_address, False, 'SQL injection in registration')
            return render_template('register.html', form=form, error='Potential SQL injection detected. Your IP has been blocked.')

        # XSS detection
        for inp in inputs:
            is_xss, xss_message = detect_xss(inp)
            if is_xss:
                notify_admin(f'Registration attempt: Username: {username}, Email: {email}', ip_address, block_ip=True)
                log_login_attempt(username, ip_address, False, f'XSS detected in {inp}')
                return render_template('register.html', form=form, error='Potential XSS detected. Your IP has been blocked.')

        # LSTM check
        try:
            for inp in inputs:
                processed = preprocess_query(inp, tokenizer)
                pred = model.predict(processed, verbose=0)[0]
                if pred.argmax() == 1:
                    notify_admin(f'Registration attempt: Username: {username}, Email: {email}', ip_address, block_ip=True)
                    log_login_attempt(username, ip_address, False, 'Malicious input in registration')
                    return render_template('register.html', form=form, error='Malicious input detected by model. Your IP has been blocked.')
        except Exception as e:
            logging.error(f'Registration prediction error: {e}\n{traceback.format_exc()}')
            notify_admin(f'Registration attempt: Username: {username}, Email: {email}', ip_address, block_ip=True)
            return render_template('register.html', form=form, error='Error processing input. Your IP has been blocked for safety.')

        # Check for existing username or email
        if User.query.filter_by(username=username).first():
            form.username.errors.append('Username already exists.')
            return render_template('register.html', form=form)
        if User.query.filter_by(email=email).first():
            form.email.errors.append('Email already exists.')
            return render_template('register.html', form=form)

        # Create user
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = User(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            password_hash=hashed.decode('utf-8'),
            is_admin=False
        )
        db.session.add(user)
        db.session.commit()
        log_login_attempt(username, ip_address, True, 'Registration successful')
        return redirect(url_for('index'))

    return render_template('register.html', form=form)

@app.route('/submit_feedback', methods=['POST'])
@limiter.limit("5 per minute")
def submit_feedback():
    name = request.form.get('name')
    feedback = request.form.get('feedback')
    ip_address = request.remote_addr

    if not all([name, feedback]):
        return jsonify({'success': False, 'message': 'All fields are required.'}), 400

    # Sanitize and XSS detection
    inputs = [name, feedback]
    sanitized_inputs = [sanitize_input(inp) for inp in inputs]
    for inp in inputs:
        is_xss, xss_message = detect_xss(inp)
        if is_xss:
            notify_admin(f'XSS attempt in feedback form: {inp}', ip_address, block_ip=True)
            log_login_attempt('unknown', ip_address, False, 'XSS in feedback form')
            return jsonify({'success': False, 'message': 'Potential XSS detected. Your IP has been blocked.'}), 403

    # Text phishing detection
    if detect_text_phishing(feedback):
        notify_admin(f'Phishing attempt in feedback message: {feedback}', ip_address, block_ip=True)
        log_login_attempt('unknown', ip_address, False, 'Phishing in feedback form')
        return jsonify({'success': False, 'message': 'Potential phishing detected in feedback. Your IP has been blocked.'}), 403

    # Save feedback
    try:
        try:
            with open('feedback.json', 'r') as f:
                feedbacks = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            feedbacks = []
        feedbacks.append({
            'name': sanitized_inputs[0],
            'feedback': sanitized_inputs[1],
            'timestamp': datetime.utcnow().isoformat(),
            'ip_address': ip_address
        })
        with open('feedback.json', 'w') as f:
            json.dump(feedbacks, f, indent=2)
        logging.info(f'Feedback saved from {ip_address}')
        return jsonify({'success': True, 'message': 'Feedback submitted successfully!'})
    except Exception as e:
        logging.error(f'Failed to save feedback: {e}\n{traceback.format_exc()}')
        return jsonify({'success': False, 'message': 'Failed to submit feedback. Please try again.'}), 500


@app.route('/predict', methods=['POST'])
@limiter.limit("5 per minute")
def predict():
    data = request.get_json()
    username = sanitize_input(data.get('username', '').strip())
    password = data.get('password', '').strip()
    ip_address = request.remote_addr

    # Validate inputs
    if not username or not password:
        log_login_attempt(username, ip_address, False, "Missing username or password")
        return jsonify({
            'blocked': False,
            'valid': False,
            'message': 'Please enter both username and password.'
        })

    # Check for injection
    username_injection = is_injection(username)
    password_injection = is_injection(password)
    if username_injection or password_injection:
        field = 'username' if username_injection else 'password'
        notify_admin(f'Username: {username}, Password: {password}', ip_address, block_ip=True)
        log_login_attempt(username, ip_address, False, f"SQL injection in {field}")
        return jsonify({
            'blocked': True,
            'message': f'Potential SQL injection detected in {field}. Your IP has been blocked.'
        })

    # XSS detection
    is_xss_username, xss_message = detect_xss(username)
    is_xss_password, _ = detect_xss(password)
    if is_xss_username or is_xss_password:
        field = 'username' if is_xss_username else 'password'
        notify_admin(f'Username: {username}, Password: {password}', ip_address, block_ip=True)
        log_login_attempt(username, ip_address, False, f'XSS detected in {field}')
        return jsonify({
            'blocked': True,
            'message': f'Potential XSS detected in {field}. Your IP has been blocked.'
        })

    # LSTM prediction
    try:
        processed_username = preprocess_query(username, tokenizer)
        processed_password = preprocess_query(password, tokenizer)
        pred_username = model.predict(processed_username, verbose=0)[0]
        pred_password = model.predict(processed_password, verbose=0)[0]
        label_username = 'Malicious' if pred_username.argmax() == 1 else 'Safe'
        label_password = 'Malicious' if pred_password.argmax() == 1 else 'Safe'

        if label_username == 'Malicious' or label_password == 'Malicious':
            field = 'username' if label_username == 'Malicious' else 'password'
            notify_admin(f'Username: {username}, Password: {password}', ip_address, block_ip=True)
            log_login_attempt(username, ip_address, False, f"Malicious input in {field}")
            return jsonify({
                'blocked': True,
                'message': f'Malicious input detected in {field} by model. Your IP has been blocked.'
            })
    except Exception as e:
        logging.error(f'Prediction error: {e}\n{traceback.format_exc()}')
        notify_admin(f'Username: {username}, Password: {password}', ip_address, block_ip=True)
        log_login_attempt(username, ip_address, False, "Prediction error")
        return jsonify({
            'blocked': True,
            'message': 'Error processing input. Your IP has been blocked for safety.'
        })

    return jsonify({
        'blocked': False,
        'valid': True,
        'username': username
    })

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    data = request.get_json()
    username = sanitize_input(data.get('username', '').strip())
    password = data.get('password', '').strip()
    ip_address = request.remote_addr

    # Run prediction
    predict_response = predict()
    if predict_response.get_json().get('blocked') or not predict_response.get_json().get('valid', True):
        return predict_response

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        log_login_attempt(username, ip_address, True, "Success")
        session.permanent = True
        if user.is_admin:
            session['admin'] = True
            return jsonify({
                'blocked': False,
                'valid': True,
                'redirect': url_for('admin')
            })
        return jsonify({
            'blocked': False,
            'valid': True,
            'redirect': url_for('success', username=username)
        })

    log_login_attempt(username, ip_address, False, "Invalid credentials")
    return jsonify({
        'blocked': False,
        'valid': False,
        'message': 'Invalid username or password.'
    })

@app.errorhandler(429)
def ratelimit_handler(e):
    ip_address = request.remote_addr
    log_login_attempt("unknown", ip_address, False, "Rate limit exceeded")
    return jsonify({
        'blocked': False,
        'valid': False,
        'message': 'Too many login attempts. Please try again later.'
    }), 429

@app.route('/success/<username>')
def success(username):
    return render_template('success.html', username=username)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get('admin'):
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        ip_address = request.form.get('ip_address')
        username = request.form.get('username')
        if action == 'unblock_ip' and ip_address:
            try:
                with open('alerts.json', 'r') as f:
                    alerts = json.load(f)
                for alert in alerts:
                    if alert['ip_address'] == ip_address:
                        alert['blocked'] = False
                with open('alerts.json', 'w') as f:
                    json.dump(alerts, f, indent=2)
                logging.info(f'IP {ip_address} unblocked by admin')
            except Exception as e:
                logging.error(f'Failed to unblock IP: {e}')
        elif action in ('delete', 'toggle_admin') and username:
            user = User.query.filter_by(username=username).first()
            if user and username != 'mohamed wafiq':
                if action == 'delete':
                    db.session.delete(user)
                elif action == 'toggle_admin':
                    user.is_admin = not user.is_admin
                db.session.commit()
                logging.info(f'User {username} {action} by admin')
    
    alerts = []
    login_attempts = []
    ad_logs = []
    blocked_ips = get_blocked_ips()
    users = User.query.all()
    ads, popup_ad = load_ads()
    try:
        with open('alerts.json', 'r') as f:
            alerts = json.load(f)
        with open('login_attempts.json', 'r') as f:
            login_attempts = json.load(f)
        with open('ad_logs.json', 'r') as f:
            ad_logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return render_template('admin.html', alerts=alerts, blocked_ips=blocked_ips, login_attempts=login_attempts, users=users, ad_logs=ad_logs, ads=ads, popup_ad=popup_ad)

@app.route('/admin/add_ad', methods=['GET', 'POST'])
def add_ad():
    if not session.get('admin'):
        return redirect(url_for('index'))
    form = AdForm()
    if form.validate_on_submit():
        ads, popup_ad = load_ads()
        new_id = str(max([int(ad['id']) for ad in ads] + [int(popup_ad['id'])]) + 1) if ads or popup_ad else '1'
        url = sanitize_input(form.url.data.strip())
        text = sanitize_input(form.text.data.strip())
        image = sanitize_input(form.image.data.strip())
        ad_type = form.ad_type.data
        is_phishing = None
        probability = 0.0

        # URL phishing detection
        if ad_type == 'auto':
            try:
                result = test_url_phishing(url, phishing_model, phishing_scaler, phishing_feature_names)
                is_phishing = result['is_phishing']
                probability = result['phishing_probability']
            except Exception as e:
                logging.error(f'Phishing detection error for {url}: {e}\n{traceback.format_exc()}')
                is_phishing = False
                probability = 0.0
        elif ad_type == 'phishing':
            is_phishing = True
            probability = 1.0
        else:
            is_phishing = False
            probability = 0.0

        # Text phishing detection
        text_phishing = detect_text_phishing(text)
        if text_phishing and not is_phishing:
            is_phishing = True
            probability = max(probability, 0.7)

        # Image phishing detection
        image_phishing = detect_image_phishing(image)
        if image_phishing and not is_phishing:
            is_phishing = True
            probability = max(probability, 0.8)

        # XSS detection for ad inputs
        inputs = [url, text, image]
        for inp in inputs:
            is_xss, xss_message = detect_xss(inp)
            if is_xss:
                notify_admin(f'XSS attempt in ad input: {inp}', request.remote_addr, block_ip=True)
                return render_template('add_ad.html', form=form, error=f'Potential XSS detected in {inp}.')

        new_ad = {
            'id': new_id,
            'url': url,
            'text': text,
            'image': image,
            'is_phishing': is_phishing,
            'probability': probability
        }
        if form.is_popup.data == 'yes':
            popup_ad = new_ad
        else:
            ads.append(new_ad)
        save_ads(ads, popup_ad)
        return redirect(url_for('admin'))
    return render_template('add_ad.html', form=form)

@app.route('/admin/edit_ad/<ad_id>', methods=['GET', 'POST'])
def edit_ad(ad_id):
    if not session.get('admin'):
        return redirect(url_for('index'))
    ads, popup_ad = load_ads()
    ad = next((ad for ad in ads + ([popup_ad] if popup_ad else []) if ad['id'] == ad_id), None)
    if not ad:
        logging.warning(f'Ad not found: {ad_id}')
        return redirect(url_for('admin'))
    form = AdForm(url=ad['url'], text=ad['text'], image=ad['image'], ad_type='auto' if ad['is_phishing'] is None else ('phishing' if ad['is_phishing'] else 'safe'), is_popup='yes' if popup_ad and popup_ad['id'] == ad_id else 'no')
    if form.validate_on_submit():
        url = sanitize_input(form.url.data.strip())
        text = sanitize_input(form.text.data.strip())
        image = sanitize_input(form.image.data.strip())
        ad_type = form.ad_type.data
        is_phishing = None
        probability = 0.0

        # URL phishing detection
        if ad_type == 'auto':
            try:
                result = test_url_phishing(url, phishing_model, phishing_scaler, phishing_feature_names)
                is_phishing = result['is_phishing']
                probability = result['phishing_probability']
            except Exception as e:
                logging.error(f'Phishing detection error for {url}: {e}\n{traceback.format_exc()}')
                is_phishing = False
                probability = 0.0
        elif ad_type == 'phishing':
            is_phishing = True
            probability = 1.0
        else:
            is_phishing = False
            probability = 0.0

        # Text phishing detection
        text_phishing = detect_text_phishing(text)
        if text_phishing and not is_phishing:
            is_phishing = True
            probability = max(probability, 0.7)

        # Image phishing detection
        image_phishing = detect_image_phishing(image)
        if image_phishing and not is_phishing:
            is_phishing = True
            probability = max(probability, 0.8)

        # XSS detection for ad inputs
        inputs = [url, text, image]
        for inp in inputs:
            is_xss, xss_message = detect_xss(inp)
            if is_xss:
                notify_admin(f'XSS attempt in ad input: {inp}', request.remote_addr, block_ip=True)
                return render_template('edit_ad.html', form=form, ad_id=ad_id, error=f'Potential XSS detected in {inp}.')

        updated_ad = {
            'id': ad_id,
            'url': url,
            'text': text,
            'image': image,
            'is_phishing': is_phishing,
            'probability': probability
        }
        if form.is_popup.data == 'yes':
            popup_ad = updated_ad
            ads = [a for a in ads if a['id'] != ad_id]
        else:
            ads = [updated_ad if a['id'] == ad_id else a for a in ads]
            if popup_ad and popup_ad['id'] == ad_id:
                popup_ad = None
        save_ads(ads, popup_ad)
        return redirect(url_for('admin'))
    return render_template('edit_ad.html', form=form, ad_id=ad_id)

@app.route('/admin/delete_ad/<ad_id>')
def delete_ad(ad_id):
    if not session.get('admin'):
        return redirect(url_for('index'))
    ads, popup_ad = load_ads()
    ads = [ad for ad in ads if ad['id'] != ad_id]
    if popup_ad and popup_ad['id'] == ad_id:
        popup_ad = None
    save_ads(ads, popup_ad)
    return redirect(url_for('admin'))

@app.route('/admin/export/<filetype>')
def export(filetype):
    if not session.get('admin'):
        return redirect(url_for('index'))
    try:
        if filetype == 'alerts':
            data = json.load(open('alerts.json'))
            filename = 'alerts.csv'
        elif filetype == 'logins':
            data = json.load(open('login_attempts.json'))
            filename = 'login_attempts.csv'
        elif filetype == 'ads':
            data = json.load(open('ad_logs.json'))
            filename = 'ad_logs.csv'
        else:
            return redirect(url_for('admin'))
        
        si = StringIO()
        cw = csv.writer(si)
        if data:
            cw.writerow(data[0].keys())
            for row in data:
                cw.writerow(row.values())
        output = si.getvalue()
        return Response(
            output,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment;filename={filename}"}
        )
    except Exception as e:
        logging.error(f'Export error: {e}\n{traceback.format_exc()}')
        return redirect(url_for('admin'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/check_ad/<ad_id>')
def check_ad(ad_id):
    ip_address = request.remote_addr
    logging.debug(f'Checking ad: ID={ad_id}, IP={ip_address}')
    ads, popup_ad = load_ads()
    ad = next((ad for ad in ads + ([popup_ad] if popup_ad else []) if ad['id'] == ad_id), None)
    if not ad:
        logging.error(f'Ad not found for ID: {ad_id}')
        return jsonify({'error': 'Ad not found'}), 404
    
    try:
        result = test_url_phishing(ad['url'], phishing_model, phishing_scaler, phishing_feature_names)
        logging.debug(f'Phishing detection result for {ad["url"]}: {result}')
    except Exception as e:
        logging.error(f'Phishing detection error for ad {ad_id} (URL: {ad["url"]}): {str(e)}\n{traceback.format_exc()}')
        is_phishing = ad.get('is_phishing', False)
        probability = ad.get('probability', 0.0)
        logging.warning(f'Using fallback: is_phishing={is_phishing}, probability={probability} for {ad["url"]}')
        result = {
            'is_phishing': is_phishing,
            'phishing_probability': float(probability)
        }

    # Additional phishing checks
    text_phishing = detect_text_phishing(ad['text'])
    image_phishing = detect_image_phishing(ad['image'])
    if text_phishing or image_phishing:
        result['is_phishing'] = True
        result['phishing_probability'] = max(result['phishing_probability'], 0.7 if text_phishing else 0.0, 0.8 if image_phishing else 0.0)

    # Log ad interaction
    ad_log = {
        'timestamp': datetime.utcnow().isoformat(),
        'url': ad['url'],
        'text': ad['text'],
        'is_phishing': result['is_phishing'],
        'probability': result['phishing_probability'],
        'ip_address': ip_address,
        'click_count': 1
    }
    try:
        try:
            with open('ad_logs.json', 'r') as f:
                ad_logs = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            ad_logs = []
        for log in ad_logs:
            if log['url'] == ad['url'] and log['ip_address'] == ip_address:
                log['click_count'] += 1
                log['timestamp'] = ad_log['timestamp']
                break
        else:
            ad_logs.append(ad_log)
        with open('ad_logs.json', 'w') as f:
            json.dump(ad_logs, f, indent=2)
    except Exception as e:
        logging.error(f'Failed to log ad interaction: {e}\n{traceback.format_exc()}')

    # Notify admin of phishing attempt
    if result['is_phishing']:
        notify_admin(f'Phishing URL clicked: {ad["url"]}', ip_address, block_ip=False)

    response = {
        'url': ad['url'],
        'is_phishing': result['is_phishing'],
        'probability': float(result['phishing_probability']),
        'message': 'DANGER: HIGH-RISK PHISHING DETECTED! DO NOT PROCEED. YOUR SECURITY IS AT RISK! (Demo detection, your IP is safe)' if result['is_phishing'] else 'SAFE: This link is secure. Proceeding... (Demo detection)'
    }
    logging.debug(f'check_ad response: {response}')
    return jsonify(response)

@app.route('/advertisements')
def advertisements():
    ads, _ = load_ads()
    results = []
    ip_address = request.remote_addr
    for ad in ads:
        try:
            result = test_url_phishing(ad['url'], phishing_model, phishing_scaler, phishing_feature_names)
        except Exception as e:
            logging.error(f'Phishing detection error for {ad["url"]}: {e}\n{traceback.format_exc()}')
            result = {'is_phishing': ad.get('is_phishing', False), 'phishing_probability': ad.get('probability', 0.0)}

        # Additional phishing checks
        text_phishing = detect_text_phishing(ad['text'])
        image_phishing = detect_image_phishing(ad['image'])
        if text_phishing or image_phishing:
            result['is_phishing'] = True
            result['phishing_probability'] = max(result['phishing_probability'], 0.7 if text_phishing else 0.0, 0.8 if image_phishing else 0.0)

        results.append({
            'text': ad['text'],
            'url': ad['url'],
            'is_phishing': result['is_phishing'],
            'probability': result['phishing_probability']
        })
        if result['is_phishing']:
            notify_admin(f'Phishing URL detected: {ad["url"]}', ip_address, block_ip=False)
            log_login_attempt('unknown', ip_address, False, f'Phishing URL accessed: {ad["url"]}')
    return render_template('advertisements.html', ads=results)

@app.route('/logout')
def logout():
    session.pop('admin', None)
    return redirect(url_for('index'))

@app.route('/submit_contact', methods=['POST'])
@limiter.limit("5 per minute")
def submit_contact():
    name = request.form.get('name')
    email = request.form.get('email')
    message = request.form.get('message')
    ip_address = request.remote_addr

    if not all([name, email, message]):
        return jsonify({'success': False, 'message': 'All fields are required.'}), 400

    # Sanitize and XSS detection
    inputs = [name, email, message]
    sanitized_inputs = [sanitize_input(inp) for inp in inputs]
    for inp in inputs:
        is_xss, xss_message = detect_xss(inp)
        if is_xss:
            notify_admin(f'XSS attempt in contact form: {inp}', ip_address, block_ip=True)
            log_login_attempt('unknown', ip_address, False, 'XSS in contact form')
            return jsonify({'success': False, 'message': 'Potential XSS detected. Your IP has been blocked.'}), 403

    # Text phishing detection
    if detect_text_phishing(message):
        notify_admin(f'Phishing attempt in contact message: {message}', ip_address, block_ip=True)
        log_login_attempt('unknown', ip_address, False, 'Phishing in contact form')
        return jsonify({'success': False, 'message': 'Potential phishing detected in message. Your IP has been blocked.'}), 403

    # Save contact message without display
    try:
        try:
            with open('contact_messages.json', 'r') as f:
                messages = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            messages = []
        messages.append({
            'name': sanitized_inputs[0],
            'email': sanitized_inputs[1],
            'message': sanitized_inputs[2],
            'timestamp': datetime.utcnow().isoformat(),
            'ip_address': ip_address
        })
        with open('contact_messages.json', 'w') as f:
            json.dump(messages, f, indent=2)
        return jsonify({'success': True, 'message': 'Message sent successfully!'})
    except Exception as e:
        logging.error(f'Failed to save contact message: {e}\n{traceback.format_exc()}')
        return jsonify({'success': False, 'message': 'Failed to send message. Please try again.'}), 500

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True, host='0.0.0.0', port=5001)