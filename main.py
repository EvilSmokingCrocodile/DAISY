from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import json
import os
import requests
from datetime import datetime, timedelta, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import pytz
import logging
from logging.handlers import RotatingFileHandler
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = 'your_secret_key_here'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False

# Настройка логирования
def setup_logging():
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            RotatingFileHandler('app.log', maxBytes=1000000, backupCount=3),
            logging.StreamHandler()
        ]
    )

setup_logging()
logger = logging.getLogger(__name__)

# Configuration
CLIENTS_FOLDER = 'clients'
API_BASE_URL = 'https://daisysms.com/stubs/handler_api.php'

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///numbers.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    login = db.Column(db.String(100))
    daisysms_password = db.Column(db.String(100))
    api_token = db.Column(db.String(100))
    activation_id = db.Column(db.String(50))
    phone_number = db.Column(db.String(20))
    service = db.Column(db.String(50))
    rate_per_day = db.Column(db.Float, default=0.80)
    paid_until = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ActiveNumber(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    activation_id = db.Column(db.String(50), unique=True)
    service = db.Column(db.String(50))
    phone = db.Column(db.String(20))
    status = db.Column(db.String(50), default='Waiting')
    sms_text = db.Column(db.String(255))
    cost = db.Column(db.String(10), default='0.00')
    wakeup_at = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    client_email = db.Column(db.String(100))

def get_accurate_utc():
    """Надежное получение UTC времени с логированием"""
    try:
        logger.debug("Attempting to get precise UTC time")
        
        try:
            response = requests.get('http://worldtimeapi.org/api/ip', timeout=2)
            if response.status_code == 200:
                data = response.json()
                dt = datetime.fromisoformat(data['utc_datetime'].replace('Z', '+00:00'))
                if 2024 <= dt.year <= 2026:
                    logger.debug(f"Successfully got time from API: {dt}")
                    return dt
        except Exception as api_error:
            logger.warning(f"WorldTimeAPI error: {str(api_error)}")
        
        sys_time = datetime.now(timezone.utc)
        logger.debug(f"Using system time: {sys_time}")
        return sys_time
        
    except Exception as e:
        logger.error(f"Critical time error: {str(e)}", exc_info=True)
        return datetime.now(timezone.utc)

def load_client(email):
    try:
        client = Client.query.filter_by(email=email).first()
        if client:
            client_data = {
                'login': client.login,
                'password': client.daisysms_password,
                'api_token': client.api_token,
                'activation_id': client.activation_id,
                'phone_number': client.phone_number,
                'service': client.service,
                'rate_per_day': client.rate_per_day,
                'paid_until': client.paid_until.isoformat() if client.paid_until else None
            }
            logger.debug(f"Loaded client data from DB: {client_data}")
            return client_data
        logger.warning(f"Client not found in DB: {email}")
        return None
    except Exception as e:
        logger.error(f"Error loading client {email} from DB: {str(e)}", exc_info=True)
        return None

def migrate_clients_to_db():
    with app.app_context():
        if not os.path.exists(CLIENTS_FOLDER):
            return
        
        for filename in os.listdir(CLIENTS_FOLDER):
            if filename.endswith('.json'):
                email = filename[:-5]
                filepath = os.path.join(CLIENTS_FOLDER, filename)
                
                if Client.query.filter_by(email=email).first():
                    continue
                
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        
                        client = Client(
                            email=email,
                            login=data.get('login'),
                            daisysms_password=data.get('password'),
                            api_token=data.get('api_token'),
                            activation_id=data.get('activation_id'),
                            phone_number=data.get('phone_number'),
                            service=data.get('service'),
                            rate_per_day=data.get('rate_per_day', 0.80),
                            paid_until=datetime.fromisoformat(data['paid_until']) if data.get('paid_until') else None
                        )
                        client.set_password("default_password")  # Temporary password
                        
                        db.session.add(client)
                        db.session.commit()
                        logger.info(f"Migrated client {email} to database")
                        
                except Exception as e:
                    logger.error(f"Error migrating client {email}: {str(e)}", exc_info=True)
                    db.session.rollback()

def get_client_balance(api_key):
    try:
        logger.debug(f"Getting balance for API key: {api_key[:5]}...")
        params = {
            'api_key': api_key,
            'action': 'getBalance'
        }
        response = requests.get(API_BASE_URL, params=params)
        logger.debug(f"Balance API response: {response.text}")
        
        if response.text.startswith('ACCESS_BALANCE:'):
            balance = float(response.text.split(':')[1])
            logger.debug(f"Current balance: {balance}")
            return balance
        return 0.0
    except Exception as e:
        logger.error(f"Balance API error: {str(e)}", exc_info=True)
        return 0.0

def load_tariffs():
    try:
        with open('tariffs.json', 'r') as f:
            tariffs = json.load(f)
            logger.debug(f"Loaded tariffs: {tariffs}")
            return tariffs
    except Exception as e:
        logger.error(f"Error loading tariffs: {str(e)}", exc_info=True)
        return {"Default": 0.50}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        access_key = request.form.get('access_key')
        logger.info(f"Login attempt with access key")
        
        # Ищем клиента с таким password_hash
        client = Client.query.filter_by(password_hash=access_key).first()
        if client:
            session['user_email'] = client.email
            logger.info(f"Successful login for {client.email}")
            return redirect(url_for('dashboard'))
        
        logger.warning("Invalid access key attempt")
        return render_template('user_login.html', error="Invalid access key")
    
    logger.debug("Serving login page")
    return render_template('user_login.html')

@app.route('/logout')
def logout():
    email = session.get('user_email', 'unknown')
    session.pop('user_email', None)
    logger.info(f"User {email} logged out")
    return redirect(url_for('login'))

@app.route('/')
def dashboard():
    if 'user_email' not in session:
        logger.warning("Unauthorized access to dashboard")
        return redirect(url_for('login'))
    
    client = load_client(session['user_email'])
    if not client:
        logger.error(f"Client data not found for {session['user_email']}")
        session.pop('user_email', None)
        return redirect(url_for('login'))
    
    logger.info(f"Rendering dashboard for {session['user_email']}")
    return render_template('user_dashboard.html', client_email=session['user_email'])

@app.route('/api/client_info', methods=['GET'])
def client_info():
    if 'user_email' not in session:
        logger.warning("Unauthorized client info request")
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        client = load_client(session['user_email'])
        if not client:
            logger.error(f"Client not found for {session['user_email']}")
            return jsonify({'error': 'Client not found'}), 404
        
        tariffs = load_tariffs()
        balance = get_client_balance(client['api_token'])
        service = client.get('service', 'Other')
        
        logger.debug(f"Returning client info for {session['user_email']}: balance={balance}, service={service}")
        
        return jsonify({
            'username': session['user_email'].replace('.json', ''),
            'service': service,
            'phone': client.get('phone_number', 'N/A'),
            'balance': balance,
            'doubled_balance': balance * 2,
            'rental_days': int(balance / 0.40 ),
            'rate': tariffs.get(service, tariffs.get('Other', 0.50))
        })
    except Exception as e:
        logger.error(f"Error in client_info: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/get_numbers', methods=['GET'])
def get_numbers():
    logger.info("Fetching numbers for user")
    if 'user_email' not in session:
        logger.warning("Unauthorized access attempt to get_numbers")
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        now = get_accurate_utc()
        client_email = session['user_email']
        logger.debug(f"Current time: {now}, Client: {client_email}")

        # Обновление спящих номеров
        asleep_numbers = ActiveNumber.query.filter(
            ActiveNumber.client_email == client_email,
            ActiveNumber.status == 'Asleep',
            ActiveNumber.wakeup_at <= now
        ).all()
        
        if asleep_numbers:
            logger.info(f"Waking up {len(asleep_numbers)} numbers")
            for num in asleep_numbers:
                num.status = 'Waiting'
                num.expires_at = now + timedelta(seconds=900)
                logger.debug(f"Woke up number {num.activation_id}, new expires_at: {num.expires_at}")

        # Удаление просроченных номеров
        expired_numbers = ActiveNumber.query.filter(
            ActiveNumber.client_email == client_email,
            ActiveNumber.status == 'Waiting',
            ActiveNumber.expires_at <= now
        ).all()
        
        if expired_numbers:
            logger.info(f"Removing {len(expired_numbers)} expired numbers")
            for num in expired_numbers:
                logger.debug(f"Removing expired number {num.activation_id} (expired at {num.expires_at})")
                db.session.delete(num)
        
        db.session.commit()
        
        numbers = ActiveNumber.query.filter_by(client_email=client_email).order_by(ActiveNumber.created_at.desc()).all()
        logger.debug(f"Returning {len(numbers)} numbers to client")
        
        return jsonify([{
            'activation_id': n.activation_id,
            'service': n.service,
            'phone': n.phone,
            'status': n.status,
            'cost': n.cost,
            'sms_text': n.sms_text,
            'wakeup_at': n.wakeup_at.timestamp() if n.wakeup_at else None,
            'expires_at': n.expires_at.timestamp() if n.expires_at else None,
            'created_at': n.created_at.timestamp() if n.created_at else None
        } for n in numbers])
    except Exception as e:
        logger.error(f"Error in get_numbers: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/handle_response', methods=['POST'])
def handle_response():
    logger.info("Handling API response")
    if 'user_email' not in session:
        logger.warning("Unauthorized access attempt to handle_response")
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.json
        response = data['response']
        logger.debug(f"Raw response received: {response}")
        client_email = session['user_email']
        client = load_client(client_email)
        service = client['service'] if client else 'Unknown'
        now = get_accurate_utc()
        logger.debug(f"Current time: {now}, Client: {client_email}, Service: {service}")

        if response.startswith('ACCESS_NUMBER'):
            logger.info("Processing ACCESS_NUMBER response")
            parts = response.split(':')
            if len(parts) >= 3:
                activation_id = parts[1]
                phone = parts[2]
                expires_at = now + timedelta(seconds=900)
                
                logger.debug(f"Creating new number: ID={activation_id}, Phone={phone}, Expires={expires_at}")
                
                new_number = ActiveNumber(
                    activation_id=activation_id,
                    service=service,
                    phone=phone,
                    status='Waiting',
                    cost='0.00',
                    expires_at=expires_at,
                    client_email=client_email
                )
                
                db.session.add(new_number)
                db.session.commit()
                logger.info(f"Number {activation_id} created successfully, expires at {expires_at}")
                
                return jsonify({
                    'success': True,
                    'status': 'Waiting',
                    'message': f"ПРОСНУЛСЯ И ГОТОВ К ПОЛУЧЕНИЮ СМС НОМЕР - {phone}",
                    'expires_at': new_number.expires_at.timestamp()
                })
                
        elif response.startswith('STATUS_OK'):
            logger.info("Processing STATUS_OK response")
            parts = response.split(':')
            activation_id = parts[0].split('_')[-2] if '_' in parts[0] else None
            sms_text = ':'.join(parts[1:])
            
            if not activation_id:
                logger.warning("No activation ID found in STATUS_OK response")
                return jsonify({'success': False, 'error': 'No activation ID in response'})
            
            logger.debug(f"Processing SMS for {activation_id}: {sms_text}")
            
            number = ActiveNumber.query.filter_by(
                activation_id=activation_id,
                client_email=client_email
            ).first()
            
            if number:
                number.status = 'Received'
                number.sms_text = sms_text
                db.session.commit()
                logger.info(f"Updated number {activation_id} with SMS")
                return jsonify({
                    'success': True,
                    'status': 'Received',
                    'message': f"ВНИМАНИЕ! ПОЛУЧЕНА СМС - {sms_text}",
                    'sms_text': sms_text
                })
            else:
                logger.warning(f"Number {activation_id} not found in database")
                return jsonify({'success': False, 'error': 'Number not found'})
                
        elif response == 'STATUS_WAIT_CODE':
            logger.debug("Received STATUS_WAIT_CODE")
            activation_id = data.get('activation_id')
            
            if activation_id:
                number = ActiveNumber.query.filter_by(
                    activation_id=activation_id,
                    client_email=client_email
                ).first()
                
                if number and number.status == 'Asleep':
                    number.status = 'Waiting'
                    number.expires_at = now + timedelta(seconds=900)
                    db.session.commit()
                    logger.info(f"Changed status from Asleep to Waiting for {activation_id}")
            
            return jsonify({
                'success': True,
                'status': 'Waiting',
                'message': 'НОМЕР ГОТОВ К ПРИНЯТИЮ СМС. ПОКА ЧТО ТЕКСТА НЕ ОБНАРУЖЕНО'
            })
                
        elif response.startswith('ASLEEP'):
            logger.info("Processing ASLEEP response")
            parts = response.split(':')
            if len(parts) >= 5:
                activation_id = parts[1]
                phone = parts[2]
                wakeup_at = datetime.fromtimestamp(int(parts[4]), tz=timezone.utc)
                
                logger.debug(f"Creating asleep number: ID={activation_id}, Wakeup={wakeup_at}")
                
                new_number = ActiveNumber(
                    activation_id=activation_id,
                    service=service,
                    phone=phone,
                    status='Asleep',
                    cost='0.00',
                    wakeup_at=wakeup_at,
                    expires_at=wakeup_at + timedelta(seconds=900),
                    client_email=client_email
                )
                db.session.add(new_number)
                db.session.commit()
                logger.info(f"Asleep number {activation_id} created, wakes at {wakeup_at}")
                return jsonify({
                    'success': True,
                    'status': 'Asleep',
                    'wakeup_at': wakeup_at.timestamp()
                })
                
        logger.warning(f"Unhandled response format: {response}")
        return jsonify({'success': False, 'error': 'Unhandled response format', 'raw_response': response})
    
    except Exception as e:
        logger.error(f"Error in handle_response: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/wake_up', methods=['GET'])
def wake_up():
    logger.info("Wake up request received")
    if 'user_email' not in session:
        logger.warning("Unauthorized wake up attempt")
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        client_email = session['user_email']
        client = load_client(client_email)
        
        if not client:
            logger.error(f"Client not found for {client_email}")
            return jsonify({'error': 'Client not found'}), 404
        
        activation_id = request.args.get('activationId') or client.get('activation_id')
        if not activation_id:
            logger.error("No activation ID provided")
            return jsonify({'error': 'Activation ID required'}), 400
        
        params = {
            'api_key': client['api_token'],
            'action': 'getExtraActivation',
            'activationId': activation_id,
            'login': client['login'],
            'password': client['password']
        }
        
        logger.debug(f"Sending wake up request with params: {params}")
        
        response = requests.get(API_BASE_URL, params=params)
        logger.debug(f"Wake up API response: {response.status_code} - {response.text}")
        
        if response.status_code != 200:
            logger.error(f"Wake up API failed: {response.status_code} - {response.text}")
            return jsonify({'error': 'API request failed', 'status': 'ERROR'}), 400
        
        logger.info(f"Successful wake up for {activation_id}: {response.text}")
        return jsonify({
            'status': response.text,
            'raw_response': response.text,
            'request_params': params
        })
    except Exception as e:
        logger.error(f"Error in wake_up: {str(e)}", exc_info=True)
        return jsonify({
            'error': str(e),
            'status': 'ERROR',
            'raw_response': None
        }), 500

@app.route('/api/get_status', methods=['GET'])
def get_status():
    logger.info("Status check request received")
    if 'user_email' not in session:
        logger.warning("Unauthorized status check attempt")
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        activation_id = request.args.get('activationId')
        client_email = session['user_email']
        client = load_client(client_email)
        
        if not client:
            logger.error(f"Client not found for {client_email}")
            return jsonify({'error': 'Client not found'}), 404
        
        if not activation_id:
            logger.error("No activation ID provided for status check")
            return jsonify({'error': 'Activation ID required'}), 400
        
        params = {
            'api_key': client['api_token'],
            'action': 'getStatus',
            'id': activation_id,
            'text': '1'
        }
        
        logger.debug(f"Checking status with params: {params}")
        
        response = requests.get(API_BASE_URL, params=params)
        logger.debug(f"Status API response: {response.status_code} - {response.text}")
        
        if response.status_code != 200:
            logger.error(f"Status API failed: {response.status_code} - {response.text}")
            return jsonify({'error': 'API request failed'}), 400
        
        logger.info(f"Status for {activation_id}: {response.text}")
        return jsonify({'status': response.text})
    except Exception as e:
        logger.error(f"Error in get_status: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/remove_number', methods=['DELETE'])
def remove_number():
    logger.info("Remove number request received")
    if 'user_email' not in session:
        logger.warning("Unauthorized number removal attempt")
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        activation_id = request.args.get('activation_id')
        client_email = session['user_email']
        
        if not activation_id:
            logger.error("No activation ID provided for removal")
            return jsonify({'error': 'Activation ID required'}), 400
            
        num = ActiveNumber.query.filter_by(
            activation_id=activation_id,
            client_email=client_email
        ).first()
        
        if num:
            logger.info(f"Removing number {activation_id} for {client_email}")
            db.session.delete(num)
            db.session.commit()
            return jsonify({'success': True})
        else:
            logger.warning(f"Number {activation_id} not found for {client_email}")
            return jsonify({'error': 'Number not found'}), 404
    except Exception as e:
        logger.error(f"Error in remove_number: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/change_password', methods=['POST'])
def change_password():
    if 'user_email' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    data = request.json
    current_password = data.get('currentPassword')
    new_password = data.get('newPassword')
    
    if not current_password or not new_password:
        return jsonify({'success': False, 'error': 'Missing parameters'}), 400
    
    client = Client.query.filter_by(email=session['user_email']).first()
    if not client:
        return jsonify({'success': False, 'error': 'Client not found'}), 404
    
    if not client.check_password(current_password):
        return jsonify({'success': False, 'error': 'Current password is incorrect'}), 400
    
    try:
        client.set_password(new_password)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# Create tables and migrate data
with app.app_context():
    db.create_all()
    migrate_clients_to_db()
    logger.info("Database tables created/verified and clients migrated")

if __name__ == '__main__':
    logger.info("Starting application")
    app.run(debug=True, host='0.0.0.0', port=5000)