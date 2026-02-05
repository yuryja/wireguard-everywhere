import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, make_response
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import bcrypt
from datetime import datetime
import io

from utils.database import Database
from utils.wireguard import WireGuardManager
from utils.qr_generator import generate_qr_code
from utils.i18n import I18n

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['DATABASE'] = os.environ.get('DATABASE', 'wireguard.db')
app.config['WG_CONFIG_PATH'] = os.environ.get('WG_CONFIG_PATH', '/etc/wireguard/wg0.conf')
app.config['CLIENT_CONFIG_DIR'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'clients')
app.config['TRANSLATIONS_PATH'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'translations/locales.json')

# Initialize database
db = Database(app.config['DATABASE'])

# Initialize WireGuard manager
wg_manager = WireGuardManager(app.config['WG_CONFIG_PATH'], app.config['CLIENT_CONFIG_DIR'])

# Initialize I18n
i18n = I18n(app.config['TRANSLATIONS_PATH'])

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Context Processor for I18n
@app.context_processor
def inject_i18n():
    # Detect language: check cookie, then header, default 'en'
    lang = request.cookies.get('lang')
    if not lang:
        lang = request.accept_languages.best_match(i18n.get_available_languages().keys())
    if not lang:
        lang = 'en'
        
    def _(key):
        return i18n.get_text(key, lang)
        
    return dict(_=_, current_lang=lang, available_languages=i18n.get_available_languages())

@app.template_filter('format_bytes')
def format_bytes(size):
    """Format bytes to human readable string"""
    if size is None:
        size = 0
    power = 2**10
    n = 0
    power_labels = {0 : '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"

class User(UserMixin):
    """User model for Flask-Login"""
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username


@login_manager.user_loader
def load_user(user_id):
    """Load user from database"""
    user_data = db.get_user_by_id(int(user_id))
    if user_data:
        return User(user_data['id'], user_data['username'])
    return None

@app.route('/set-lang/<lang>')
def set_language(lang):
    """Set language cookie"""
    if lang in i18n.get_available_languages():
        resp = make_response(redirect(request.referrer or url_for('index')))
        resp.set_cookie('lang', lang, max_age=60*60*24*365) # 1 year
        return resp
    return redirect(request.referrer or url_for('index'))

@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')

@app.route('/')
@login_required
def index():
    """Dashboard - show all clients"""
    clients = db.get_all_clients()
    transfer_stats = wg_manager.get_transfer_stats()
    
    # Enrich clients with real-time data usage and convert to dict for template/logic
    enriched_clients = []
    for client in clients:
        c_dict = dict(client)
        c_dict['data_usage'] = transfer_stats.get(client['public_key'], 0)
        enriched_clients.append(c_dict)
        
    stats = {
        'total_clients': len(enriched_clients),
        'active_clients': sum(1 for c in enriched_clients if c['enabled']),
        'total_data': sum(c['data_usage'] for c in enriched_clients),
        'server_ip': wg_manager.get_server_config()['endpoint']
    }
    return render_template('dashboard.html', clients=enriched_clients, stats=stats)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user_data = db.get_user_by_username(username)
        
        if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data['password_hash'].encode('utf-8')):
            user = User(user_data['id'], user_data['username'])
            login_user(user, remember=request.form.get('remember', False))
            
            # Log successful login
            db.log_activity(user_data['id'], 'login', f'Successful login from {request.remote_addr}')
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('invalid_login', 'error')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """Logout current user"""
    db.log_activity(current_user.id, 'logout', 'User logged out')
    logout_user()
    flash('flash_logout', 'success')
    return redirect(url_for('login'))


@app.route('/clients/add', methods=['GET', 'POST'])
@login_required
def add_client():
    """Add new WireGuard client"""
    if request.method == 'POST':
        client_name = request.form.get('client_name', '').strip()
        
        # Validate client name
        if not client_name:
            flash('flash_name_required', 'error')
            return redirect(url_for('add_client'))
        
        # Sanitize client name (same as install.sh)
        import re
        client_name = re.sub(r'[^0-9a-zA-Z_-]', '_', client_name)[:15]
        
        # Check if client already exists
        if db.get_client_by_name(client_name):
            flash('flash_client_exists', 'error')
            return redirect(url_for('add_client'))
        
        try:
            # Create WireGuard configuration
            config = wg_manager.create_client(client_name)
            
            # Save to database
            db.add_client(
                name=client_name,
                public_key=config['public_key'],
                ip_address=config['ip_address'],
                created_by=current_user.id
            )
            
            # Log activity
            db.log_activity(current_user.id, 'client_created', f'Created client: {client_name}')
            
            flash('flash_client_created', 'success')
            return redirect(url_for('view_client', client_name=client_name))
        
        except Exception as e:
            flash(f'Error creating client: {str(e)}', 'error')
            return redirect(url_for('add_client'))
    
    return render_template('add_client.html')


@app.route('/clients/<client_name>')
@login_required
def view_client(client_name):
    """View client details and QR code"""
    client = db.get_client_by_name(client_name)
    
    if not client:
        flash('Client not found', 'error')
        return redirect(url_for('index'))
    
    # Get configuration file content
    config_content = wg_manager.get_client_config(client_name)
    
    return render_template('view_client.html', client=client, config_content=config_content)


@app.route('/clients/<client_name>/qr')
@login_required
def client_qr(client_name):
    """Generate QR code for client configuration"""
    client = db.get_client_by_name(client_name)
    
    if not client:
        return jsonify({'error': 'Client not found'}), 404
    
    # Get configuration content
    config_content = wg_manager.get_client_config(client_name)
    
    if not config_content:
        return jsonify({'error': 'Configuration not found'}), 404
    
    # Generate QR code
    qr_image = generate_qr_code(config_content)
    
    # Return as PNG image
    img_io = io.BytesIO()
    qr_image.save(img_io, 'PNG')
    img_io.seek(0)
    
    return send_file(img_io, mimetype='image/png')


@app.route('/clients/<client_name>/download')
@login_required
def download_client_config(client_name):
    """Download client configuration file"""
    client = db.get_client_by_name(client_name)
    
    if not client:
        flash('Client not found', 'error')
        return redirect(url_for('index'))
    
    # Get configuration file path
    config_path = wg_manager.get_client_config_path(client_name)
    
    if not os.path.exists(config_path):
        flash('Configuration file not found', 'error')
        return redirect(url_for('view_client', client_name=client_name))
    
    # Log activity
    db.log_activity(current_user.id, 'config_downloaded', f'Downloaded config for: {client_name}')
    
    return send_file(config_path, as_attachment=True, download_name=f'{client_name}.conf')


@app.route('/clients/<client_name>/toggle', methods=['POST'])
@login_required
def toggle_client(client_name):
    """Enable/disable a client"""
    client = db.get_client_by_name(client_name)
    
    if not client:
        return jsonify({'error': 'Client not found'}), 404
    
    try:
        new_status = not client['enabled']
        
        if new_status:
            wg_manager.enable_client(client_name)
        else:
            wg_manager.disable_client(client_name)
        
        db.update_client_status(client_name, new_status)
        
        # Log activity
        action = 'enabled' if new_status else 'disabled'
        db.log_activity(current_user.id, 'client_toggled', f'{action.capitalize()} client: {client_name}')
        
        return jsonify({'success': True, 'enabled': new_status})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/clients/<client_name>/delete', methods=['POST'])
@login_required
def delete_client(client_name):
    """Delete a client"""
    client = db.get_client_by_name(client_name)
    
    if not client:
        flash('Client not found', 'error')
        return redirect(url_for('index'))
    
    try:
        # Remove from WireGuard
        wg_manager.delete_client(client_name)
        
        # Remove from database
        db.delete_client(client_name)
        
        # Log activity
        db.log_activity(current_user.id, 'client_deleted', f'Deleted client: {client_name}')
        
        flash('flash_client_deleted', 'success')
    
    except Exception as e:
        flash(f'Error deleting client: {str(e)}', 'error')
    
    return redirect(url_for('index'))


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """Settings page"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            user_data = db.get_user_by_id(current_user.id)
            
            if not bcrypt.checkpw(current_password.encode('utf-8'), user_data['password_hash'].encode('utf-8')):
                flash('flash_password_incorrect', 'error')
            elif new_password != confirm_password:
                flash('flash_password_mismatch', 'error')
            elif len(new_password) < 8:
                flash('flash_password_min_length', 'error')
            else:
                # Hash new password
                password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                db.update_user_password(current_user.id, password_hash)
                
                # Log activity
                db.log_activity(current_user.id, 'password_changed', 'Password changed successfully')
                
                flash('flash_password_changed', 'success')
    
    # Get activity logs
    logs = db.get_activity_logs(limit=50)
    
    return render_template('settings.html', logs=logs)


@app.route('/api/stats')
@login_required
def api_stats():
    """API endpoint for dashboard statistics"""
    clients = db.get_all_clients()
    
    return jsonify({
        'total_clients': len(clients),
        'active_clients': sum(1 for c in clients if c['enabled']),
        'inactive_clients': sum(1 for c in clients if not c['enabled']),
        'recent_clients': [
            {
                'name': c['name'],
                'created_at': c['created_at'],
                'enabled': c['enabled']
            }
            for c in sorted(clients, key=lambda x: x['created_at'], reverse=True)[:5]
        ]
    })


if __name__ == '__main__':
    # Initialize database tables
    db.init_database()
    
    # Check if admin user exists, if not create one
    if not db.get_user_by_username('admin'):
        default_password = secrets.token_urlsafe(16)
        password_hash = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        db.create_user('admin', password_hash)
        print(f'\n{"="*60}')
        print(f'🔐 Default admin user created!')
        print(f'   Username: admin')
        print(f'   Password: {default_password}')
        print(f'   ⚠️  Please change this password immediately after login!')
        print(f'{"="*60}\n')
    
    # Run the app
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    print(f'\n🚀 WireGuard Web Manager starting on http://0.0.0.0:{port}')
    print(f'   Press CTRL+C to quit\n')
    
    app.run(host='0.0.0.0', port=port, debug=debug)
