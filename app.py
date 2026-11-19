import os
import json
import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort,jsonify
from ai.chatbot import ask_ai
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from tinydb import TinyDB, Query
from functools import wraps
from elgamal_crypto import generate_keys, encrypt_message, decrypt_message, encrypt_file, decrypt_file

app = Flask(__name__)
app.secret_key = 'super-secret-key-for-life-insurance-portal'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# TinyDB Initialization
db = TinyDB('db.json')
users_table = db.table('users')
policies_table = db.table('policies')
messages_table = db.table('messages')
files_table = db.table('files')
payments_table = db.table('payments')
audit_logs_table = db.table('audit_logs')
notifications_table = db.table('notifications')

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['email']
        self.email = user_data['email']
        self.name = user_data['name']
        self.role = user_data['role']
        self.public_key = user_data.get('public_key')
        self.private_key = user_data.get('private_key')

@login_manager.user_loader
def load_user(user_id):
    user_data = users_table.get(Query().email == user_id)
    if user_data:
        return User(user_data)
    return None

# Audit Logger
def audit_logger(user_email, action, details):
    audit_logs_table.insert({
        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'user_email': user_email,
        'action': action,
        'details': details
    })

# Role Decorator
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                flash("Access denied.", "danger")
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        
        if users_table.search(Query().email == email):
            flash("Email already exists.", "warning")
            return redirect(url_for('signup'))
        
        # Generate ElGamal Keys for the user
        pub, priv = generate_keys()
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        users_table.insert({
            'name': name,
            'email': email,
            'password': hashed_password,
            'role': role,
            'public_key': pub,
            'private_key': priv
        })
        
        audit_logger(email, "Signup", f"New user registered as {role}")
        flash("Registration successful. Please login.", "success")
        return redirect(url_for('login'))
        
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user_data = users_table.get(Query().email == email)
        
        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data)
            login_user(user)
            audit_logger(email, "Login", "User logged in successfully")
            
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'agent':
                return redirect(url_for('agent_dashboard'))
            else:
                return redirect(url_for('client_dashboard'))
        
        flash("Invalid credentials.", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    audit_logger(current_user.email, "Logout", "User logged out")
    logout_user()
    return redirect(url_for('index'))

# --- ADMIN ROUTES ---

@app.route('/admin/dashboard')
@role_required('admin')
def admin_dashboard():
    stats = {
        'agents': len(users_table.search(Query().role == 'agent')),
        'clients': len(users_table.search(Query().role == 'client')),
        'policies': len(policies_table.all()),
        'logs': len(audit_logs_table.all())
    }
    return render_template('admin/dashboard.html', stats=stats)

@app.route('/admin/manage_agents')
@role_required('admin')
def manage_agents():
    agents = users_table.search(Query().role == 'agent')
    return render_template('admin/manage_agents.html', agents=agents)

@app.route('/admin/manage_clients')
@role_required('admin')
def manage_clients():
    clients = users_table.search(Query().role == 'client')
    return render_template('admin/manage_clients.html', clients=clients)

@app.route('/admin/audit_logs')
@role_required('admin')
def admin_audit_logs():
    logs = audit_logs_table.all()[::-1]
    return render_template('admin/audit_logs.html', logs=logs)

@app.route('/admin/view_policies')
@role_required('admin')
def admin_view_policies():
    policies = policies_table.all()
    return render_template('admin/view_policies.html', policies=policies)

@app.route('/admin/communications')
@role_required('admin')
def admin_communications():
    msgs = messages_table.all()[::-1]
    return render_template('admin/communications.html', messages=msgs)

@app.route('/admin/search')
@role_required('admin')
def admin_search():
    query = request.args.get('q', '')
    results = []
    if query:
        # Simple search in users and policies
        for u in users_table.all():
            if query.lower() in u['name'].lower() or query.lower() in u['email'].lower():
                results.append({'type': 'user', 'title': u['name'], 'subtitle': u['email'], 'date': u.get('role')})
        for p in policies_table.all():
            if query.lower() in p['policy_name'].lower() or query.lower() in p['client_email'].lower():
                results.append({'type': 'policy', 'title': p['policy_name'], 'subtitle': f"Client: {p['client_email']}", 'date': p['created_at']})
    
    return render_template('admin/search.html', query=query, results=results)

@app.route('/admin/reports')
@role_required('admin')
def admin_reports():
    return render_template('admin/reports.html')

# --- AGENT ROUTES ---

@app.route('/agent/dashboard')
@role_required('agent')
def agent_dashboard():
    clients = users_table.search(Query().role == 'client')
    return render_template('agent/dashboard.html', clients_count=len(clients))

@app.route('/agent/clients')
@role_required('agent')
def agent_clients():
    clients = users_table.search(Query().role == 'client')
    # Add policy count for each client
    for c in clients:
        c['policy_count'] = len(policies_table.search(Query().client_email == c['email']))
    return render_template('agent/clients.html', clients=clients)

@app.route('/agent/commissions')
@role_required('agent')
def agent_commissions():
    return render_template('agent/commissions.html')

@app.route('/agent/payments')
@role_required('agent')
def agent_payments():
    return render_template('agent/payments.html')

@app.route('/agent/create_policy', methods=['GET', 'POST'])
@role_required('agent')
def create_policy():
    if request.method == 'POST':
        client_email = request.form['client_email']
        policy_name = request.form['policy_name']
        amount = request.form['amount']
        
        policy_id = len(policies_table.all()) + 1
        policies_table.insert({
            'policy_id': policy_id,
            'client_email': client_email,
            'agent_email': current_user.email,
            'policy_name': policy_name,
            'amount': amount,
            'status': 'Active',
            'created_at': datetime.datetime.now().strftime("%Y-%m-%d")
        })
        
        audit_logger(current_user.email, "Policy Creation", f"Created policy {policy_id} for {client_email}")
        flash("Policy created successfully.", "success")
        return redirect(url_for('agent_dashboard'))
        
    clients = users_table.search(Query().role == 'client')
    return render_template('agent/create_policy.html', clients=clients)

@app.route('/agent/compare_policies')
@role_required('agent')
def compare_policies():
    return render_template('agent/compare_policies.html')

# --- CLIENT ---
@app.route('/client/dashboard')
@role_required('client')
def client_dashboard():
    policies = policies_table.search(Query().client_email == current_user.email)
    files = files_table.search(Query().client_email == current_user.email)
    # Add doc_id for links
    for f in files: f['doc_id'] = f.doc_id
    return render_template('client/dashboard.html', policies=policies, files=files)

@app.route('/client/policies')
@role_required('client')
def client_policies_view():
    policies = policies_table.search(Query().client_email == current_user.email)
    return render_template('client/policies.html', policies=policies)

@app.route('/client/agent_communication')
@role_required('client')
def client_agent_communication():
    msgs = messages_table.search((Query().sender_email == current_user.email) | (Query().recipient_email == current_user.email))
    decrypted_msgs = []
    user_data = users_table.get(Query().email == current_user.email)
    for m in msgs:
        try:
            text = decrypt_message(m['encrypted_content'], user_data['private_key']) if m['recipient_email'] == current_user.email else "[Sent Encrypted]"
            decrypted_msgs.append({'sender': m['sender_email'], 'text': text, 'timestamp': m['timestamp']})
        except: pass
    return render_template('client/agent_communication.html', messages=decrypted_msgs)

@app.route('/client/encrypted_files')
@role_required('client')
def client_encrypted_files():
    files = files_table.search(Query().client_email == current_user.email)
    for f in files: f['doc_id'] = f.doc_id
    return render_template('client/encrypted_files.html', files=files)

@app.route('/client/decrypted_files')
@role_required('client')
def client_decrypted_files():
    files = files_table.search(Query().client_email == current_user.email)
    for f in files: f['doc_id'] = f.doc_id
    return render_template('client/decrypted_files.html', files=files)

@app.route('/client/payments')
@role_required('client')
def client_payments():
    return render_template('client/payments.html')

@app.route('/client/profile')
@role_required('client')
def client_profile():
    return render_template('client/profile.html')

# --- FILE ROUTES ---

@app.route('/agent/upload_file', methods=['GET', 'POST'])
@role_required('agent')
def agent_upload_file():
    if request.method == 'POST':
        client_email = request.form['client_email']
        file = request.files['file']
        
        if file:
            filename = f"{datetime.datetime.now().timestamp()}_{file.filename}"
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{filename}")
            enc_filename = f"enc_{filename}.txt"
            enc_path = os.path.join(app.config['UPLOAD_FOLDER'], enc_filename)
            
            file.save(temp_path)
            
            # Get client's public key
            client = users_table.get(Query().email == client_email)
            if client:
                encrypt_file(temp_path, enc_path, client['public_key'])
                os.remove(temp_path)
                
                files_table.insert({
                    'filename': file.filename,
                    'storage_path': enc_filename,
                    'client_email': client_email,
                    'agent_email': current_user.email,
                    'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                
                audit_logger(current_user.email, "File Upload", f"Uploaded and encrypted {file.filename} for {client_email}")
                flash("File uploaded and encrypted successfully.", "success")
                return redirect(url_for('agent_dashboard'))
    
    clients = users_table.search(Query().role == 'client')
    return render_template('agent/upload_file.html', clients=clients)

@app.route('/download/<int:file_id>/<mode>')
@login_required
def download_file_route(file_id, mode):
    file_data = files_table.get(doc_id=file_id)
    if not file_data:
        abort(404)
        
    # Check access
    if current_user.role != 'admin' and current_user.email not in [file_data['client_email'], file_data['agent_email']]:
        abort(403)
        
    enc_path = os.path.join(app.config['UPLOAD_FOLDER'], file_data['storage_path'])
    
    if mode == 'encrypted':
        return send_from_directory(app.config['UPLOAD_FOLDER'], file_data['storage_path'], as_attachment=True)
    
    # Decrypt mode
    user_data = users_table.get(Query().email == current_user.email)
    dec_filename = f"dec_{file_data['filename']}"
    dec_path = os.path.join(app.config['UPLOAD_FOLDER'], dec_filename)
    
    try:
        decrypt_file(enc_path, dec_path, user_data['private_key'])
        audit_logger(current_user.email, "File Decryption", f"Decrypted and downloaded {file_data['filename']}")
        # Serve the decrypted file and delete it after sending to keep server clean
        # response = send_from_directory(app.config['UPLOAD_FOLDER'], dec_filename, as_attachment=True)
        # return response # Note: os.remove(dec_path) after response is tricky with Flask, usually use generator or background task
        return send_from_directory(app.config['UPLOAD_FOLDER'], dec_filename, as_attachment=True)
    except Exception as e:
        flash(f"Decryption failed: {str(e)}", "danger")
        return redirect(request.referrer)

@app.route('/messages')
@login_required
def view_messages():
    msgs = messages_table.search((Query().sender_email == current_user.email) | (Query().recipient_email == current_user.email))
    decrypted_msgs = []
    user_data = users_table.get(Query().email == current_user.email)
    
    for m in msgs:
        try:
            if m['recipient_email'] == current_user.email:
                text = decrypt_message(m['encrypted_content'], user_data['private_key'])
            else:
                text = "[Encrypted Content Sent]"
                
            decrypted_msgs.append({
                'sender': m['sender_email'],
                'recipient': m['recipient_email'],
                'text': text,
                'timestamp': m['timestamp']
            })
        except:
            decrypted_msgs.append({
                'sender': m['sender_email'],
                'recipient': m['recipient_email'],
                'text': "[Decryption Error]",
                'timestamp': m['timestamp']
            })
            
    return render_template('common/notifications.html', messages=decrypted_msgs)

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    recipient_email = request.form['recipient_email']
    message_text = request.form['message']
    
    recipient = users_table.get(Query().email == recipient_email)
    if not recipient:
        flash("Recipient not found.", "danger")
        return redirect(request.referrer)
    
    # Encrypt for recipient
    encrypted_msg = encrypt_message(message_text, recipient['public_key'])
    
    messages_table.insert({
        'sender_email': current_user.email,
        'recipient_email': recipient_email,
        'encrypted_content': encrypted_msg,
        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    
    audit_logger(current_user.email, "Message Sent", f"Sent encrypted message to {recipient_email}")
    flash("Message sent securely.", "success")
    return redirect(request.referrer)
    # ============================
    # AI CHATBOT ROUTES
    # ============================

@app.route('/chatbot')
@login_required
def chatbot():
    return render_template('common/chatbot.html')


@app.route('/chat', methods=['POST'])
@login_required
def chat():
    print("chat route called")
    data = request.get_json()

    user_message = data.get("message")

    if not user_message:
        return jsonify({
            "reply": "Please enter a message."
        })

    reply = ask_ai(user_message)

    return jsonify({
        "reply": reply
    })

if __name__ == '__main__':
    app.run(debug=True)
