from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from main import *
from setting import *
from setting import MajorLoginRes
import threading
import time
import socket
import json
import base64
import requests
from datetime import datetime, timedelta, timezone
import jwt
import gzip
from google.protobuf.timestamp_pb2 import Timestamp
import MajorLoginRes_pb2
import errno
import select
import atexit
import os
import signal
import sys
import psutil
import urllib3
import logging
import random
import hashlib
import secrets

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
# Use a fixed secret key for session persistence across restarts
SECRET_KEY_FILE = 'secret_key.txt'
if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, 'r') as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, 'w') as f:
        f.write(app.secret_key)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please login to access this page.'
login_manager.login_message_category = 'info'

# Region configuration with GetLoginData URLs and Hosts
REGION_CONFIG = {
    "IND": {
        "url": "https://client.ind.freefiremobile.com/GetLoginData",
        "host": "client.ind.freefiremobile.com",
        "json_file": "ind.json"
    },
    "ID": {
        "url": "https://clientbp.ggblueshark.com/GetLoginData",
        "host": "clientbp.common.ggbluefox.com",
        "json_file": "ID.json"
    },
    "BR": {
        "url": "https://client.us.freefiremobile.com/GetLoginData",
        "host": "client.us.freefiremobile.com",
        "json_file": "BR.json"
    },
    "ME": {
        "url": "https://clientbp.ggblueshark.com/GetLoginData",
        "host": "clientbp.common.ggbluefox.com",
        "json_file": "ME.json"
    },
    "VN": {
        "url": "https://clientbp.ggblueshark.com/GetLoginData",
        "host": "clientbp.common.ggbluefox.com",
        "json_file": "VN.json"
    },
    "TH": {
        "url": "https://clientbp.ggblueshark.com/GetLoginData",
        "host": "clientbp.common.ggbluefox.com",
        "json_file": "TH.json"
    },
    "CIS": {
        "url": "https://clientbp.ggblueshark.com/GetLoginData",
        "host": "clientbp.common.ggbluefox.com",
        "json_file": "CIS.json"
    },
    "BD": {
        "url": "https://clientbp.ggblueshark.com/GetLoginData",
        "host": "clientbp.ggbluefox.com",
        "json_file": "bd.json"
    },
    "PK": {
        "url": "https://clientbp.ggblueshark.com/GetLoginData",
        "host": "clientbp.common.ggbluefox.com",
        "json_file": "pk.json"
    },
    "SG": {
        "url": "https://clientbp.ggblueshark.com/GetLoginData",
        "host": "clientbp.common.ggbluefox.com",
        "json_file": "SG.json"
    },
    "NA": {
        "url": "https://client.us.freefiremobile.com/GetLoginData",
        "host": "client.us.freefiremobile.com",
        "json_file": "NA.json"
    },
    "US": {
        "url": "https://client.us.freefiremobile.com/GetLoginData",
        "host": "client.us.freefiremobile.com",
        "json_file": "US.json"
    },
    "SAC": {
        "url": "https://client.us.freefiremobile.com/GetLoginData",
        "host": "client.us.freefiremobile.com",
        "json_file": "SAC.json"
    },
    "EU": {
        "url": "https://clientbp.ggblueshark.com/GetLoginData",
        "host": "clientbp.common.ggbluefox.com",
        "json_file": "EU.json"
    },
    "TW": {
        "url": "https://clientbp.ggblueshark.com/GetLoginData",
        "host": "clientbp.common.ggbluefox.com",
        "json_file": "TW.json"
    }
}

# Separate clients for each region - dynamically created
clients = {}
shutting_down = False

# For compact printing - group accounts
connected_accounts = []
print_lock = threading.Lock()

shared_0500_info = {
    'got': False,
    'idT': None,
    'squad': None,
    'AutH': None
}

MASTER_ACCOUNT_ID = '4208257071'  # Chỉnh sửa theo tài khoản chính của bạn

# Track team_code -> (account_id, last_fetch_time) mapping for each region - dynamically created
team_tracking = {}
team_tracking_lock = threading.Lock()

# BD auto-join loop control (global - for backward compatibility)
bd_loop_running = False
bd_loop_thread = None
bd_loop_lock = threading.Lock()

# Account-specific loop control
account_loops = {}  # account_id -> {'running': bool, 'thread': Thread}
account_loops_lock = threading.Lock()

# Loop auto-start configuration file
LOOP_AUTOSTART_FILE = 'loop_autostart.json'

# Helper functions for loop auto-start configuration
def load_loop_autostart_config():
    """Load loop auto-start configuration from file."""
    if os.path.exists(LOOP_AUTOSTART_FILE):
        try:
            with open(LOOP_AUTOSTART_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                if config:
                    print(f"📋 Loaded auto-start config: {len(config)} account(s) with auto-start enabled")
                return config
        except Exception as e:
            print(f"❌ Error loading loop autostart config: {e}")
            return {}
    else:
        print(f"ℹ️  Auto-start config file not found: {LOOP_AUTOSTART_FILE}")
    return {}

def save_loop_autostart_config(config):
    """Save loop auto-start configuration to file."""
    try:
        with open(LOOP_AUTOSTART_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        if config:
            print(f"💾 Saved auto-start config: {len(config)} account(s) enabled")
    except Exception as e:
        print(f"❌ Error saving loop autostart config: {e}")

def is_loop_autostart_enabled(account_id):
    """Check if auto-start is enabled for an account's loop."""
    config = load_loop_autostart_config()
    return config.get(account_id, False)

def set_loop_autostart(account_id, enabled):
    """Set auto-start preference for an account's loop."""
    config = load_loop_autostart_config()
    if enabled:
        config[account_id] = True
        print(f"✅ Enabled auto-start for account {account_id}")
    else:
        config.pop(account_id, None)  # Remove if disabled
        print(f"❌ Disabled auto-start for account {account_id}")
    save_loop_autostart_config(config)

def auto_start_loops_for_accounts():
    """Auto-Start Level UPs for accounts that have auto-start enabled and team codes."""
    print("\n🔄 Checking for accounts with auto-start enabled...")
    autostart_config = load_loop_autostart_config()
    
    if not autostart_config:
        print("ℹ️  No accounts with auto-start enabled found.")
        return
    
    for region_code, config in REGION_CONFIG.items():
        try:
            json_file = config['json_file']
            accounts_metadata = get_all_accounts_metadata(json_file)
            
            for account_id, account_data in accounts_metadata.items():
                # Check if auto-start is enabled for this account
                if account_id in autostart_config and autostart_config[account_id]:
                    team_code = account_data.get('team_code', '')
                    if team_code:
                        # Wait a bit for client to connect, then Start Level UP with retry logic
                        def start_loop_after_delay(acc_id, region):
                            max_retries = 6  # Try for up to 60 seconds (6 * 10 seconds)
                            retry_count = 0
                            
                            while retry_count < max_retries and not shutting_down:
                                time.sleep(10)  # Wait 10 seconds between retries
                                retry_count += 1
                                
                                # Check if account is running and loop is not already running
                                with account_loops_lock:
                                    if acc_id in account_loops and account_loops[acc_id].get('running', False):
                                        print(f"[{acc_id}] ✅ Loop already running, skipping auto-start")
                                        return
                                    
                                    if is_account_running(acc_id, region):
                                        # Double check account is actually connected
                                        if region in clients and acc_id in clients[region]:
                                            client = clients[region][acc_id]
                                            if client.running and client.socket_client and client.is_socket_connected(client.socket_client):
                                                # Make sure loop is not already running
                                                if acc_id not in account_loops or not account_loops[acc_id].get('running', False):
                                                    account_loops[acc_id] = {
                                                        'running': True,
                                                        'thread': None
                                                    }
                                                    loop_thread = threading.Thread(target=account_auto_join_loop, args=(acc_id,), daemon=True)
                                                    account_loops[acc_id]['thread'] = loop_thread
                                                    loop_thread.start()
                                                    print(f"[{acc_id}] ✅ Auto-started loop on server startup (auto-start enabled, attempt {retry_count})")
                                                    return
                                                else:
                                                    print(f"[{acc_id}] ℹ️  Loop already running, skipping")
                                                    return
                                            else:
                                                print(f"[{acc_id}] ⚠️  Account client not fully connected yet (socket check failed)")
                                        else:
                                            print(f"[{acc_id}] ⚠️  Account client not found in clients dict")
                                    else:
                                        print(f"[{acc_id}] ⚠️  Account not running yet (is_account_running returned False)")
                                
                                if retry_count < max_retries:
                                    print(f"[{acc_id}] ⏳ Waiting for account to connect... (attempt {retry_count}/{max_retries})")
                            
                            print(f"[{acc_id}] ❌ Failed to auto-Start Level UP: account not ready after {max_retries} attempts")
                        
                        loop_start_thread = threading.Thread(target=start_loop_after_delay, args=(account_id, region_code), daemon=True)
                        loop_start_thread.start()
                        print(f"[{account_id}] 📋 Queued for auto-start (has team code: {team_code})")
        except Exception as e:
            print(f"Error checking auto-start for {region_code} accounts: {e}")
    
    print("✅ Auto-start check completed\n")

# User authentication
USERS_FILE = 'users.json'
SESSIONS_FILE = 'sessions.json'
active_sessions = {}  # Track active sessions
session_lock = threading.Lock()

# Load persistent sessions from file
def load_sessions():
    """Load sessions from file on startup."""
    global active_sessions
    if os.path.exists(SESSIONS_FILE):
        try:
            with open(SESSIONS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Only load sessions that haven't expired (30 days)
                current_time = time.time()
                active_sessions = {
                    session_id: session_data
                    for session_id, session_data in data.items()
                    if current_time - session_data.get('created_at', 0) < 2592000  # 30 days
                }
                # Save cleaned sessions
                if len(active_sessions) != len(data):
                    save_sessions()
        except Exception as e:
            print(f"Error loading sessions: {e}")
            active_sessions = {}
    else:
        active_sessions = {}

# Save sessions to file
def save_sessions():
    """Save sessions to file."""
    try:
        with open(SESSIONS_FILE, 'w', encoding='utf-8') as f:
            json.dump(active_sessions, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"Error saving sessions: {e}")

# Load sessions on startup
load_sessions()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_id, username, password_hash, role='user', assigned_account=None, valid_until=None):
        self.id = user_id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.assigned_account = assigned_account
        self.valid_until = valid_until
    
    def is_admin(self):
        return self.role == 'admin'
    
    def is_valid(self):
        """Check if user account is still valid"""
        if not self.valid_until:
            return True  # No expiration
        try:
            expiry = datetime.fromisoformat(self.valid_until)
            return datetime.now() < expiry
        except:
            return True

# Load users from file
def load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}
    return {}

# Save users to file
def save_users(users_data):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users_data, f, indent=4, ensure_ascii=False)

# Initialize default admin user if not exists
def init_default_user():
    users = load_users()
    if not users:
        default_username = 'admin'
        default_password = 'admin123'
        users[default_username] = {
            'password_hash': generate_password_hash(default_password),
            'created_at': datetime.now().isoformat(),
            'role': 'admin',
            'assigned_account': None,
            'valid_until': None
        }
        save_users(users)
        print(f"Default admin user created: {default_username} / {default_password}")
    else:
        # Ensure existing admin has role set
        for username, user_data in users.items():
            if 'role' not in user_data:
                user_data['role'] = 'admin'  # Backward compatibility
            if 'assigned_account' not in user_data:
                user_data['assigned_account'] = None
            if 'valid_until' not in user_data:
                user_data['valid_until'] = None
        save_users(users)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    users = load_users()
    if user_id in users:
        user_data = users[user_id]
        return User(
            user_id, 
            user_id, 
            user_data['password_hash'],
            role=user_data.get('role', 'user'),
            assigned_account=user_data.get('assigned_account'),
            valid_until=user_data.get('valid_until')
        )
    return None

# Invalidate all sessions (for password change)
def invalidate_all_sessions():
    global active_sessions
    with session_lock:
        active_sessions.clear()
        save_sessions()  # Save empty sessions to file
    # Note: Flask-Login sessions will be invalidated on next request

# Security: Anti-debugging and code protection
def add_security_headers(response):
    """Add security headers to prevent code extraction"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    return response

# Admin-only decorator with security
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return add_security_headers(jsonify({'success': False, 'error': 'Authentication required'})), 401
        if not current_user.is_admin():
            return add_security_headers(jsonify({'success': False, 'error': 'Admin access required'})), 403
        result = f(*args, **kwargs)
        if isinstance(result, tuple) and len(result) == 2:
            response, status = result
            return add_security_headers(response), status
        return add_security_headers(result)
    return decorated_function

# Secure API decorator
def secure_api(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Validate request origin
        if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
            # Allow but log suspicious activity
            pass
        
        result = f(*args, **kwargs)
        if isinstance(result, tuple) and len(result) == 2:
            response, status = result
            return add_security_headers(response), status
        return add_security_headers(result)
    return decorated_function

# Check if user is valid (not expired)
def check_user_validity():
    if current_user.is_authenticated and not current_user.is_admin():
        if not current_user.is_valid():
            logout_user()
            flash('Your account has expired. Please contact admin.', 'error')
            return redirect(url_for('login'))
    return None

# Helper functions for team chat connection
def get_random_color():
    colors = [
        "[FF0000]", "[00FF00]", "[0000FF]", "[FFFF00]", "[FF00FF]", "[00FFFF]", "[FFFFFF]", "[FFA500]",
        "[A52A2A]", "[800080]", "[000000]", "[808080]", "[C0C0C0]", "[FFC0CB]", "[FFD700]", "[ADD8E6]",
        "[90EE90]", "[D2691E]", "[DC143C]", "[00CED1]", "[9400D3]", "[F08080]", "[20B2AA]", "[FF1493]",
        "[7CFC00]", "[B22222]", "[FF4500]", "[DAA520]", "[00BFFF]", "[00FF7F]", "[4682B4]", "[6495ED]",
        "[5F9EA0]", "[DDA0DD]", "[E6E6FA]", "[B0C4DE]", "[556B2F]", "[8FBC8F]", "[2E8B57]", "[3CB371]",
        "[6B8E23]", "[808000]", "[B8860B]", "[CD5C5C]", "[8B0000]", "[FF6347]", "[FF8C00]", "[BDB76B]",
        "[9932CC]", "[8A2BE2]", "[4B0082]", "[6A5ACD]", "[7B68EE]", "[4169E1]", "[1E90FF]", "[191970]",
        "[00008B]", "[000080]", "[008080]", "[008B8B]", "[B0E0E6]", "[AFEEEE]", "[E0FFFF]", "[F5F5DC]",
        "[FAEBD7]"
    ]
    return random.choice(colors)

def GeTSQDaTa(D):
    """Extract squad data from decoded packet"""
    try:
        uid = D['5']['data']['1']['data']
        chat_code = D["5"]["data"]["14"]["data"]
        squad_code = D["5"]["data"]["31"]["data"]
        return uid, chat_code, squad_code
    except Exception as e:
        print(f"Error extracting squad data: {e}")
        return None, None, None

def AuTo_ResTartinG():
    while not shutting_down:
        time.sleep(3 * 60)
        print('\n - AuTo ResTartinG The BoT ... ! ')
        python = sys.executable
        print(f" - Restarting app.py")
        os.execl(python, python, *sys.argv)

def ResTarT_BoT():
    print('\n - ResTartinG The BoT ... ! ')
    python = sys.executable
    os.execl(python, python, *sys.argv)

class TcpBotConnectMain:
    def __init__(self, account_id, password, region='PK'):
        self.account_id = account_id
        self.password = password
        self.region = region.upper()  # Region code (PK, IND, BD, etc.)
        self.key = None
        self.iv = None
        self.socket_client = None
        self.clientsocket = None
        self.running = False
        self.connection_attempts = 0
        self.max_connection_attempts = 3
        self.AutH = None
        self.DaTa2 = None
        self.team_chat_connected = False  # Flag to track team chat connection
        
        # Get region-specific configuration
        if self.region in REGION_CONFIG:
            self.region_url = REGION_CONFIG[self.region]['url']
            self.region_host = REGION_CONFIG[self.region]['host']
        else:
            # Default fallback
            self.region_url = 'https://clientbp.ggblueshark.com/GetLoginData'
            self.region_host = 'clientbp.common.ggbluefox.com'
    
    def run(self):
        if shutting_down:
            return
            
        # بدء إعادة التشغيل التلقائي لوحدة العميل مرة واحدة
        if not hasattr(self, "auto_restart_thread_started"):
            t = threading.Thread(target=AuTo_ResTartinG, daemon=True)
            t.start()
            self.auto_restart_thread_started = True
        
        self.running = True
        self.connection_attempts = 0
        
        while self.running and not shutting_down and self.connection_attempts < self.max_connection_attempts:
            try:
                self.connection_attempts += 1
                print(f"[{self.account_id}] محاولة الاتصال {self.connection_attempts}/{self.max_connection_attempts}")
                self.get_tok()
                break
            except Exception as e:
                print(f"[{self.account_id}] Error in run: {e}")
                if self.connection_attempts >= self.max_connection_attempts:
                    print(f"[{self.account_id}] وصل للحد الأقصى لمحاولات الاتصال. التوقف.")
                    self.stop()
                    break
                print(f"[{self.account_id}] إعادة المحاولة بعد 5 ثواني...")
                time.sleep(5)
    
    def stop(self):
        self.running = False
        try:
            if self.clientsocket:
                self.clientsocket.close()
        except:
            pass
        try:
            if self.socket_client:
                self.socket_client.close()
        except:
            pass
        print(f"[{self.account_id}] Client stopped")
    
    def restart(self, delay=5):
        if shutting_down:
            return
            
        print(f"[{self.account_id}] Restarting client in {delay} seconds...")
        time.sleep(delay)
        self.run()
    
    def is_socket_connected(self, sock):
        try:
            if sock is None:
                return False
            writable = select.select([], [sock], [], 0.1)[1]
            if sock in writable:
                sock.send(b'')
                return True
            return False
        except (OSError, socket.error) as e:
            if e.errno == errno.EBADF:
                print(f"[{self.account_id}] Socket bad file descriptor")
            return False
        except Exception as e:
            print(f"[{self.account_id}] Socket check error: {e}")
            return False
    
    def ensure_connection(self):
        if not self.is_socket_connected(self.socket_client) and self.running:
            print(f"[{self.account_id}] Attempting to reconnect")
            self.restart(delay=2)
            return False
        return True
    
    def sockf1(self, tok, online_ip, online_port, packet, key, iv):
        while self.running and not shutting_down:
            try:
                # Reset team chat connection flag on reconnect
                self.team_chat_connected = False
                
                self.socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket_client.settimeout(30)
                self.socket_client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                
                online_port = int(online_port)
                print(f"[{self.account_id}] Connecting to {online_ip}:{online_port}...")
                self.socket_client.connect((online_ip, online_port))
                print(f"[{self.account_id}] Connected to {online_ip}:{online_port}")
                self.socket_client.send(bytes.fromhex(tok))
                print(f"[{self.account_id}] Token sent successfully")
                
                while self.running and not shutting_down and self.is_socket_connected(self.socket_client):
                    try:
                        readable, _, _ = select.select([self.socket_client], [], [], 1.0)
                        if self.socket_client in readable:
                            self.DaTa2 = self.socket_client.recv(99999)
                            if not self.DaTa2:
                                print(f"[{self.account_id}] Server closed connection gracefully")
                                break

                            # Team chat connection logic (same as dance.py TcPOnLine)
                            if self.DaTa2.hex().startswith('0500') and len(self.DaTa2.hex()) > 1000:
                                if not self.team_chat_connected:
                                    try:
                                        print(f"[{self.account_id}] DEBUG: Detected 0500 packet, attempting team chat connection")
                                        print(f"[{self.account_id}] DEBUG: Packet hex: {self.DaTa2.hex()[:100]}...")
                                        
                                        # Decode packet
                                        packet_hex = self.DaTa2.hex()[10:]
                                        decoded_packet = DeCode_PackEt(packet_hex)
                                        if decoded_packet:
                                            print(f"[{self.account_id}] DEBUG: Decoded packet successfully")
                                            packet = json.loads(decoded_packet)
                                            print(f"[{self.account_id}] DEBUG: Parsed JSON packet")
                                            
                                            # Extract team data
                                            OwNer_UiD, CHaT_CoDe, SQuAD_CoDe = GeTSQDaTa(packet)
                                            if OwNer_UiD and CHaT_CoDe and SQuAD_CoDe:
                                                print(f"[{self.account_id}] DEBUG: Got team data - Owner: {OwNer_UiD}, Chat: {CHaT_CoDe}, Squad: {SQuAD_CoDe}")
                                                
                                                # Authenticate with team chat
                                                # Auth_Chat(idT, sq, K, V) - type 3 is hardcoded in main.py
                                                JoinCHaT = Auth_Chat(OwNer_UiD, CHaT_CoDe, self.key, self.iv)
                                                
                                                # Send auth packet through whisper socket (clientsocket)
                                                if self.clientsocket and self.is_socket_connected(self.clientsocket):
                                                    self.clientsocket.send(JoinCHaT)
                                                    print(f"[{self.account_id}] DEBUG: Sent team chat auth packet")
                                                    
                                                    # Send welcome message
                                                    color1 = get_random_color()
                                                    color2 = get_random_color()
                                                    cmd1 = xMsGFixinG('RIFAT')
                                                    cmd2 = xMsGFixinG('FALCONcheatsX64')
                                                    dev = xMsGFixinG('FALCONX64')
                                                    message = '[B][C]{}\n- WeLComE To Emote Bot ! \n\n{}- Owner : {} \n\nYOUTUBE : @{} \n\n[00FF00]Dev : {}'.format(
                                                        color1, color2, cmd1, cmd2, dev
                                                    )
                                                    
                                                    # Create message packet (using xSendTeamMsg from main.py)
                                                    msg_packet = xSendTeamMsg(message, OwNer_UiD, self.key, self.iv)
                                                    self.clientsocket.send(msg_packet)
                                                    print(f"[{self.account_id}] DEBUG: Successfully sent welcome message to team chat")
                                                    
                                                    self.team_chat_connected = True
                                                else:
                                                    print(f"[{self.account_id}] DEBUG: Whisper socket not connected, cannot send chat packets")
                                            else:
                                                print(f"[{self.account_id}] DEBUG: Failed to extract team data")
                                        else:
                                            print(f"[{self.account_id}] DEBUG: Failed to decode packet")
                                    except Exception as e:
                                        print(f"[{self.account_id}] DEBUG: Exception in team chat connection: {e}")
                                        import traceback
                                        traceback.print_exc()
                                
                    except socket.timeout:
                        continue
                    except (OSError, socket.error) as e:
                        if e.errno == errno.EBADF:
                            print(f"[{self.account_id}] Bad file descriptor, reconnecting...")
                            break
                        else:
                            print(f"[{self.account_id}] Socket error: {e}. Reconnecting...")
                            break
                    except Exception as e:
                        print(f"[{self.account_id}] Unexpected error: {e}. Reconnecting...")
                        break
                        
            except socket.timeout:
                print(f"[{self.account_id}] Connection timeout, retrying...")
            except (OSError, socket.error) as e:
                if e.errno == errno.EBADF:
                    print(f"[{self.account_id}] Bad file descriptor during connection")
                else:
                    print(f"[{self.account_id}] Connection error: {e}")
            except Exception as e:
                print(f"[{self.account_id}] Unexpected error: {e}")
    def connect(self, tok, packet, key, iv, whisper_ip, whisper_port, online_ip, online_port):
        while self.running and not shutting_down:
            try:
                self.clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.clientsocket.settimeout(None)
                self.clientsocket.connect((whisper_ip, int(whisper_port)))
                print(f"[{self.account_id}] Connected to {whisper_ip}:{whisper_port}")
                self.clientsocket.send(bytes.fromhex(tok))
                self.data = self.clientsocket.recv(1024)
                self.clientsocket.send(get_packet2(self.key, self.iv))

                thread = threading.Thread(
                    target=self.sockf1,
                    args=(tok, online_ip, online_port, "anything", key, iv)
                )
                thread.daemon = True
                thread.start()
                
                while self.running and not shutting_down:
                    dataS = self.clientsocket.recv(1024)
                    if not dataS:
                        break
            except Exception as e:
                if not shutting_down:
                    print(f"[{self.account_id}] Error in connect: {e}. Retrying in 3 seconds...")
                    time.sleep(3)
            finally:
                if self.clientsocket:
                    try:
                        self.clientsocket.close()
                    except:
                        pass
                
                if self.running and not shutting_down:
                    time.sleep(2)
    
    def parse_my_message(self, serialized_data):
        MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
        MajorLogRes.ParseFromString(serialized_data)
        
        timestamp = MajorLogRes.kts
        key = MajorLogRes.ak
        iv = MajorLogRes.aiv
        BASE64_TOKEN = MajorLogRes.token
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv, BASE64_TOKEN
    
    def GET_PAYLOAD_BY_DATA(self,JWT_TOKEN , NEW_ACCESS_TOKEN,date):
        token_payload_base64 = JWT_TOKEN.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
        decoded_payload = json.loads(decoded_payload)
        NEW_EXTERNAL_ID = decoded_payload['external_id']
        SIGNATURE_MD5 = decoded_payload['signature_md5']
        now = datetime.now()
        now =str(now)[:len(str(now))-7]
        formatted_time = date
        payload = bytes.fromhex("1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131382e31422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033")
        payload = payload.replace(b"2025-07-30 11:02:51", str(now).encode())
        payload = payload.replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", NEW_ACCESS_TOKEN.encode("UTF-8"))
        payload = payload.replace(b"996a629dbcdb3964be6b6978f5d814db", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
        PAYLOAD = payload.hex()
        PAYLOAD = encrypt_api(PAYLOAD)
        PAYLOAD = bytes.fromhex(PAYLOAD)
        whisper_ip, whisper_port, online_ip, online_port = self.GET_LOGIN_DATA(JWT_TOKEN , PAYLOAD)
        return whisper_ip, whisper_port, online_ip, online_port
    
    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = self.region_url
        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': FreeFireVersion,
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': self.region_host,
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        
        max_retries = 3
        attempt = 0
        while attempt < max_retries and not shutting_down:
            try:
                response = requests.post(url, headers=headers, data=PAYLOAD, verify=False)
                response.raise_for_status()
                x = response.content.hex()
                json_result = get_available_room(x)
                parsed_data = json.loads(json_result)
                whisper_address = parsed_data['32']['data']
                online_address = parsed_data['14']['data']
                online_ip = online_address[:len(online_address) - 6]
                whisper_ip = whisper_address[:len(whisper_address) - 6]
                online_port = int(online_address[len(online_address) - 5:])
                whisper_port = int(whisper_address[len(whisper_address) - 5:])
                return whisper_ip, whisper_port, online_ip, online_port
            except requests.RequestException as e:
                print(f"[{self.account_id}] Request failed: {e}. Attempt {attempt + 1} of {max_retries}. Retrying...")
                attempt += 1
                time.sleep(2)
        print(f"[{self.account_id}] Failed to get login data after multiple attempts.")
        return None, None, None, None
    
    def guest_token(self,uid , password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"Host": "100067.connect.garena.com","User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 10;en;EN;)","Content-Type": "application/x-www-form-urlencoded","Accept-Encoding": "gzip, deflate, br","Connection": "close",}
        data = {"uid": f"{uid}","password": f"{password}","response_type": "token","client_type": "2","client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3","client_id": "100067",}
        response = requests.post(url, headers=headers, data=data)
        data = response.json()
        NEW_ACCESS_TOKEN = data['access_token']
        NEW_OPEN_ID = data['open_id']
        OLD_ACCESS_TOKEN = "ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a"
        OLD_OPEN_ID = "996a629dbcdb3964be6b6978f5d814db"
        time.sleep(0.2)
        data = self.TOKEN_MAKER(OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,uid)
        return data
        
    def TOKEN_MAKER(self,OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,id):
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB52',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        data = bytes.fromhex('1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131382e31422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033')
        data = data.replace(OLD_OPEN_ID.encode(),NEW_OPEN_ID.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode() , NEW_ACCESS_TOKEN.encode())
        hex = data.hex()
        d = encrypt_api(data.hex())
        Final_Payload = bytes.fromhex(d)
        URL = "https://loginbp.ggblueshark.com/MajorLogin"

        RESPONSE = requests.post(URL, headers=headers, data=Final_Payload,verify=False)
        
        combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
        if RESPONSE.status_code == 200:
            if len(RESPONSE.text) < 10:
                return False
            whisper_ip, whisper_port, online_ip, online_port =self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN,NEW_ACCESS_TOKEN,1)
            self.key = key
            self.iv = iv
            #logging.info(key, iv)
            return(BASE64_TOKEN, key, iv, combined_timestamp, whisper_ip, whisper_port, online_ip, online_port)
        else:
            return False
    
    def get_tok(self):
        global g_token
        token_data = self.guest_token(self.account_id, self.password)
        if not token_data:
            logging.critical("Failed to get token data from guest_token. Restarting.")
            self.restart()
            return

        token, key, iv, Timestamp, whisper_ip, whisper_port, online_ip, online_port = token_data
        g_token = token
        #logging.info(f"{whisper_ip}, {whisper_port}")
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            account_id = decoded.get('account_id')
            encoded_acc = hex(account_id)[2:]
            hex_value = self.dec_to_hex(Timestamp)
            time_hex = hex_value
            BASE64_TOKEN_ = token.encode().hex()
            logging.info(f"Token decoded and processed. Account ID: {account_id}")
        except Exception as e:
            logging.error(f"Error processing token: {e}. Restarting.")
            self.restart()
            return

        try:
            head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
            length = len(encoded_acc)
            zeros = '00000000'

            if length == 9:
                zeros = '0000000'
            elif length == 8:
                zeros = '00000000'
            elif length == 10:
                zeros = '000000'
            elif length == 7:
                zeros = '000000000'
            else:
                logging.warning('Unexpected length encountered')
            head = f'0115{zeros}{encoded_acc}{time_hex}00000{head}'
            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
            logging.info("Final token constructed successfully.")
        except Exception as e:
            logging.error(f"Error constructing final token: {e}. Restarting.")
            self.restart()
            return
        token = final_token
        self.connect(token, 'anything', key, iv, whisper_ip, whisper_port, online_ip, online_port)
        
      
        return token, key, iv
    
    def dec_to_hex(self, ask):
        ask_result = hex(ask)
        final_result = str(ask_result)[2:]
        if len(final_result) == 1:
            final_result = "0" + final_result
            return final_result
        else:
            return final_result


def load_accounts(file_path):
    """Load accounts from JSON file. Supports both old and new format."""
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
    
    # Check if new format (with "accounts" key)
    if 'accounts' in data:
        accounts = {}
        for account_id, account_data in data['accounts'].items():
            if isinstance(account_data, dict) and account_data.get('enabled', True):
                accounts[account_id] = account_data.get('password', '')
        return accounts
    else:
        # Old format: direct account_id -> password mapping
        return data

def get_account_metadata(file_path, account_id):
    """Get metadata (name, team_code, uid) for a specific account."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
        
        if 'accounts' in data and account_id in data['accounts']:
            account_data = data['accounts'][account_id]
            return {
                'name': account_data.get('name', account_id),
                'team_code': account_data.get('team_code', ''),
                'uid': account_data.get('uid', ''),
                'enabled': account_data.get('enabled', True)
            }
        return {'name': account_id, 'team_code': '', 'uid': '', 'enabled': True}
    except:
        return {'name': account_id, 'team_code': '', 'uid': '', 'enabled': True}

def get_all_accounts_metadata(file_path):
    """Get all accounts with their metadata."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
        
        if 'accounts' in data:
            return data['accounts']
        else:
            # Old format - convert to new format
            accounts = {}
            for account_id, password in data.items():
                accounts[account_id] = {
                    'password': password,
                    'name': account_id,
                    'team_code': '',
                    'uid': '',
                    'enabled': True
                }
            return accounts
    except:
        return {}

def save_accounts_metadata(file_path, accounts_data):
    """Save accounts metadata to JSON file."""
    data = {'accounts': accounts_data}
    with open(file_path, 'w', encoding='utf-8') as file:
        json.dump(data, file, indent=2, ensure_ascii=False)

def cleanup():
    global shutting_down
    shutting_down = True
    print("Shutting down all clients...")
    for region_code, region_clients in clients.items():
        for account_id, client in list(region_clients.items()):
            client.stop()
            del region_clients[account_id]
    print("Cleanup completed")

# Helper function to execute join team logic (without Flask response)
def execute_join_team(clients_dict, team_tracking_dict, region_name):
    """Execute join team logic without Flask response - for loop usage"""
    if shutting_down:
        return False

    # Get account file path for this region
    account_file = REGION_CONFIG.get(region_name, {}).get('json_file', 'bd.json')
    
    # Get all connected clients with their metadata
    connected_clients = {}
    account_team_codes = {}  # account_id -> team_code mapping
    
    for account_id, client in clients_dict.items():
        if client.socket_client and client.is_socket_connected(client.socket_client):
            connected_clients[account_id] = client
            # Get account-specific team code
            metadata = get_account_metadata(account_file, account_id)
            team_code = metadata.get('team_code', '')
            if team_code:
                account_team_codes[account_id] = team_code
    
    if not connected_clients:
        print(f"[{region_name}] No connected clients available")
        return False
    
    # If no accounts have team codes, return False
    if not account_team_codes:
        print(f"[{region_name}] No team codes configured for accounts")
        return False
    
    # Select an account (prefer accounts with team codes)
    current_time = time.time()
    selected_account_id = None
    selected_team_code = None
    
    # Try to find an account with a team code
    if account_team_codes:
        # Check cache first
        for account_id, team_code in account_team_codes.items():
            cache_key = f"{account_id}_{team_code}"
            if cache_key in team_tracking_dict:
                cached_account_id, last_fetch_time = team_tracking_dict[cache_key]
                if (current_time - last_fetch_time) < 300 and cached_account_id in connected_clients:
                    selected_account_id = cached_account_id
                    selected_team_code = account_team_codes.get(cached_account_id, team_code)
                    print(f"[{region_name}] Using cached account {selected_account_id} for team_code {selected_team_code}")
                    break
        
        # If no cache hit, select random account with team code
        if selected_account_id is None:
            selected_account_id = random.choice(list(account_team_codes.keys()))
            selected_team_code = account_team_codes[selected_account_id]
            print(f"[{region_name}] Selected account {selected_account_id} for team_code {selected_team_code}")
    else:
        # Fallback: select any connected client
        selected_account_id = random.choice(list(connected_clients.keys()))
        selected_team_code = list(account_team_codes.values())[0] if account_team_codes else None
    
    if not selected_team_code:
        print(f"[{region_name}] No team code available for selected account")
        return False
    
    # Update team tracking
    cache_key = f"{selected_account_id}_{selected_team_code}"
    with team_tracking_lock:
        team_tracking_dict[cache_key] = (selected_account_id, current_time)
    
    selected_client = connected_clients[selected_account_id]

    try:
        print(f"[{selected_account_id}] Joining team with team code: {selected_team_code}")
        EM = GenJoinSquadsPacket(int(selected_team_code), selected_client.key, selected_client.iv)
        selected_client.socket_client.send(EM)
        time.sleep(1)  # Small delay after join
        EK = FS(selected_client.key, selected_client.iv)
        selected_client.socket_client.send(EK)
        PM = LagSquad(selected_client.key, selected_client.iv)
        selected_client.socket_client.send(PM)
        time.sleep(14)
        leave = ExiT('000000', selected_client.key, selected_client.iv)
        selected_client.socket_client.send(leave)
        print(f"[{selected_account_id}] Successfully completed team join cycle for team_code {selected_team_code}")
        return True
        
    except Exception as e:
        print(f"[{selected_account_id}] Error joining team: {str(e)}")
        return False


# Continuous loop function for BD region
def bd_auto_join_loop():
    """Continuous loop to auto-join teams for BD region"""
    global bd_loop_running
    print("[BD] Auto-join loop started!")
    time.sleep(3)  # Wait for clients to connect initially
    
    while not shutting_down and bd_loop_running:
        try:
            # Initialize if not exists
            if 'BD' not in clients:
                clients['BD'] = {}
            if 'BD' not in team_tracking:
                team_tracking['BD'] = {}
            
            # Check if loop should still run
            if not bd_loop_running:
                break
            
            # Execute join team
            execute_join_team(clients['BD'], team_tracking['BD'], 'BD')
            
            # Check again before waiting
            if not bd_loop_running:
                break
            
            # Wait before next cycle (adjust delay as needed)
            time.sleep(18)  # Wait 18 seconds before next join cycle
            
        except Exception as e:
            print(f"[BD] Error in auto-join loop: {str(e)}")
            if bd_loop_running:
                time.sleep(5)  # Wait a bit before retrying on error
    
    print("[BD] Auto-join loop stopped!")
    with bd_loop_lock:
        bd_loop_running = False

# Account-specific loop function
def account_auto_join_loop(account_id):
    """Continuous loop to auto-join teams for a specific account"""
    print(f"[{account_id}] Account auto-join loop started!")
    time.sleep(3)  # Wait for client to connect initially
    
    while not shutting_down:
        try:
            # Check if this account's loop should still run
            with account_loops_lock:
                if account_id not in account_loops or not account_loops[account_id].get('running', False):
                    break
            
            # Check if account client exists and is running
            if 'BD' not in clients or account_id not in clients['BD']:
                print(f"[{account_id}] Account client not found, stopping loop")
                break
            
            client = clients['BD'][account_id]
            if not client.running or not (client.socket_client and client.is_socket_connected(client.socket_client)):
                print(f"[{account_id}] Account client not connected, waiting...")
                time.sleep(5)
                continue
            
            # Get account-specific team code
            account_file = 'bd.json'
            metadata = get_account_metadata(account_file, account_id)
            team_code = metadata.get('team_code', '')
            
            if not team_code:
                print(f"[{account_id}] No team code configured, stopping loop")
                break
            
            # Initialize team tracking if needed
            if 'BD' not in team_tracking:
                team_tracking['BD'] = {}
            
            # Create a single-account clients dict for this account
            single_account_clients = {account_id: client}
            
            # Execute join team for this specific account
            try:
                # Use account-specific team code
                print(f"[{account_id}] Joining team with team code: {team_code}")
                EM = GenJoinSquadsPacket(int(team_code), client.key, client.iv)
                client.socket_client.send(EM)
                time.sleep(1)
                EK = FS(client.key, client.iv)
                client.socket_client.send(EK)
                PM = LagSquad(client.key, client.iv)
                client.socket_client.send(PM)
                time.sleep(14)
                leave = ExiT('000000', client.key, client.iv)
                client.socket_client.send(leave)
                print(f"[{account_id}] Successfully completed team join cycle for team_code {team_code}")
            except Exception as e:
                print(f"[{account_id}] Error joining team: {str(e)}")
            
            # Check again before waiting
            with account_loops_lock:
                if account_id not in account_loops or not account_loops[account_id].get('running', False):
                    break
            
            # Wait before next cycle
            time.sleep(18)  # Wait 18 seconds before next join cycle
            
        except Exception as e:
            print(f"[{account_id}] Error in account auto-join loop: {str(e)}")
            with account_loops_lock:
                if account_id in account_loops and account_loops[account_id].get('running', False):
                    time.sleep(5)  # Wait a bit before retrying on error
                else:
                    break
    
    print(f"[{account_id}] Account auto-join loop stopped!")
    with account_loops_lock:
        if account_id in account_loops:
            account_loops[account_id]['running'] = False

# Endpoint to update team code in teamcode.json
@app.route('/set', methods=['GET'])
def set_team_code():
    team_code = request.args.get('tc')
    if not team_code:
        return jsonify({'error': 'Team code parameter (tc) is required'}), 400
    
    try:
        # Read current teamcode.json
        teamcode_file = 'teamcode.json'
        if os.path.exists(teamcode_file):
            with open(teamcode_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
        else:
            data = {}
        
        # Update team code
        data['team_code'] = team_code
        
        # Write back to file
        with open(teamcode_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        
        return jsonify({
            'success': True,
            'message': f'Team code updated successfully to: {team_code}',
            'team_code': team_code
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error updating team code: {str(e)}'
        }), 500


# ==================== USER MANAGEMENT ROUTES (ADMIN ONLY) ====================

@app.route('/api/users', methods=['GET'])
@login_required
@admin_required
@secure_api
def get_users():
    """Get all users (admin only)"""
    try:
        users = load_users()
        safe_users = {}
        
        for username, user_data in users.items():
            safe_users[username] = {
                'username': username,
                'role': user_data.get('role', 'user'),
                'assigned_account': user_data.get('assigned_account'),
                'valid_until': user_data.get('valid_until'),
                'created_at': user_data.get('created_at'),
                'is_valid': True if not user_data.get('valid_until') else datetime.now() < datetime.fromisoformat(user_data.get('valid_until'))
            }
        
        return jsonify({
            'success': True,
            'users': safe_users
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error loading users: {str(e)}'
        }), 500

@app.route('/api/users', methods=['POST'])
@login_required
@admin_required
@secure_api
def create_user():
    """Create a new user (admin only)"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        role = data.get('role', 'user').strip()
        assigned_account = data.get('assigned_account', '').strip()
        valid_days = data.get('valid_days')  # Number of days user is valid
        
        if not username or not password:
            return jsonify({
                'success': False,
                'error': 'Username and password are required'
            }), 400
        
        if len(username) < 3:
            return jsonify({
                'success': False,
                'error': 'Username must be at least 3 characters'
            }), 400
        
        if len(password) < 6:
            return jsonify({
                'success': False,
                'error': 'Password must be at least 6 characters'
            }), 400
        
        if role not in ['admin', 'user']:
            return jsonify({
                'success': False,
                'error': 'Role must be either "admin" or "user"'
            }), 400
        
        users = load_users()
        
        if username in users:
            return jsonify({
                'success': False,
                'error': 'Username already exists'
            }), 400
        
        # Check if assigned account exists (if provided)
        if assigned_account:
            account_file = 'bd.json'
            accounts = get_all_accounts_metadata(account_file)
            if assigned_account not in accounts:
                return jsonify({
                    'success': False,
                    'error': f'Account {assigned_account} does not exist'
                }), 400
            
            # Check if account is already assigned to another user
            for uname, udata in users.items():
                if udata.get('assigned_account') == assigned_account:
                    return jsonify({
                        'success': False,
                        'error': f'Account {assigned_account} is already assigned to user {uname}'
                    }), 400
        
        # Calculate expiration date
        valid_until = None
        if valid_days and int(valid_days) > 0:
            valid_until = (datetime.now() + timedelta(days=int(valid_days))).isoformat()
        
        # Create new user
        users[username] = {
            'password_hash': generate_password_hash(password),
            'role': role,
            'assigned_account': assigned_account if assigned_account else None,
            'valid_until': valid_until,
            'created_at': datetime.now().isoformat(),
            'created_by': current_user.username
        }
        
        save_users(users)
        
        return jsonify({
            'success': True,
            'message': f'User {username} created successfully',
            'user': {
                'username': username,
                'role': role,
                'assigned_account': assigned_account,
                'valid_until': valid_until
            }
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error creating user: {str(e)}'
        }), 500

@app.route('/api/users/<username>', methods=['PUT'])
@login_required
@admin_required
@secure_api
def update_user(username):
    """Update user (admin only)"""
    try:
        data = request.get_json()
        users = load_users()
        
        if username not in users:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        # Don't allow updating yourself
        if username == current_user.username:
            return jsonify({
                'success': False,
                'error': 'Cannot update your own account from this endpoint'
            }), 400
        
        # Update fields if provided
        if 'password' in data and data['password'].strip():
            if len(data['password']) < 6:
                return jsonify({
                    'success': False,
                    'error': 'Password must be at least 6 characters'
                }), 400
            users[username]['password_hash'] = generate_password_hash(data['password'].strip())
        
        if 'role' in data and data['role'] in ['admin', 'user']:
            users[username]['role'] = data['role']
        
        if 'assigned_account' in data:
            new_account = data['assigned_account'].strip()
            if new_account:
                # Check if account exists
                account_file = 'bd.json'
                accounts = get_all_accounts_metadata(account_file)
                if new_account not in accounts:
                    return jsonify({
                        'success': False,
                        'error': f'Account {new_account} does not exist'
                    }), 400
                
                # Check if account is already assigned to another user
                for uname, udata in users.items():
                    if uname != username and udata.get('assigned_account') == new_account:
                        return jsonify({
                            'success': False,
                            'error': f'Account {new_account} is already assigned to user {uname}'
                        }), 400
                
                users[username]['assigned_account'] = new_account
            else:
                users[username]['assigned_account'] = None
        
        if 'valid_days' in data:
            valid_days = data['valid_days']
            if valid_days and int(valid_days) > 0:
                users[username]['valid_until'] = (datetime.now() + timedelta(days=int(valid_days))).isoformat()
            else:
                users[username]['valid_until'] = None
        
        users[username]['updated_at'] = datetime.now().isoformat()
        users[username]['updated_by'] = current_user.username
        
        save_users(users)
        
        return jsonify({
            'success': True,
            'message': f'User {username} updated successfully'
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error updating user: {str(e)}'
        }), 500

@app.route('/api/users/<username>', methods=['DELETE'])
@login_required
@admin_required
@secure_api
def delete_user(username):
    """Delete user (admin only)"""
    try:
        users = load_users()
        
        if username not in users:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        # Don't allow deleting yourself
        if username == current_user.username:
            return jsonify({
                'success': False,
                'error': 'Cannot delete your own account'
            }), 400
        
        del users[username]
        save_users(users)
        
        return jsonify({
            'success': True,
            'message': f'User {username} deleted successfully'
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error deleting user: {str(e)}'
        }), 500

@app.route('/api/available-accounts', methods=['GET'])
@login_required
@admin_required
@secure_api
def get_available_accounts():
    """Get all accounts and their assignment status (admin only)"""
    try:
        account_file = 'bd.json'
        accounts = get_all_accounts_metadata(account_file)
        users = load_users()
        
        # Build assignment map
        account_assignments = {}
        for username, user_data in users.items():
            assigned_acc = user_data.get('assigned_account')
            if assigned_acc:
                account_assignments[assigned_acc] = username
        
        # Build response
        available = []
        for account_id, account_data in accounts.items():
            available.append({
                'account_id': account_id,
                'name': account_data.get('name', account_id),
                'assigned_to': account_assignments.get(account_id, None),
                'running': is_account_running(account_id, 'BD')
            })
        
        return jsonify({
            'success': True,
            'accounts': available
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error loading accounts: {str(e)}'
        }), 500

# ==================== ACCOUNT MANAGEMENT ROUTES ====================

def is_account_running(account_id, region='BD'):
    """Check if an account is currently running."""
    if region not in clients:
        return False
    if account_id not in clients[region]:
        return False
    client = clients[region][account_id]
    # Check if client is running and socket is connected
    if hasattr(client, 'running') and client.running:
        if client.socket_client and client.is_socket_connected(client.socket_client):
            return True
    return False

@app.route('/api/accounts', methods=['GET'])
@login_required
@secure_api
def get_accounts():
    """Get BD accounts - admins see all, users see only their assigned account."""
    try:
        # Check user validity
        validity_check = check_user_validity()
        if validity_check:
            return validity_check
        
        account_file = 'bd.json'
        accounts = get_all_accounts_metadata(account_file)
        
        # Filter accounts based on user role
        if not current_user.is_admin():
            # Regular user - only show assigned account
            assigned_account = current_user.assigned_account
            if not assigned_account or assigned_account not in accounts:
                return jsonify({
                    'success': False,
                    'error': 'No account assigned to you. Please contact admin.'
                }), 403
            
            accounts = {assigned_account: accounts[assigned_account]}
        
        # Remove password from response for security
        safe_accounts = {}
        for account_id, account_data in accounts.items():
            # Check if account is running
            running = is_account_running(account_id, 'BD')
            # Check if account loop is running (only if account is actually running)
            with account_loops_lock:
                loop_flag_running = account_id in account_loops and account_loops[account_id].get('running', False)
                # Loop is only considered running if both the flag is set AND the account is actually running
                loop_running = loop_flag_running and running
            
            autostart_enabled = is_loop_autostart_enabled(account_id)
            
            safe_accounts[account_id] = {
                'name': account_data.get('name', account_id),
                'team_code': account_data.get('team_code', ''),
                'uid': account_data.get('uid', ''),
                'enabled': account_data.get('enabled', True),
                'running': running,
                'loop_running': loop_running,
                'autostart_enabled': autostart_enabled
            }
        
        return jsonify({
            'success': True,
            'accounts': safe_accounts,
            'user_role': current_user.role
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error loading accounts: {str(e)}'
        }), 500

@app.route('/api/accounts', methods=['POST'])
@login_required
@admin_required
@secure_api
def add_account():
    """Add a new account (admin only)."""
    try:
        data = request.get_json()
        account_id = data.get('account_id', '').strip()
        password = data.get('password', '').strip()
        name = data.get('name', account_id).strip()
        team_code = data.get('team_code', '').strip()
        
        if not account_id or not password:
            return jsonify({
                'success': False,
                'error': 'Account ID and password are required'
            }), 400
        
        account_file = 'bd.json'
        accounts = get_all_accounts_metadata(account_file)
        
        if account_id in accounts:
            return jsonify({
                'success': False,
                'error': 'Account already exists'
            }), 400
        
        accounts[account_id] = {
            'password': password,
            'name': name,
            'team_code': team_code,
            'uid': '',
            'enabled': True
        }
        
        save_accounts_metadata(account_file, accounts)
        
        return jsonify({
            'success': True,
            'message': f'Account {account_id} added successfully'
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error adding account: {str(e)}'
        }), 500

@app.route('/api/accounts/<account_id>', methods=['PUT'])
@login_required
@admin_required
@secure_api
def update_account(account_id):
    """Update an existing account (admin only)."""
    try:
        data = request.get_json()
        account_file = 'bd.json'
        accounts = get_all_accounts_metadata(account_file)
        
        if account_id not in accounts:
            return jsonify({
                'success': False,
                'error': 'Account not found'
            }), 404
        
        # Update fields if provided
        if 'name' in data:
            accounts[account_id]['name'] = data['name'].strip()
        if 'team_code' in data:
            accounts[account_id]['team_code'] = data['team_code'].strip()
        if 'uid' in data:
            accounts[account_id]['uid'] = data['uid'].strip()
        if 'enabled' in data:
            accounts[account_id]['enabled'] = bool(data['enabled'])
        if 'password' in data and data['password'].strip():
            accounts[account_id]['password'] = data['password'].strip()
        
        save_accounts_metadata(account_file, accounts)
        
        return jsonify({
            'success': True,
            'message': f'Account {account_id} updated successfully'
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error updating account: {str(e)}'
        }), 500

@app.route('/api/accounts/<account_id>/stop', methods=['POST'])
@login_required
@secure_api
def stop_account(account_id):
    """Stop a specific account's client connection."""
    try:
        # Check user validity
        validity_check = check_user_validity()
        if validity_check:
            return validity_check
        
        # Check permissions - users can only stop their assigned account
        if not current_user.is_admin():
            if current_user.assigned_account != account_id:
                return jsonify({
                    'success': False,
                    'error': 'You can only control your assigned account'
                }), 403
        

        # Stop client if running in any region
        stopped = False
        for region_code, region_clients in clients.items():
            if account_id in region_clients:
                region_clients[account_id].stop()
                # Keep client in dict but mark as stopped
                stopped = True
                print(f"[{region_code}] Stopped account {account_id}")
        
        # Also stop the account's loop if it's running
        with account_loops_lock:
            if account_id in account_loops and account_loops[account_id].get('running', False):
                account_loops[account_id]['running'] = False
                print(f"[{account_id}] Stopped account loop")
        
        if stopped:
            return jsonify({
                'success': True,
                'message': f'Account {account_id} stopped successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': f'Account {account_id} not found or not running'
            }), 404
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error stopping account: {str(e)}'
        }), 500

@app.route('/api/accounts/<account_id>/start', methods=['POST'])
@login_required
@secure_api
def start_account(account_id):
    """Start/restart a specific account's client connection."""
    try:
        # Check user validity
        validity_check = check_user_validity()
        if validity_check:
            return validity_check
        
        # Check permissions - users can only start their assigned account
        if not current_user.is_admin():
            if current_user.assigned_account != account_id:
                return jsonify({
                    'success': False,
                    'error': 'You can only control your assigned account'
                }), 403
        

        account_file = 'bd.json'
        accounts = get_all_accounts_metadata(account_file)
        
        if account_id not in accounts:
            return jsonify({
                'success': False,
                'error': 'Account not found'
            }), 404
        
        account_data = accounts[account_id]
        password = account_data.get('password', '')
        region = 'BD'  # Default to BD region
        
        if not password:
            return jsonify({
                'success': False,
                'error': 'Account password not found'
            }), 400
        
        # Initialize region clients dict if not exists
        if region not in clients:
            clients[region] = {}
        
        # Stop existing client if any
        if account_id in clients[region]:
            try:
                clients[region][account_id].stop()
            except:
                pass
        
        # Create and start new client
        client = TcpBotConnectMain(account_id, password, region=region)
        clients[region][account_id] = client
        client_thread = threading.Thread(target=client.run)
        client_thread.daemon = True
        client_thread.start()
        
        print(f"[{region}] Started account {account_id}")
        
        # Automatically Start Level UP if account has team code AND auto-start is enabled
        team_code = account_data.get('team_code', '')
        if team_code and is_loop_autostart_enabled(account_id):
            # Wait a bit for client to start connecting, then Start Level UP
            def start_loop_after_delay():
                time.sleep(5)  # Wait 5 seconds for client to connect
                # Check if account is running and loop is not already running
                with account_loops_lock:
                    if account_id not in account_loops or not account_loops[account_id].get('running', False):
                        if is_account_running(account_id, region):
                            account_loops[account_id] = {
                                'running': True,
                                'thread': None
                            }
                            loop_thread = threading.Thread(target=account_auto_join_loop, args=(account_id,), daemon=True)
                            account_loops[account_id]['thread'] = loop_thread
                            loop_thread.start()
                            print(f"[{account_id}] Auto-started loop after account start (auto-start enabled)")
            
            loop_start_thread = threading.Thread(target=start_loop_after_delay, daemon=True)
            loop_start_thread.start()
        
        return jsonify({
            'success': True,
            'message': f'Account {account_id} started successfully' + (f' and loop will start automatically' if team_code else '')
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error starting account: {str(e)}'
        }), 500

@app.route('/api/accounts/<account_id>/loop/start', methods=['POST'])
@login_required
@secure_api
def start_account_loop(account_id):
    """Start auto-join loop for a specific account."""
    try:
        # Check user validity
        validity_check = check_user_validity()
        if validity_check:
            return validity_check
        
        # Check permissions - users can only control their assigned account
        if not current_user.is_admin():
            if current_user.assigned_account != account_id:
                return jsonify({
                    'success': False,
                    'error': 'You can only control your assigned account'
                }), 403
        

        account_file = 'bd.json'
        accounts = get_all_accounts_metadata(account_file)
        
        if account_id not in accounts:
            return jsonify({
                'success': False,
                'error': 'Account not found'
            }), 404
        
        # Check if account is running
        if not is_account_running(account_id, 'BD'):
            return jsonify({
                'success': False,
                'error': f'Account {account_id} must be running before starting loop'
            }), 400
        
        # Check if account has team code
        account_data = accounts[account_id]
        team_code = account_data.get('team_code', '')
        if not team_code:
            return jsonify({
                'success': False,
                'error': 'Account must have a team code configured'
            }), 400
        
        with account_loops_lock:
            # Check if loop already running
            if account_id in account_loops and account_loops[account_id].get('running', False):
                # Check if account is actually running, if not, stop the loop flag
                if not is_account_running(account_id, 'BD'):
                    account_loops[account_id]['running'] = False
                else:
                    return jsonify({
                        'success': False,
                        'error': f'Loop for account {account_id} is already running'
                    }), 400
            
            # Initialize loop tracking
            account_loops[account_id] = {
                'running': True,
                'thread': None
            }
            
            # Start Level UP thread
            loop_thread = threading.Thread(target=account_auto_join_loop, args=(account_id,), daemon=True)
            account_loops[account_id]['thread'] = loop_thread
            loop_thread.start()
        
        # Enable auto-start when manually starting loop
        set_loop_autostart(account_id, True)
        
        print(f"[{account_id}] Account loop started (auto-start enabled)")
        
        return jsonify({
            'success': True,
            'message': f'Loop started for account {account_id} (auto-start enabled)'
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error starting account loop: {str(e)}'
        }), 500

@app.route('/api/accounts/<account_id>/loop/stop', methods=['POST'])
@login_required
@secure_api
def stop_account_loop(account_id):
    """Stop auto-join loop for a specific account."""
    try:
        # Check user validity
        validity_check = check_user_validity()
        if validity_check:
            return validity_check
        
        # Check permissions - users can only control their assigned account
        if not current_user.is_admin():
            if current_user.assigned_account != account_id:
                return jsonify({
                    'success': False,
                    'error': 'You can only control your assigned account'
                }), 403
        

        with account_loops_lock:
            if account_id not in account_loops or not account_loops[account_id].get('running', False):
                return jsonify({
                    'success': False,
                    'error': f'Loop for account {account_id} is not running'
                }), 400
            
            # Stop the loop
            account_loops[account_id]['running'] = False
        
        print(f"[{account_id}] Account loop stop requested")
        
        return jsonify({
            'success': True,
            'message': f'Loop stop requested for account {account_id}'
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error stopping account loop: {str(e)}'
        }), 500

@app.route('/api/accounts/<account_id>/loop/status', methods=['GET'])
@login_required
def get_account_loop_status(account_id):
    """Get loop status for a specific account."""
    try:
        with account_loops_lock:
            running = account_id in account_loops and account_loops[account_id].get('running', False)
        
        autostart_enabled = is_loop_autostart_enabled(account_id)
        
        return jsonify({
            'success': True,
            'running': running,
            'autostart_enabled': autostart_enabled,
            'message': f'Loop for account {account_id} is {"running" if running else "stopped"}'
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error getting account loop status: {str(e)}'
        }), 500

@app.route('/api/accounts/<account_id>/loop/autostart', methods=['POST'])
@login_required
@secure_api
def set_account_loop_autostart(account_id):
    """Enable or disable auto-start for an account's loop."""
    try:
        # Check user validity
        validity_check = check_user_validity()
        if validity_check:
            return validity_check
        
        # Check permissions - users can only control their assigned account
        if not current_user.is_admin():
            if current_user.assigned_account != account_id:
                return jsonify({
                    'success': False,
                    'error': 'You can only control your assigned account'
                }), 403
        
        data = request.get_json()
        enabled = data.get('enabled', True)
        
        set_loop_autostart(account_id, enabled)
        
        return jsonify({
            'success': True,
            'message': f'Auto-start {"enabled" if enabled else "disabled"} for account {account_id}'
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error setting auto-start: {str(e)}'
        }), 500

@app.route('/api/accounts/<account_id>/teamcode', methods=['POST'])
@login_required
@secure_api
def update_account_teamcode(account_id):
    """Update team code for a specific account."""
    try:
        # Check user validity
        validity_check = check_user_validity()
        if validity_check:
            return validity_check
        
        # Check permissions - users can only update their assigned account
        if not current_user.is_admin():
            if current_user.assigned_account != account_id:
                return jsonify({
                    'success': False,
                    'error': 'You can only control your assigned account'
                }), 403
        

        data = request.get_json()
        team_code = data.get('team_code', '').strip()
        uid = data.get('uid', '').strip()
        
        if not team_code:
            return jsonify({
                'success': False,
                'error': 'Team code is required'
            }), 400
        
        # UID is optional for admin, required for regular users
        if not current_user.is_admin() and not uid:
            return jsonify({
                'success': False,
                'error': 'UID is required'
            }), 400
        
        account_file = 'bd.json'
        accounts = get_all_accounts_metadata(account_file)
        
        if account_id not in accounts:
            return jsonify({
                'success': False,
                'error': 'Account not found'
            }), 404
        
        # Update team code and UID (UID can be empty for admin)
        accounts[account_id]['team_code'] = team_code
        if uid:
            accounts[account_id]['uid'] = uid
        save_accounts_metadata(account_file, accounts)
        
        return jsonify({
            'success': True,
            'message': f'Team code and UID updated for account {account_id}',
            'team_code': team_code,
            'uid': uid
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error updating team code: {str(e)}'
        }), 500

# Level-XP mapping table (same as lvlup website)
LEVEL_XP_TABLE = {
    1: (0, 48),
    2: (48, 154),
    3: (202, 342),
    4: (544, 468),
    5: (1012, 832),
    6: (1844, 948),
    7: (2792, 1008),
    8: (3800, 1070),
    9: (4870, 1134),
    10: (6004, 1188),
    11: (7192, 1256),
    12: (8448, 1312),
    13: (9760, 1380),
    14: (11140, 1426),
    15: (12566, 1494),
    16: (14060, 1550),
    17: (15610, 1614),
    18: (17224, 1678),
    19: (18902, 1730),
    20: (20632, 1792),
    21: (22424, 1854),
    22: (24278, 1914),
    23: (26192, 1974),
    24: (28166, 2034),
    25: (30200, 2094),
    26: (32294, 2154),
    27: (34448, 3356),
    28: (37804, 3470),
    29: (41274, 3596),
    30: (44870, 3712),
    31: (48582, 4812),
    32: (53394, 5172),
    33: (58566, 5530),
    34: (64096, 5888),
    35: (69994, 6466),
    36: (76460, 7046),
    37: (83506, 7622),
    38: (91128, 8194),
    39: (99322, 8770),
    40: (108092, 12052),
    41: (120144, 13122),
    42: (133266, 14206),
    43: (147472, 15288),
    44: (162760, 16366),
    45: (179126, 17446),
    46: (195672, 18796),
    47: (215368, 20148),
    48: (235516, 21494),
    49: (257010, 22850),
    50: (279860, 24196),
    51: (304056, 44262),
    52: (348318, 46664),
    53: (394982, 49062),
    54: (444044, 51464),
    55: (495508, 53856),
    56: (549364, 84392),
    57: (633756, 87988),
    58: (721744, 91592),
    59: (813336, 95186),
    60: (908522, 132916),
    61: (1044138, 138914),
    62: (1180352, 144914),
    63: (1325266, 150918),
    64: (1476184, 158616),
    65: (1633400, 206646),
    66: (1840946, 215648),
    67: (2056594, 226448),
    68: (2281242, 233638),
    69: (2514880, 242650),
    70: (2757530, 301976),
    71: (3055906, 312778),
    72: (3372284, 327172),
    73: (3699456, 341574),
    74: (4041030, 359972),
    75: (4397002, 432102),
    76: (4829104, 453100),
    77: (5282204, 474100),
    78: (5756304, 495100),
    79: (6251404, 516098),
    80: (6767502, 613822),
    81: (7381324, 661830),
    82: (8043154, 709828),
    83: (8752982, 757826),
    84: (9518088, 805830),
    85: (10316638, 960552),
    86: (11277190, 1014558),
    87: (12297448, 1068556),
    88: (13360304, 1122554),
    89: (14482858, 1176560),
    90: (15659418, 1367220),
    91: (17026708, 1427242),
    92: (18453950, 1487330),
    93: (19941280, 1547290),
    94: (21488570, 1607288),
    95: (23095858, 1667280),
    96: (24763138, 1727290),
    97: (26490428, 1787280),
    98: (28277708, 1847282),
    99: (30124996, 1907288),
    100: (32032284, 0),  # Max level
}

def get_level_from_exp(total_exp):
    """Calculate level from total EXP using the level table"""
    if total_exp < 0:
        return 1, 0, 48, 48, 0.0
    
    # Find the level based on total EXP
    for level in sorted(LEVEL_XP_TABLE.keys(), reverse=True):
        level_start_exp, exp_needed_for_next = LEVEL_XP_TABLE[level]
        if total_exp >= level_start_exp:
            # Calculate current level progress
            current_level_exp = total_exp - level_start_exp
            
            # Calculate progress percentage
            if exp_needed_for_next > 0:
                level_progress = min((current_level_exp / exp_needed_for_next) * 100, 100.0)
            else:
                level_progress = 100.0  # Max level (level 100)
            
            # Calculate EXP needed for next level
            if exp_needed_for_next > 0:
                exp_for_next_level = max(exp_needed_for_next - current_level_exp, 0)
            else:
                exp_for_next_level = 0  # Max level reached
            
            return level, current_level_exp, exp_needed_for_next, exp_for_next_level, level_progress
    
    # If total_exp is less than level 1 start (shouldn't happen, but handle it)
    return 1, total_exp, 48, max(48 - total_exp, 0), min((total_exp / 48) * 100, 100.0)

def get_exp_for_level(target_level):
    """Get the EXP required to reach a specific level"""
    if target_level <= 1:
        return 0
    if target_level > 100:
        target_level = 100
    
    # Get the start EXP for the target level
    if target_level in LEVEL_XP_TABLE:
        level_start_exp, _ = LEVEL_XP_TABLE[target_level]
        return level_start_exp
    else:
        # If level not in table, find the closest level
        for level in sorted(LEVEL_XP_TABLE.keys(), reverse=True):
            if level <= target_level:
                level_start_exp, _ = LEVEL_XP_TABLE[level]
                return level_start_exp
    
    return 0

def get_level_from_total_exp(total_exp):
    """Get the level that corresponds to a total EXP value"""
    if total_exp < 0:
        return 1
    
    # Find the level based on total EXP
    for level in sorted(LEVEL_XP_TABLE.keys(), reverse=True):
        level_start_exp, _ = LEVEL_XP_TABLE[level]
        if total_exp >= level_start_exp:
            return level
    
    return 1

# Account tracking data structure (stored in memory, can be persisted to file)
account_tracking = {}  # account_id -> tracking data

def get_account_tracking(account_id):
    """Get tracking data for an account"""
    if account_id not in account_tracking:
        account_tracking[account_id] = {
            'initial_exp': None,
            'initial_level': None,
            'target_level': None,
            'previous_exp': None,
            'previous_exp_time': None,
            'xp_rate': 0,
            'played_count': 0,
            'last_updated': None,
            'is_paused': False
        }
    return account_tracking[account_id]

def calculate_progress_and_eta(account_id, current_exp, current_level):
    """Calculate progress percentage and ETA based on target_level - Same logic as lvlup website"""
    tracking = get_account_tracking(account_id)
    
    # Initialize if first time
    if tracking['initial_exp'] is None:
        tracking['initial_exp'] = current_exp
        tracking['initial_level'] = current_level
        tracking['target_level'] = min(current_level + 1, 100)  # Default: next level
        tracking['previous_exp'] = current_exp
        tracking['previous_exp_time'] = datetime.now(timezone.utc)
        tracking['xp_rate'] = 0
        tracking['played_count'] = 0
    
    # Track played count: increment if XP changed
    if tracking['previous_exp'] is not None and current_exp != tracking['previous_exp']:
        if tracking['played_count'] is None:
            tracking['played_count'] = 0
        tracking['played_count'] += 1
    
    # Calculate progress
    target_level = tracking['target_level'] or (current_level + 1)
    
    if current_level >= target_level:
        progress = 100.0
        total_exp = get_exp_for_level(target_level)
    else:
        # Step-by-step: Show progress from current level to next level
        next_level = min(current_level + 1, target_level)
        current_level_start_exp = get_exp_for_level(current_level)
        next_level_start_exp = get_exp_for_level(next_level)
        
        exp_range = next_level_start_exp - current_level_start_exp
        exp_progress = current_exp - current_level_start_exp
        
        if exp_range > 0:
            progress = min((exp_progress / exp_range) * 100, 100.0)
        else:
            progress = 100.0
        
        total_exp = next_level_start_exp
    
    # Calculate real-time XP/min rate - Same logic as lvlup website
    now = datetime.now(timezone.utc)
    if tracking['is_paused']:
        # Don't update XP rate when paused, keep previous values
        if tracking['xp_rate'] is None:
            tracking['xp_rate'] = 0
    else:
        # Simple method: Track when XP last changed and calculate rate
        if tracking['previous_exp'] is not None and tracking['previous_exp_time'] is not None:
            # Ensure previous_exp_time is timezone-aware
            prev_time = tracking['previous_exp_time']
            if prev_time.tzinfo is None:
                prev_time = prev_time.replace(tzinfo=timezone.utc)
            
            # Check if XP changed
            if current_exp != tracking['previous_exp']:
                # XP changed - calculate rate based on time since last change
                time_diff_seconds = (now - prev_time).total_seconds()
                
                if time_diff_seconds > 0:
                    exp_gained = current_exp - tracking['previous_exp']
                    
                    if exp_gained > 0:
                        # Calculate XP per minute: (XP gained / time in minutes)
                        minutes_passed = time_diff_seconds / 60.0
                        if minutes_passed > 0:
                            tracking['xp_rate'] = int(exp_gained / minutes_passed)
                        else:
                            # Very small time difference, calculate per second and convert
                            xp_per_second = exp_gained / time_diff_seconds
                            tracking['xp_rate'] = int(xp_per_second * 60)
                    else:
                        # XP decreased (shouldn't happen normally, but handle it)
                        tracking['xp_rate'] = 0
                else:
                    # Same timestamp, keep previous rate
                    if tracking['xp_rate'] is None:
                        tracking['xp_rate'] = 0
            else:
                # XP didn't change - check if too much time passed
                time_diff_seconds = (now - prev_time).total_seconds()
                if time_diff_seconds > 120:  # More than 2 minutes with no change
                    tracking['xp_rate'] = 0
                # Otherwise keep previous rate
                if tracking['xp_rate'] is None:
                    tracking['xp_rate'] = 0
        else:
            # First time or no previous data
            if tracking['xp_rate'] is None:
                tracking['xp_rate'] = 0
    
    # Calculate estimated played (how many plays needed to reach target) - Same logic as lvlup website
    estimated_played = None
    if tracking['played_count'] and tracking['played_count'] > 0 and tracking['initial_exp'] is not None:
        # Calculate average XP per play
        total_exp_gained = current_exp - tracking['initial_exp']
        if total_exp_gained > 0:
            avg_xp_per_play = total_exp_gained / tracking['played_count']
            
            # Calculate remaining EXP needed
            if target_level and target_level > 0:
                if current_level >= target_level:
                    estimated_played = tracking['played_count']  # Already reached
                else:
                    next_level = min(current_level + 1, target_level)
                    current_level_start_exp = get_exp_for_level(current_level)
                    next_level_start_exp = get_exp_for_level(next_level)
                    remaining_exp = next_level_start_exp - current_exp
                    if avg_xp_per_play > 0:
                        estimated_played = int(remaining_exp / avg_xp_per_play) + tracking['played_count']
                    else:
                        estimated_played = None
    
    # Calculate ETA
    if current_level >= target_level:
        eta = "Completed"
        tracking['xp_rate'] = 0
    elif tracking['is_paused']:
        eta = "Paused"
    elif tracking['xp_rate'] and tracking['xp_rate'] > 0:
        next_level = min(current_level + 1, target_level)
        current_level_start_exp = get_exp_for_level(current_level)
        next_level_start_exp = get_exp_for_level(next_level)
        remaining_exp = next_level_start_exp - current_exp
        minutes_needed = remaining_exp / tracking['xp_rate']
        hours = int(minutes_needed // 60)
        mins = int(minutes_needed % 60)
        
        if hours > 0:
            eta = f"{hours}h {mins}m"
        else:
            eta = f"{mins}m"
    else:
        eta = "Calculating..."
    
    # Update previous values for next calculation
    tracking['previous_exp'] = current_exp
    tracking['previous_exp_time'] = now
    tracking['last_updated'] = now
    
    # Calculate level-specific stats
    level, current_level_exp, exp_needed_for_level, exp_for_next_level, level_progress = get_level_from_exp(current_exp)
    
    # Calculate remaining XP to next level
    remaining_xp_to_next = exp_for_next_level
    
    return {
        'progress': progress,
        'total_exp': total_exp,
        'current_exp': current_exp,
        'target_level': target_level,
        'xp_rate': tracking['xp_rate'] or 0,
        'eta': eta,
        'played_count': tracking['played_count'],
        'estimated_played': estimated_played,
        'current_level_exp': current_level_exp,
        'exp_needed_for_level': exp_needed_for_level,
        'exp_for_next_level': exp_for_next_level,
        'remaining_xp_to_next': remaining_xp_to_next,
        'level_progress': level_progress,
        'level': level
    }

@app.route('/api/player-info/<uid>', methods=['GET'])
@login_required
@secure_api
def get_player_info(uid):
    """Fetch player info from external API."""
    try:
        # Check user validity
        validity_check = check_user_validity()
        if validity_check:
            return validity_check
        
        if not uid:
            return jsonify({
                'success': False,
                'error': 'UID is required'
            }), 400
        
        # Fetch from external API
        url = f"http://raw.thug4ff.com/info?uid={uid}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            basic_info = data.get('basicInfo', {})
            clan_info = data.get('clanBasicInfo', {})
            pet_info = data.get('petInfo', {})
            social_info = data.get('socialInfo', {})
            credit_info = data.get('creditScoreInfo', {})
            
            return jsonify({
                'success': True,
                'data': {
                    'accountId': basic_info.get('accountId', uid),
                    'nickname': basic_info.get('nickname', 'N/A'),
                    'level': basic_info.get('level', 0),
                    'exp': basic_info.get('exp', 0),
                    'rank': basic_info.get('rank', 0),
                    'maxRank': basic_info.get('maxRank', 0),
                    'rankingPoints': basic_info.get('rankingPoints', 0),
                    'region': basic_info.get('region', 'N/A'),
                    'liked': basic_info.get('liked', 0),
                    'bannerId': basic_info.get('bannerId', ''),
                    'headPic': basic_info.get('headPic', ''),
                    'badgeId': basic_info.get('badgeId', ''),
                    'title': basic_info.get('title', ''),
                    'clanName': clan_info.get('clanName', 'N/A'),
                    'clanId': clan_info.get('clanId', ''),
                    'clanLevel': clan_info.get('clanLevel', 0),
                    'petName': pet_info.get('name', 'N/A'),
                    'petLevel': pet_info.get('level', 0),
                    'petId': pet_info.get('id', ''),
                    'signature': social_info.get('signature', ''),
                    'creditScore': credit_info.get('creditScore', 100),
                    'lastLoginAt': basic_info.get('lastLoginAt', ''),
                    'createAt': basic_info.get('createAt', '')
                }
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': f'Failed to fetch player info: HTTP {response.status_code}'
            }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error fetching player info: {str(e)}'
        }), 500

@app.route('/api/accounts/<account_id>', methods=['DELETE'])
@login_required
@admin_required
@secure_api
def delete_account(account_id):
    """Delete an account (admin only)."""
    try:
        account_file = 'bd.json'
        accounts = get_all_accounts_metadata(account_file)
        
        if account_id not in accounts:
            return jsonify({
                'success': False,
                'error': 'Account not found'
            }), 404
        
        # Stop client if running
        if 'BD' in clients and account_id in clients['BD']:
            clients['BD'][account_id].stop()
            del clients['BD'][account_id]
        
        del accounts[account_id]
        save_accounts_metadata(account_file, accounts)
        
        return jsonify({
            'success': True,
            'message': f'Account {account_id} deleted successfully'
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error deleting account: {str(e)}'
        }), 500

# ==================== AUTHENTICATION ROUTES ====================

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html')
        
        users = load_users()
        if username in users:
            if check_password_hash(users[username]['password_hash'], password):
                user_data = users[username]
                
                # Check if user account is valid (not expired)
                valid_until = user_data.get('valid_until')
                if valid_until:
                    try:
                        expiry = datetime.fromisoformat(valid_until)
                        if datetime.now() >= expiry:
                            flash('Your account has expired. Please contact admin.', 'error')
                            return render_template('login.html')
                    except:
                        pass
                
                user = User(
                    username, 
                    username, 
                    user_data['password_hash'],
                    role=user_data.get('role', 'user'),
                    assigned_account=user_data.get('assigned_account'),
                    valid_until=valid_until
                )
                login_user(user, remember=True, duration=timedelta(days=30))  # Remember for 30 days
                
                # Track session persistently
                session_id = secrets.token_hex(16)
                session['_id'] = session_id
                with session_lock:
                    active_sessions[session_id] = {
                        'username': username,
                        'role': user_data.get('role', 'user'),
                        'login_time': datetime.now().isoformat(),
                        'created_at': time.time()
                    }
                    save_sessions()  # Save to file immediately
                
                flash(f'Welcome back, {username}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password', 'error')
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    
    # Remove from active sessions
    with session_lock:
        session_id = session.get('_id')
        if session_id in active_sessions:
            del active_sessions[session_id]
            save_sessions()  # Save updated sessions
    
    flash(f'You have been logged out successfully, {username}', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Check user validity
    validity_check = check_user_validity()
    if validity_check:
        return validity_check
    
    # Route to separate dashboards based on role
    if current_user.is_admin():
        return render_template('admin_dashboard.html', 
                             username=current_user.username,
                             active_sessions_count=len(active_sessions))
    else:
        return render_template('user_dashboard.html', 
                             username=current_user.username,
                             assigned_account=current_user.assigned_account)

@app.route('/account/<account_id>')
@login_required
def view_account(account_id):
    """Redirect to dashboard - account_view.html has been removed"""
    return redirect(url_for('dashboard'))

@app.route('/api/account/<account_id>/update', methods=['GET'])
@login_required
@secure_api
def update_account_info(account_id):
    """API endpoint to fetch and update account info (for auto-refresh)"""
    try:
        # Check permissions
        if not current_user.is_admin():
            if current_user.assigned_account != account_id:
                return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get account metadata
        account_file = 'bd.json'
        accounts = get_all_accounts_metadata(account_file)
        
        if account_id not in accounts:
            return jsonify({'success': False, 'error': 'Account not found'}), 404
        
        account_data = accounts[account_id]
        uid = account_data.get('uid', '')
        
        if not uid:
            return jsonify({'success': False, 'error': 'No UID set for this account'}), 400
        
        # Fetch latest player info
        url = f"http://raw.thug4ff.com/info?uid={uid}"
        response = requests.get(url, timeout=10)
        
        if response.status_code != 200:
            return jsonify({'success': False, 'error': 'Failed to fetch player info from API'}), 500
        
        data = response.json()
        basic_info = data.get('basicInfo', {})
        
        current_exp = basic_info.get('exp', 0)
        current_level = basic_info.get('level', 0)
        
        # Calculate progress
        progress_data = calculate_progress_and_eta(account_id, current_exp, current_level)
        
        # Get level details
        level, current_level_exp, exp_needed_for_level, exp_for_next_level, level_progress = get_level_from_exp(current_exp)
        
        # Get tracking data
        tracking = get_account_tracking(account_id)
        
        return jsonify({
            'success': True,
            'nickname': basic_info.get('nickname', account_id),
            'level': level,
            'exp': current_exp,
            'rank': basic_info.get('rank', 0),
            'region': basic_info.get('region', 'BD'),
            'bannerId': basic_info.get('bannerId', ''),
            'headPic': basic_info.get('headPic', ''),
            'progress': round(progress_data['progress'], 2),
            'current_exp': progress_data['current_exp'],
            'total_exp': progress_data['total_exp'],
            'target_level': progress_data['target_level'],
            'next_level': min(level + 1, progress_data['target_level']),
            'initial_exp': tracking['initial_exp'],
            'initial_level': tracking['initial_level'],
            'xp_rate': progress_data['xp_rate'],
            'eta': progress_data['eta'],
            'uid': uid,
            'current_level_exp': current_level_exp,
            'exp_needed_for_level': exp_needed_for_level,
            'exp_for_next_level': exp_for_next_level,
            'remaining_xp_to_next': progress_data.get('remaining_xp_to_next', exp_for_next_level),
            'level_progress': round(level_progress, 2),
            'played_count': progress_data['played_count'],
            'estimated_played': progress_data.get('estimated_played'),
            'is_paused': tracking['is_paused'],
            'last_updated': tracking['last_updated'].isoformat() if tracking['last_updated'] else None
        })
    except Exception as e:
        print(f"Error in update_account_info: {e}")
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'}), 500

@app.route('/api/account/<account_id>/set-target', methods=['POST'])
@login_required
@secure_api
def set_account_target(account_id):
    """Set target level for an account"""
    try:
        # Check permissions
        if not current_user.is_admin():
            if current_user.assigned_account != account_id:
                return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        target_level = data.get('target_level', type=int)
        
        if not target_level or target_level < 1 or target_level > 100:
            return jsonify({'success': False, 'error': 'Target level must be between 1 and 100'}), 400
        
        tracking = get_account_tracking(account_id)
        tracking['target_level'] = target_level
        
        return jsonify({
            'success': True,
            'message': f'Target level set to {target_level}',
            'target_level': target_level
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error setting target: {str(e)}'}), 500

@app.route('/api/account/<account_id>/pause', methods=['POST'])
@login_required
@secure_api
def pause_account_tracking(account_id):
    """Pause XP tracking for an account"""
    try:
        # Check permissions
        if not current_user.is_admin():
            if current_user.assigned_account != account_id:
                return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        tracking = get_account_tracking(account_id)
        tracking['is_paused'] = True
        
        return jsonify({
            'success': True,
            'message': 'Account tracking paused'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error pausing tracking: {str(e)}'}), 500

@app.route('/api/account/<account_id>/resume', methods=['POST'])
@login_required
@secure_api
def resume_account_tracking(account_id):
    """Resume XP tracking for an account"""
    try:
        # Check permissions
        if not current_user.is_admin():
            if current_user.assigned_account != account_id:
                return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        tracking = get_account_tracking(account_id)
        tracking['is_paused'] = False
        
        return jsonify({
            'success': True,
            'message': 'Account tracking resumed'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error resuming tracking: {str(e)}'}), 500

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        action = request.form.get('action')
        users = load_users()
        
        if action == 'change_password':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            if not current_password or not new_password or not confirm_password:
                flash('All password fields are required', 'error')
                return render_template('settings.html', username=current_user.username)
            
            if new_password != confirm_password:
                flash('New passwords do not match', 'error')
                return render_template('settings.html', username=current_user.username)
            
            if len(new_password) < 6:
                flash('New password must be at least 6 characters long', 'error')
                return render_template('settings.html', username=current_user.username)
            
            if not check_password_hash(users[current_user.username]['password_hash'], current_password):
                flash('Current password is incorrect', 'error')
                return render_template('settings.html', username=current_user.username)
            
            # Update password
            users[current_user.username]['password_hash'] = generate_password_hash(new_password)
            users[current_user.username]['password_changed_at'] = datetime.now().isoformat()
            save_users(users)
            
            # Invalidate all sessions (force logout everywhere)
            invalidate_all_sessions()
            logout_user()
            
            flash('Password changed successfully. Please login again with your new password.', 'success')
            return redirect(url_for('login'))
        
        elif action == 'change_username':
            new_username = request.form.get('new_username', '').strip()
            password = request.form.get('password', '')
            
            if not new_username or not password:
                flash('Username and password are required', 'error')
                return render_template('settings.html', username=current_user.username)
            
            if len(new_username) < 3:
                flash('Username must be at least 3 characters long', 'error')
                return render_template('settings.html', username=current_user.username)
            
            if new_username in users:
                flash('Username already exists', 'error')
                return render_template('settings.html', username=current_user.username)
            
            if not check_password_hash(users[current_user.username]['password_hash'], password):
                flash('Password is incorrect', 'error')
                return render_template('settings.html', username=current_user.username)
            
            # Update username
            old_username = current_user.username
            users[new_username] = users.pop(old_username)
            users[new_username]['username_changed_at'] = datetime.now().isoformat()
            save_users(users)
            
            # Invalidate all sessions
            invalidate_all_sessions()
            logout_user()
            
            flash(f'Username changed from {old_username} to {new_username}. Please login again.', 'success')
            return redirect(url_for('login'))
    
    return render_template('settings.html', username=current_user.username)

# API routes for dashboard (AJAX)
@app.route('/api/loop/start', methods=['POST'])
@login_required
def api_start_loop():
    global bd_loop_running, bd_loop_thread
    
    with bd_loop_lock:
        if bd_loop_running:
            return jsonify({'success': False, 'message': 'Loop is already running'}), 400
        
        if 'BD' not in clients or len(clients['BD']) == 0:
            return jsonify({'success': False, 'error': 'No BD clients available'}), 400
        
        if 'BD' not in team_tracking:
            team_tracking['BD'] = {}
        
        bd_loop_running = True
        bd_loop_thread = threading.Thread(target=bd_auto_join_loop, daemon=True)
        bd_loop_thread.start()
        
        return jsonify({'success': True, 'message': 'Loop started successfully'}), 200

@app.route('/api/loop/stop', methods=['POST'])
@login_required
def api_stop_loop():
    global bd_loop_running
    
    with bd_loop_lock:
        if not bd_loop_running:
            return jsonify({'success': False, 'message': 'Loop is not running'}), 400
        
        bd_loop_running = False
        return jsonify({'success': True, 'message': 'Loop stop requested'}), 200

@app.route('/api/loop/status', methods=['GET'])
@login_required
def api_loop_status():
    return jsonify({
        'success': True,
        'running': bd_loop_running
    }), 200

@app.route('/api/teamcode/update', methods=['POST'])
@login_required
def api_update_teamcode():
    data = request.get_json()
    team_code = data.get('team_code', '').strip()
    
    if not team_code:
        return jsonify({'success': False, 'error': 'Team code is required'}), 400
    
    try:
        teamcode_file = 'teamcode.json'
        if os.path.exists(teamcode_file):
            with open(teamcode_file, 'r', encoding='utf-8') as f:
                file_data = json.load(f)
        else:
            file_data = {}
        
        file_data['team_code'] = team_code
        
        with open(teamcode_file, 'w', encoding='utf-8') as f:
            json.dump(file_data, f, indent=4, ensure_ascii=False)
        
        return jsonify({
            'success': True,
            'message': f'Team code updated to: {team_code}',
            'team_code': team_code
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


def signal_handler(sig, frame):
    print('Received shutdown signal')
    cleanup()
    sys.exit(0)

# Add security headers to all responses
@app.after_request
def set_security_headers(response):
    return add_security_headers(response)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    atexit.register(cleanup)

    # Initialize default user
    init_default_user()

    # Load accounts for all regions
    connected_accounts.clear()
    
    for region_code, config in REGION_CONFIG.items():
        try:
            json_file = config['json_file']
            accounts = load_accounts(json_file)
            
            # Initialize region clients dict if not exists
            if region_code not in clients:
                clients[region_code] = {}
            if region_code not in team_tracking:
                team_tracking[region_code] = {}
            
            print(f"\n🚀 Starting {len(accounts)} {region_code} accounts from {json_file}...\n")
            for account_id, password in accounts.items():
                client = TcpBotConnectMain(account_id, password, region=region_code)
                clients[region_code][account_id] = client
                client_thread = threading.Thread(target=client.run)
                client_thread.daemon = True
                client_thread.start()
        except FileNotFoundError:
            print(f"No {config['json_file']} file found. Starting without {region_code} accounts.")
        except Exception as e:
            print(f"Error loading {region_code} accounts: {e}")

    # Auto-Start Level UPs for accounts with auto-start enabled
    def start_autostart_loops():
        print("\n⏳ Waiting for accounts to connect before auto-starting loops...")
        time.sleep(20)  # Wait 20 seconds for all accounts to start connecting
        print("🚀 Starting auto-start process...")
        auto_start_loops_for_accounts()
    
    autostart_thread = threading.Thread(target=start_autostart_loops, daemon=True)
    autostart_thread.start()
    print("✅ Auto-start thread initialized (will start after 20 seconds)\n")

    try:
        app.run(host='0.0.0.0', port=4004, debug=False)
    except KeyboardInterrupt:
        print("Server stopped by user")
        cleanup()

