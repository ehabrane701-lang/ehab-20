import os
import json
import re
import subprocess
import psutil
import socket
import sys
import hashlib
import secrets
import shutil
from datetime import datetime, timedelta
from flask import Flask, send_from_directory, request, jsonify, session, redirect, url_for, make_response

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_DIR = os.path.join(BASE_DIR, "USERS")
os.makedirs(USERS_DIR, exist_ok=True)

app = Flask(__name__, static_folder=BASE_DIR)
app.secret_key = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

running_procs = {}
USERS_FILE = os.path.join(BASE_DIR, "users.json")
REMEMBER_TOKENS_FILE = os.path.join(BASE_DIR, "remember_tokens.json")

# الحساب الرئيسي (المسؤول)
ADMIN_USERNAME = "Ziad555"
ADMIN_PASSWORD = "Ziad555"

# ============== Helper Functions ==============

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def safe_load_json(path, default_val):
    """دالة آمنة لقراءة ملفات JSON لمنع انهيار التطبيق عند تلف البيانات أو فراغ الملف"""
    if not os.path.exists(path):
        return default_val
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return default_val
            return json.loads(content)
    except (json.JSONDecodeError, Exception):
        return default_val

def init_users_db():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            admin_data = {
                ADMIN_USERNAME: {
                    "password": hash_password(ADMIN_PASSWORD),
                    "created_at": datetime.now().isoformat(),
                    "last_login": None,
                    "theme": "premium",
                    "is_admin": True,
                    "can_create_users": True
                }
            }
            json.dump(admin_data, f, indent=2)

def init_tokens_db():
    if not os.path.exists(REMEMBER_TOKENS_FILE):
        with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f)

def create_remember_token(username):
    """إنشاء رمز تذكر جديد للمستخدم"""
    init_tokens_db()
    tokens = safe_load_json(REMEMBER_TOKENS_FILE, {})
    
    token = secrets.token_urlsafe(32)
    expires = (datetime.now() + timedelta(days=30)).isoformat()
    
    tokens[token] = {
        "username": username,
        "created_at": datetime.now().isoformat(),
        "expires_at": expires,
        "last_used": datetime.now().isoformat()
    }
    
    with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    
    return token

def validate_remember_token(token):
    """التحقق من رمز التذكر"""
    tokens = safe_load_json(REMEMBER_TOKENS_FILE, {})
    if token not in tokens:
        return None
    
    token_data = tokens[token]
    try:
        expires_at = datetime.fromisoformat(token_data["expires_at"])
    except (ValueError, KeyError, TypeError):
        tokens.pop(token, None)
        with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(tokens, f, indent=2)
        return None
    
    if datetime.now() > expires_at:
        tokens.pop(token, None)
        with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(tokens, f, indent=2)
        return None
    
    token_data["last_used"] = datetime.now().isoformat()
    tokens[token] = token_data
    
    with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    
    return token_data.get("username")

def delete_remember_token(token):
    """حذف رمز التذكر"""
    tokens = safe_load_json(REMEMBER_TOKENS_FILE, {})
    if token in tokens:
        tokens.pop(token, None)
        with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(tokens, f, indent=2)

def delete_all_user_tokens(username):
    """حذف جميع رموز التذكر للمستخدم"""
    tokens = safe_load_json(REMEMBER_TOKENS_FILE, {})
    tokens_to_delete = [token for token, data in tokens.items() if data.get("username") == username]
    
    if tokens_to_delete:
        for token in tokens_to_delete:
            tokens.pop(token, None)
        with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(tokens, f, indent=2)

def register_user(username, password, created_by_admin=False):
    init_users_db()
    users = safe_load_json(USERS_FILE, {})
    
    if username in users:
        return False, "المستخدم موجود بالفعل"
    
    if len(password) < 6:
        return False, "كلمة المرور يجب أن تكون 6 أحرف على الأقل"
    
    users[username] = {
        "password": hash_password(password),
        "created_at": datetime.now().isoformat(),
        "last_login": None,
        "theme": "blue",
        "is_admin": username == ADMIN_USERNAME,
        "created_by_admin": created_by_admin,
        "created_by": session.get('username') if 'username' in session else None
    }
    
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    
    user_dir = os.path.join(USERS_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    
    return True, "تم إنشاء الحساب بنجاح"

def authenticate_user(username, password):
    init_users_db()
    users = safe_load_json(USERS_FILE, {})
    
    if username not in users:
        return False, "المستخدم غير موجود"
    
    if users[username]["password"] != hash_password(password):
        return False, "كلمة المرور غير صحيحة"
    
    users[username]["last_login"] = datetime.now().isoformat()
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    
    return True, "تم تسجيل الدخول بنجاح"

def is_admin(username):
    init_users_db()
    users = safe_load_json(USERS_FILE, {})
    if username in users:
        return users[username].get("is_admin", False)
    return False

def get_user_servers_dir(username):
    return os.path.join(USERS_DIR, username, "SERVERS")

def ensure_user_servers_dir():
    if 'username' not in session:
        return None
    user_dir = get_user_servers_dir(session['username'])
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def sanitize_folder_name(name):
    if not name: return ""
    name = name.strip()
    name = re.sub(r"\s+", "-", name)
    name = re.sub(r"[^A-Za-z0-9\-\_\.]", "", name)
    return name[:200]

def sanitize_filename(name):
    if not name: return ""
    name = name.strip()
    name = re.sub(r"[^A-Za-z0-9\-\_\.]", "", name)
    return name[:200]

def ensure_meta(folder):
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir:
        return None
    
    folder_path = os.path.join(user_servers_dir, folder)
    os.makedirs(folder_path, exist_ok=True)
    meta_path = os.path.join(folder_path, "meta.json")
    if not os.path.exists(meta_path):
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump({"display_name": folder, "startup_file": ""}, f, indent=2)
    return meta_path

def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception: 
        return '127.0.0.1'

def load_servers_list():
    if 'username' not in session:
        return []
    
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir or not os.path.exists(user_servers_dir):
        return []
    
    try:
        entries = [d for d in os.listdir(user_servers_dir) 
                  if os.path.isdir(os.path.join(user_servers_dir, d))]
    except Exception: 
        entries = []
    
    servers = []
    for i, folder in enumerate(entries, start=1):
        ensure_meta(folder)
        meta_path = os.path.join(user_servers_dir, folder, "meta.json")
        display_name, startup_file = folder, ""
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
                display_name = meta.get("display_name", folder)
                startup_file = meta.get("startup_file", "")
        except Exception: 
            pass
        servers.append({
            "id": i, 
            "title": display_name, 
            "folder": folder, 
            "subtitle": f"Node-{i} · Local", 
            "startup_file": startup_file
        })
    return servers

# ============== Routes ==============

@app.before_request
def check_remember_token():
    """فحص رمز التذكر قبل كل طلب"""
    if 'username' in session:
        return
    
    remember_token = request.cookies.get('remember_token')
    if remember_token:
        username = validate_remember_token(remember_token)
        if username:
            session['username'] = username
            session.permanent = True

@app.route("/")
def home():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    
    if is_admin(session['username']):
        return send_from_directory(BASE_DIR, "admin_panel.html")
    
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/index.html")
def serve_index():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    
    if is_admin(session['username']):
        return redirect(url_for('home'))
    
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/login")
def login_page():
    if 'username' in session:
        return redirect(url_for('home'))
    return send_from_directory(BASE_DIR, "login.html")

@app.route("/admin")
def admin_panel():
    if 'username' not in session or not is_admin(session['username']):
        return redirect(url_for('login_page'))
    return send_from_directory(BASE_DIR, "admin_panel.html")

@app.route("/api/register", methods=["POST"])
def api_register():
    if 'username' not in session or not is_admin(session['username']):
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    
    if not username or not password:
        return jsonify({"success": False, "message": "اسم المستخدم وكلمة المرور مطلوبان"})
    
    success, message = register_user(username, password, created_by_admin=True)
    return jsonify({"success": success, "message": message})

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    remember_me = data.get("remember_me", False)
    
    if not username or not password:
        return jsonify({"success": False, "message": "اسم المستخدم وكلمة المرور مطلوبان"})
    
    success, message = authenticate_user(username, password)
    if success:
        session['username'] = username
        
        response_data = {
            "success": True, 
            "message": message,
            "username": username,
            "is_admin": is_admin(username)
        }
        
        if remember_me:
            token = create_remember_token(username)
            response = make_response(jsonify(response_data))
            response.set_cookie(
                'remember_token',
                token,
                max_age=30*24*60*60,
                httponly=True,
                secure=request.is_secure,
                samesite='Strict'
            )
            return response
        
        return jsonify(response_data)
    
    return jsonify({"success": False, "message": message})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    username = session.get('username')
    if username:
        delete_all_user_tokens(username)
    
    session.pop('username', None)
    
    response = make_response(jsonify({"success": True, "message": "تم تسجيل الخروج"}))
    response.set_cookie('remember_token', '', expires=0)
    return response

@app.route("/api/current_user")
def api_current_user():
    if 'username' in session:
        admin = is_admin(session['username'])
        return jsonify({
            "success": True, 
            "username": session['username'],
            "is_admin": admin,
            "has_remember_token": bool(request.cookies.get('remember_token'))
        })
    return jsonify({"success": False}), 401

@app.route("/api/user/settings", methods=["GET", "POST"])
def user_settings():
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    if request.method == "GET":
        users = safe_load_json(USERS_FILE, {})
        user_data = users.get(session['username'], {})
        return jsonify({
            "success": True,
            "username": session['username'],
            "created_at": user_data.get("created_at"),
            "last_login": user_data.get("last_login"),
            "theme": user_data.get("theme", "blue"),
            "is_admin": user_data.get("is_admin", False)
        })
    
    data = request.get_json(silent=True) or {}
    theme = data.get("theme", "blue")
    
    users = safe_load_json(USERS_FILE, {})
    if session['username'] in users:
        users[session['username']]["theme"] = theme
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2)
        return jsonify({"success": True, "message": "تم تحديث الإعدادات"})
    
    return jsonify({"success": False, "message": "المستخدم غير موجود"})

# ============== Protected Routes ==============

@app.route("/servers")
def get_servers():
    if 'username' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    return jsonify({"success": True, "servers": load_servers_list()})

@app.route("/add", methods=["POST"])
def add_server():
    if 'username' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    folder = sanitize_folder_name(name)
    if not folder:
        return jsonify({"success": False, "message": "اسم المجلد غير صالح"}), 400
    
    user_servers_dir = ensure_user_servers_dir()
    target = os.path.realpath(os.path.join(user_servers_dir, folder))
    
    if not target.startswith(os.path.realpath(user_servers_dir)):
        return jsonify({"success": False, "message": "مسار غير صالح"}), 403
    
    if os.path.exists(target): 
        return jsonify({"success": False, "message": "Exists"}), 409
    
    os.makedirs(target, exist_ok=True)
    ensure_meta(folder)
    with open(os.path.join(target, "server.log"), "w", encoding="utf-8") as f:
        f.write("")
    return jsonify({"success": True, "servers": load_servers_list()})

@app.route("/server/stats/<folder>")
def get_stats(folder):
    if 'username' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    
    folder = sanitize_folder_name(folder)
    proc_key = f"{session['username']}_{folder}"
    proc = running_procs.get(proc_key)
    running = False
    cpu, mem = "0%", "0 MB"
    
    if proc and psutil.pid_exists(proc.pid):
        try:
            p = psutil.Process(proc.pid)
            if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                running = True
                cpu = f"{p.cpu_percent(interval=None)}%"
                mem = f"{p.memory_info().rss / 1024 / 1024:.1f} MB"
        except Exception: 
            pass
    
    user_servers_dir = ensure_user_servers_dir()
    log_path = os.path.join(user_servers_dir, folder, "server.log")
    logs = ""
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                logs = f.read()
        except Exception:
            pass
    
    return jsonify({
        "status": "Running" if running else "Offline", 
        "cpu": cpu, 
        "mem": mem, 
        "logs": logs, 
        "ip": get_ip()
    })

@app.route("/server/action/<folder>/<act>", methods=["POST"])
def server_action(folder, act):
    if 'username' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    
    folder = sanitize_folder_name(folder)
    proc_key = f"{session['username']}_{folder}"
    
    if proc_key in running_procs:
        try:
            p = psutil.Process(running_procs[proc_key].pid)
            for child in p.children(recursive=True): 
                child.kill()
            p.kill()
        except Exception: 
            pass
        if act == "stop": 
            running_procs.pop(proc_key, None)
    
    if act == "stop": 
        return jsonify({"success": True})

    user_servers_dir = ensure_user_servers_dir()
    log_path = os.path.join(user_servers_dir, folder, "server.log")
    
    try:
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("")
    except Exception:
        pass
    
    meta_path = ensure_meta(folder)
    if not meta_path:
        return jsonify({"success": False, "message": "مجلد غير موجود"})
    
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            startup = json.load(f).get("startup_file")
    except Exception:
        startup = ""
    
    if not startup: 
        return jsonify({"success": False, "message": "No main file set."})
    
    server_folder_path = os.path.realpath(os.path.join(user_servers_dir, folder))
    startup_file_path = os.path.realpath(os.path.join(server_folder_path, startup))
    
    if not startup_file_path.startswith(server_folder_path) or not os.path.exists(startup_file_path):
        return jsonify({"success": False, "message": "الملف غير موجود أو المسار غير صالح"})
    
    try:
        log_file = open(log_path, "a", encoding="utf-8")
        proc = subprocess.Popen(
            [sys.executable, "-u", startup], 
            cwd=server_folder_path, 
            stdout=log_file, 
            stderr=log_file
        )
        running_procs[proc_key] = proc
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": f"فشل تشغيل السيرفر: {str(e)}"})

@app.route("/files/list/<folder>")
def list_files(folder):
    if 'username' not in session:
        return jsonify([]), 401
    
    folder = sanitize_folder_name(folder)
    user_servers_dir = ensure_user_servers_dir()
    p = os.path.realpath(os.path.join(user_servers_dir, folder))
    
    if not p.startswith(os.path.realpath(user_servers_dir)):
        return jsonify([]), 403
        
    files = []
    if os.path.exists(p):
        try:
            for f in os.listdir(p):
                if f in ["meta.json", "server.log"]: 
                    continue
                f_path = os.path.join(p, f)
                if os.path.isfile(f_path):
                    files.append({"name": f, "size": f"{os.path.getsize(f_path) / 1024:.1f} KB"})
        except Exception:
            pass
    return jsonify(files)

@app.route("/files/content/<folder>/<filename>")
def get_file_content(folder, filename):
    if 'username' not in session:
        return jsonify({"content": ""}), 401
    
    folder = sanitize_folder_name(folder)
    user_servers_dir = os.path.realpath(ensure_user_servers_dir())
    file_path = os.path.realpath(os.path.join(user_servers_dir, folder, filename))
    
    if not file_path.startswith(user_servers_dir):
        return jsonify({"content": ""}), 403
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return jsonify({"content": f.read()})
    except Exception: 
        return jsonify({"content": ""})

@app.route("/files/save/<folder>/<filename>", methods=["POST"])
def save_file_content(folder, filename):
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    folder = sanitize_folder_name(folder)
    user_servers_dir = os.path.realpath(ensure_user_servers_dir())
    file_path = os.path.realpath(os.path.join(user_servers_dir, folder, filename))
    
    if not file_path.startswith(user_servers_dir):
        return jsonify({"success": False}), 403
    
    data = request.get_json(silent=True) or {}
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(data.get('content', ''))
        return jsonify({"success": True})
    except Exception:
        return jsonify({"success": False})

@app.route("/files/upload/<folder>", methods=["POST"])
def upload_file(folder):
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    folder = sanitize_folder_name(folder)
    user_servers_dir = os.path.realpath(ensure_user_servers_dir())
    target_dir = os.path.realpath(os.path.join(user_servers_dir, folder))
    
    if not target_dir.startswith(user_servers_dir):
        return jsonify({"success": False}), 403
        
    uploaded_files = request.files.getlist('files[]')
    results = []
    
    for f in uploaded_files:
        if f and f.filename:
            safe_name = sanitize_filename(f.filename)
            save_path = os.path.join(target_dir, safe_name)
            f.save(save_path)
            try:
                size_kb = os.path.getsize(save_path) / 1024
            except Exception:
                size_kb = 0.0
            results.append({
                "name": safe_name,
                "size": f"{size_kb:.2f} KB"
            })
    
    return jsonify({
        "success": True, 
        "message": f"تم رفع {len(results)} ملف بنجاح",
        "uploaded_files": results
    })

@app.route("/files/upload-single/<folder>", methods=["POST"])
def upload_single_file(folder):
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    folder = sanitize_folder_name(folder)
    user_servers_dir = os.path.realpath(ensure_user_servers_dir())
    target_dir = os.path.realpath(os.path.join(user_servers_dir, folder))
    
    if not target_dir.startswith(user_servers_dir):
        return jsonify({"success": False}), 403
        
    if 'file' not in request.files:
        return jsonify({"success": False, "message": "لم يتم اختيار ملف"})
    
    f = request.files['file']
    
    if f and f.filename:
        safe_name = sanitize_filename(f.filename)
        save_path = os.path.join(target_dir, safe_name)
        f.save(save_path)
        try:
            size_kb = os.path.getsize(save_path) / 1024
        except Exception:
            size_kb = 0.0
        
        return jsonify({
            "success": True,
            "message": "تم رفع الملف بنجاح",
            "file": {
                "name": safe_name,
                "size": f"{size_kb:.2f} KB"
            }
        })
    
    return jsonify({"success": False, "message": "فشل رفع الملف"})

@app.route("/files/rename/<folder>", methods=["POST"])
def rename_file(folder):
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    folder = sanitize_folder_name(folder)
    user_servers_dir = os.path.realpath(ensure_user_servers_dir())
    data = request.get_json(silent=True) or {}
    
    old_name = data.get('old', '')
    new_name = data.get('new', '')
    
    if not old_name or not new_name:
        return jsonify({"success": False, "message": "الأسماء مطلوبة"}), 400
        
    old_path = os.path.realpath(os.path.join(user_servers_dir, folder, old_name))
    new_path = os.path.realpath(os.path.join(user_servers_dir, folder, new_name))
    
    if not old_path.startswith(user_servers_dir) or not new_path.startswith(user_servers_dir):
        return jsonify({"success": False}), 403
    
    try:
        os.rename(old_path, new_path)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/files/delete/<folder>", methods=["POST"])
def delete_file(folder):
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    folder = sanitize_folder_name(folder)
    user_servers_dir = os.path.realpath(ensure_user_servers_dir())
    data = request.get_json(silent=True) or {}
    filename = data.get('name', '')
    
    file_path = os.path.realpath(os.path.join(user_servers_dir, folder, filename))
    
    if not file_path.startswith(user_servers_dir):
        return jsonify({"success": False}), 403
    
    try:
        os.remove(file_path)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/files/install/<folder>", methods=["POST"])
def install_req(folder):
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    folder = sanitize_folder_name(folder)
    user_servers_dir = ensure_user_servers_dir()
    server_dir = os.path.realpath(os.path.join(user_servers_dir, folder))
    
    req_path = os.path.join(server_dir, "requirements.txt")
    if not os.path.exists(req_path):
        return jsonify({"success": False, "message": "ملف requirements.txt غير موجود"})
    
    log_path = os.path.join(server_dir, "server.log")
    
    try:
        with open(log_path, "w", encoding="utf-8") as log_file:
            log_file.write("[SYSTEM] Starting Installation...\n")
            log_file.write(f"[SYSTEM] Installing packages from: {req_path}\n")
            log_file.write(f"[SYSTEM] Python executable: {sys.executable}\n")
            log_file.write(f"[SYSTEM] Working directory: {server_dir}\n")
            log_file.write("="*50 + "\n")
    except Exception:
        pass
    
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
            cwd=server_dir, 
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        
        with open(log_path, "a", encoding="utf-8") as log_file:
            if proc.stdout:
                for line in proc.stdout:
                    log_file.write(line)
                    log_file.flush()
        
        proc.wait()
        
        with open(log_path, "a", encoding="utf-8") as log_file:
            if proc.returncode == 0:
                log_file.write("\n" + "="*50 + "\n")
                log_file.write("[SYSTEM] Installation completed successfully!\n")
            else:
                log_file.write("\n" + "="*50 + "\n")
                log_file.write(f"[SYSTEM] Installation failed with exit code: {proc.returncode}\n")
        
        return jsonify({"success": True, "message": "تم بدء التثبيت بنجاح"})
    
    except Exception as e:
        try:
            with open(log_path, "a", encoding="utf-8") as log_file:
                log_file.write(f"\n[ERROR] Failed to start installation: {str(e)}\n")
        except Exception:
            pass
        
        return jsonify({"success": False, "message": f"فشل بدء التثبيت: {str(e)}"})

@app.route("/server/set-startup/<folder>", methods=["POST"])
def set_startup(folder):
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    folder = sanitize_folder_name(folder)
    meta_path = ensure_meta(folder)
    if not meta_path:
        return jsonify({"success": False}), 404
    
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            m = json.load(f)
    except Exception:
        m = {"display_name": folder, "startup_file": ""}
        
    data = request.get_json(silent=True) or {}
    m["startup_file"] = data.get('file', '')
    
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(m, f, indent=2)
    return jsonify({"success": True})

@app.route("/api/admin/users", methods=["GET"])
def get_all_users():
    if 'username' not in session or not is_admin(session['username']):
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    
    init_users_db()
    users = safe_load_json(USERS_FILE, {})
    
    user_list = []
    for username, data in users.items():
        if username != ADMIN_USERNAME:
            user_list.append({
                "username": username,
                "created_at": data.get("created_at"),
                "last_login": data.get("last_login"),
                "created_by": data.get("created_by", "system")
            })
    
    return jsonify({"success": True, "users": user_list})

@app.route("/api/admin/delete-user", methods=["POST"])
def delete_user():
    if 'username' not in session or not is_admin(session['username']):
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    
    data = request.get_json(silent=True) or {}
    username_to_delete = data.get("username", "").strip()
    
    # التحقق النظيف من اسم المستخدم لمنع حذف المشرف الرئيسي
    if not username_to_delete or username_to_delete == ADMIN_USERNAME:
        return jsonify({"success": False, "message": "لا يمكن حذف هذا المستخدم"})
    
    init_users_db()
    users = safe_load_json(USERS_FILE, {})
    
    if username_to_delete not in users:
        return jsonify({"success": False, "message": "المستخدم غير موجود"})
    
    users.pop(username_to_delete, None)
    
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    
    user_dir = os.path.join(USERS_DIR, username_to_delete)
    if os.path.exists(user_dir):
        try:
            shutil.rmtree(user_dir)
        except Exception:
            pass
    
    return jsonify({"success": True, "message": "تم حذف المستخدم بنجاح"})

if __name__ == "__main__":
    port = int(os.environ.get("SERVER_PORT", 21910))
    # تم جعل وضع التصحيح آمنًا بحيث يعتمد على متغيرات البيئة بدلاً من تفعيله مباشرة افتراضياً
    debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
