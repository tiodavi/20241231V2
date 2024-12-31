from flask import Flask, request, session, redirect, url_for, render_template, flash, g
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime, timedelta
import secrets
import re
from functools import wraps

app = Flask(__name__)
app.config.update(
    SECRET_KEY='please-change-this-random-string',
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='myemail@gmail.com',
    MAIL_PASSWORD='abcdefghijklmnop',
    DATABASE='member_system.db'
)

mail = Mail(app)

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.executescript(f.read())
        db.commit()

@app.teardown_appcontext
def teardown_db(exception):
    close_db()

def is_valid_password(password):
    if len(password) < 8:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    return True

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if not is_valid_password(password):
            flash('密碼必須至少8個字元，包含大小寫字母和數字', 'error')
            return redirect(url_for('register'))
            
        verification_token = secrets.token_urlsafe(32)
        
        try:
            db = get_db()
            cur = db.cursor()
            
            # 檢查使用者名稱是否已存在
            cur.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            if cur.fetchone():
                flash('使用者名稱已存在', 'error')
                return redirect(url_for('register'))
                
            # 檢查電子郵件是否已存在
            cur.execute("SELECT 1 FROM users WHERE email = ?", (email,))
            if cur.fetchone():
                flash('電子郵件已被使用', 'error')
                return redirect(url_for('register'))
            
            # 插入新使用者，直接設定為已驗證
            cur.execute(
                """INSERT INTO users 
                   (username, email, password, verification_token, is_verified, created_at) 
                   VALUES (?, ?, ?, ?, ?, datetime('now'))""",
                (username, email, generate_password_hash(password), verification_token, True)
            )
            
            db.commit()
            
            # 註解掉郵件發送部分
            '''
            try:
                msg = Message('驗證您的帳號',
                            sender=app.config['MAIL_USERNAME'],
                            recipients=[email])
                verify_url = url_for('verify_email', 
                                   token=verification_token, 
                                   _external=True)
                msg.body = f'請點擊以下連結驗證您的帳號：{verify_url}'
                mail.send(msg)
                flash('註冊成功！請檢查您的電子郵件進行驗證。', 'success')
            except Exception as e:
                flash('註冊成功！但發送驗證郵件時發生錯誤。', 'warning')
                print(f"郵件發送錯誤: {e}")
            '''
            
            flash('註冊成功！現在可以登入了。', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.rollback()
            flash('註冊時發生錯誤，請稍後再試。', 'error')
            print(f"資料庫錯誤: {e}")
            return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = 'remember' in request.form
        
        conn = get_db()
        cur = conn.cursor()
        
        try:
            cur.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cur.fetchone()
            
            if user:
                # 檢查帳號是否被鎖定
                if user[11] and user[11] > datetime.now():
                    flash('帳號已被暫時鎖定，請稍後再試', 'error')
                    return redirect(url_for('login'))
                
                if check_password_hash(user[3], password):
                    if not user[5]:  # 檢查是否已驗證
                        flash('請先驗證您的電子郵件', 'warning')
                        return redirect(url_for('login'))
                        
                    session['user_id'] = user[0]
                    session.permanent = remember
                    
                    # 重設登入嘗試次數
                    cur.execute(
                        "UPDATE users SET login_attempts = 0, last_login = datetime('now') WHERE id = ?",
                        (user[0],)
                    )
                    conn.commit()
                    
                    flash('登入成功！', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    # 增加登入嘗試次數
                    attempts = user[10] + 1
                    if attempts >= 5:
                        locked_until = datetime.now() + timedelta(minutes=30)
                        cur.execute(
                            "UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?",
                            (attempts, locked_until, user[0])
                        )
                    else:
                        cur.execute(
                            "UPDATE users SET login_attempts = ? WHERE id = ?",
                            (attempts, user[0])
                        )
                    conn.commit()
                    flash('密碼錯誤', 'error')
            else:
                flash('使用者名稱不存在', 'error')
                
        finally:
            cur.close()
            conn.close()
            
    return render_template('login.html')

@app.cli.command('init-db')
def init_db_command():
    """Clear existing data and create new tables."""
    init_db()
    print('Initialized the database.')

@app.route('/')
def index():
    return render_template('index.html')

# 登入要求裝飾器
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('請先登入', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 會員中心首頁
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = cur.fetchone()
    return render_template('dashboard.html', user=user)

# 個人資料編輯
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        email = request.form['email']
        # 可以加入更多個人資料欄位
        
        db = get_db()
        cur = db.cursor()
        cur.execute('UPDATE users SET email = ? WHERE id = ?',
                   (email, session['user_id']))
        db.commit()
        flash('個人資料已更新', 'success')
        return redirect(url_for('profile'))
        
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = cur.fetchone()
    return render_template('profile.html', user=user)

# 修改密碼
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        db = get_db()
        cur = db.cursor()
        cur.execute('SELECT password FROM users WHERE id = ?', (session['user_id'],))
        user = cur.fetchone()
        
        if not check_password_hash(user['password'], current_password):
            flash('目前密碼錯誤', 'error')
        elif new_password != confirm_password:
            flash('新密碼與確認密碼不符', 'error')
        else:
            hashed_password = generate_password_hash(new_password)
            cur.execute('UPDATE users SET password = ? WHERE id = ?',
                       (hashed_password, session['user_id']))
            db.commit()
            flash('密碼已更新', 'success')
            return redirect(url_for('dashboard'))
            
    return render_template('change_password.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('您已成功登出', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    #with app.app_context():
     #init_db()
    app.run(debug=True)
