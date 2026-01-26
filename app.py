from flask import Flask, render_template, request, session, redirect, url_for
from AI_backend import chatbot_bp
import csv
import os
import time
from typing import Optional, Tuple

from werkzeug.security import check_password_hash, generate_password_hash

### 初始化应用###
app = Flask(__name__)
app.secret_key = 'RtRo%wKe4!'

### 注册 Chatbot API 蓝图###
app.register_blueprint(chatbot_bp)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERINFO_CSV_PATH = os.path.join(BASE_DIR, 'data', 'userinfo.csv')

# ======================= 实验开关（给学生改造用） =======================
# TODO(实验任务): 打开/完善这些开关与函数，实现"登录防御"并做前后对比复测
STORE_HASHED_PASSWORDS = True
HIDE_ENUMERATION_ERRORS = True
# =====================================================================

### 从CSV文件读取用户数据的函数###


def load_users_from_csv():
    """
    从 data/userinfo.csv 文件中读取所有用户信息
    返回用户列表，每个用户是一个字典 {'username': '...', 'password': '...'}
    """
    users = []
    csv_path = USERINFO_CSV_PATH

    if not os.path.exists(csv_path):
        return users

    with open(csv_path, 'r', encoding='utf-8', newline='') as file:
        reader = csv.reader(file)
        first_row = next(reader, None)
        if first_row is None:
            return users

        def add_row(row):
            if len(row) < 2:
                return
            users.append({'username': row[0], 'password': row[1]})

        # 兼容有/无表头两种格式
        if [c.strip().lower() for c in first_row[:2]] == ['username', 'password']:
            for row in reader:
                add_row(row)
        else:
            add_row(first_row)
            for row in reader:
                add_row(row)

    return users


def save_user_to_csv(username, password):
    """
    将新用户保存到 data/userinfo.csv 文件
    返回 True 表示保存成功，False 表示失败
    """
    csv_path = USERINFO_CSV_PATH

    try:
        file_exists = os.path.exists(csv_path)
        # 以追加模式打开文件，在文件末尾添加新用户（若为空文件则补表头）
        with open(csv_path, 'a', encoding='utf-8', newline='') as file:
            csv_writer = csv.writer(file)
            if (not file_exists) or os.stat(csv_path).st_size == 0:
                csv_writer.writerow(['username', 'password'])
            csv_writer.writerow([username, password])
        print(f"用户 {username} 注册成功！")
        return True
    except Exception as e:
        print(f"保存用户失败: {e}")
        return False


def check_username_exists(username):
    """
    检查用户名是否已存在
    返回 True 表示已存在，False 表示不存在
    """
    users = load_users_from_csv()
    for user in users:
        if user['username'] == username:
            return True
    return False


def _looks_like_password_hash(value: str) -> bool:
    # werkzeug 的哈希格式通常形如：pbkdf2:sha256:...$salt$hash
    return (':' in value) and ('$' in value)


def verify_password(stored_password: str, input_password: str) -> bool:
    if _looks_like_password_hash(stored_password):
        return check_password_hash(stored_password, input_password)
    return stored_password == input_password


def evaluate_password_strength(password: str, username: Optional[str]) -> Tuple[bool, Optional[str]]:
    """
    TODO(实验任务): 将这里升级为“口令强度评价器/策略”
    建议规则：长度优先(>=12)；字符多样性；禁止包含用户名；弱口令黑名单；拒绝常见模式(123456/111111/qwerty)
    """
    if len(password) < 6:
        return False, '密码至少需要6个字符'
    return True, None


# =============== 在线爆破防护：限速/退避/锁定 =================
# 防护配置（可以修改这些参数来调整防护强度）
FAILED_LOGIN_STATE = {}  # 存储失败记录
MAX_ATTEMPTS = 3 # 最大允许失败次数
LOCKOUT_DURATION = 100  # 锁定时长（秒）


def get_client_ip() -> str:
    """获取客户端真实IP地址"""
    return request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()


# =================== TODO 实验任务：实现这3个小函数 ===================
# 提示：这些函数都是简单的数学计算或逻辑判断，每个函数只需要2-5行代码

def calculate_fail_count(username: str, ip: str) -> int:
    """
    任务1：计算某个用户+IP组合已经失败了多少次
    """
    return 0


def should_be_locked(fail_count: int) -> bool:
    """
    任务2：判断是否应该被锁定
    """
    return False


def calculate_remaining_lockout_time(last_fail_time: float, current_time: float) -> int:
    """
    任务3：计算还需要等待多少秒才能解锁
    """
    return 0

# =================== TODO 结束 ===================

# 下面的代码已经写好了，会调用你实现的3个函数
def check_login_throttle(username: str, ip: str) -> Tuple[bool, int, Optional[str]]:
    """检查是否允许登录（框架代码，已完成）"""
    key = f"{username}:{ip}"
    now = time.time()
    
    # 使用学生实现的函数1：计算失败次数
    fail_count = calculate_fail_count(username, ip)
    
    # 如果没有失败记录，允许登录
    if fail_count == 0:
        return True, 0, None
    
    # 使用学生实现的函数2：判断是否应该锁定
    if should_be_locked(fail_count):
        last_fail_time = FAILED_LOGIN_STATE[key]['last_attempt']
        # 使用学生实现的函数3：计算剩余锁定时间
        remaining = calculate_remaining_lockout_time(last_fail_time, now)
        
        if remaining > 0:
            return False, remaining, f'失败次数过多，请在 {remaining} 秒后重试'
        else:
            # 锁定时间已过，清除记录，允许重新尝试
            del FAILED_LOGIN_STATE[key]
            return True, 0, None
    
    # 未达到锁定阈值，允许登录
    return True, 0, None


def record_login_failure(username: str, ip: str) -> None:
    """记录登录失败（框架代码，已完成）"""
    key = f"{username}:{ip}"
    now = time.time()
    
    if key not in FAILED_LOGIN_STATE:
        FAILED_LOGIN_STATE[key] = {'attempts': 1, 'last_attempt': now}
    else:
        FAILED_LOGIN_STATE[key]['attempts'] += 1
        FAILED_LOGIN_STATE[key]['last_attempt'] = now
    
    # 输出日志，方便观察
    fail_count = FAILED_LOGIN_STATE[key]['attempts']
    print(f"[登录失败] 用户:{username} IP:{ip} 失败次数:{fail_count}")


def record_login_success(username: str, ip: str) -> None:
    """记录登录成功，清除失败记录（框架代码，已完成）"""
    key = f"{username}:{ip}"
    if key in FAILED_LOGIN_STATE:
        del FAILED_LOGIN_STATE[key]
    print(f"[登录成功] 用户:{username} IP:{ip}")
# ============================================================================

### 登录状态判断###


@app.route('/login', methods=['GET', 'POST'])
def login():
    # 如果不是POST请求，直接返回登录页面
    if request.method != 'POST':
        return render_template('login.html')

    # 获取用户输入的用户名和密码
    input_username = request.form.get('username')
    input_password = request.form.get('password')
    client_ip = get_client_ip()

    allowed, wait_seconds, deny_reason = check_login_throttle(
        input_username or '', client_ip)
    if not allowed:
        # 直接返回错误信息，不要在服务器端sleep阻塞响应
        return render_template('login.html', error=deny_reason or '请稍后再试')

    # 从CSV文件加载所有用户
    users = load_users_from_csv()

    # 遍历用户列表，查找匹配的用户名和密码
    for user in users:
        # 先检查用户名是否匹配
        if user['username'] == input_username:
            # 再检查密码是否匹配
            if verify_password(user['password'], input_password):
                # 登录成功：设置session并跳转到首页
                session['logged_in'] = True
                session['username'] = input_username  # 保存用户名到session
                record_login_success(input_username, client_ip)
                return redirect(url_for('index'))
            else:
                record_login_failure(input_username, client_ip)
                # 计算剩余尝试次数
                fail_count = calculate_fail_count(input_username, client_ip)
                remaining_attempts = MAX_ATTEMPTS - fail_count
                
                if HIDE_ENUMERATION_ERRORS:
                    error_msg = '用户名或密码错误'
                else:
                    error_msg = '密码错误'
                
                # 如果还有剩余次数，显示提示
                if remaining_attempts > 0:
                    error_msg += f'（还可以尝试 {remaining_attempts} 次）'
                
                return render_template('login.html', error=error_msg)

    # 没有找到匹配的用户名
    record_login_failure(input_username or '', client_ip)
    # 计算剩余尝试次数
    fail_count = calculate_fail_count(input_username or '', client_ip)
    remaining_attempts = MAX_ATTEMPTS - fail_count
    
    if HIDE_ENUMERATION_ERRORS:
        error_msg = '用户名或密码错误'
    else:
        error_msg = '用户名不存在'
    
    # 如果还有剩余次数，显示提示
    if remaining_attempts > 0:
        error_msg += f'（还可以尝试 {remaining_attempts} 次）'
    
    return render_template('login.html', error=error_msg)


### 注册页面显示###
@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')


### 注册处理###

# TODO(实验任务): 口令强度检测
def validate_register_form(username, password, password_confirm):
    if not username or not password:
        return False, '用户名和密码不能为空'
    if len(username) < 3:
        return False, '用户名至少需要3个字符'
    ok, message = evaluate_password_strength(password, username)
    if not ok:
        return False, message or '密码强度不足'
    if password != password_confirm:
        return False, '两次输入的密码不一致'
    return True, None   # 返回True表示验证成功，None表示没有错误


@app.route('/register', methods=['POST'])
def register():
    # 获取用户输入的注册信息
    input_username = request.form.get('username')
    input_password = request.form.get('password')
    input_password_confirm = request.form.get('password_confirm')

    ok, error_message = validate_register_form(
        input_username, input_password, input_password_confirm)
    if not ok:
        return render_template('register.html', error=error_message)

    # 5. 检查用户名是否已存在
    if check_username_exists(input_username):
        return render_template('register.html', error='用户名已存在，请换一个')

    # 6. 保存新用户到CSV文件
    password_to_store = generate_password_hash(
        input_password) if STORE_HASHED_PASSWORDS else input_password
    if save_user_to_csv(input_username, password_to_store):
        # 注册成功，跳转到登录页面并显示成功消息
        return render_template('login.html', success='注册成功！请登录')
    else:
        return render_template('register.html', error='注册失败，请重试')


### 1.默认页面###


@app.route('/')
def home():
    if session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template('login.html')

### 2.首页###


@app.route('/index')
def index():
    print("hello")
    if not session.get('logged_in'):
        return redirect(url_for('home'))
    return render_template('index.html')

### 3.博客###


@app.route("/blog")
def blog():
    if not session.get('logged_in'):
        return redirect(url_for('home'))

    return render_template("blog.html")

### 4.密码安全###


@app.route("/passwordsecurity")
def passwordsecurity():
    if not session.get('logged_in'):
        return redirect(url_for('home'))

    return render_template("passwordsecurity.html")

### 5.AI安全###


@app.route("/aisecurity")
def aisecurity():
    if not session.get('logged_in'):
        return redirect(url_for('home'))

    return render_template("aisecurity.html")


### 6.退出页面###


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return render_template('login.html')

### 7.越狱挑战页面（无防御）###


@app.route('/nodefense')
def nodefense():
    if not session.get('logged_in'):
        return redirect(url_for('home'))
    return render_template('nodefense.html')

### 8.防御挑战页面（有防御）###


@app.route('/mydefense')
def mydefense():
    if not session.get('logged_in'):
        return redirect(url_for('home'))
    return render_template('mydefense.html')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080, use_reloader=False)
