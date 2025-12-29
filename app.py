from flask import Flask, render_template, request, session, redirect, url_for
from user_info import get_user_data
import csv
import os
import time
from typing import Optional, Tuple

from werkzeug.security import check_password_hash, generate_password_hash

### 初始化应用###
app = Flask(__name__)
app.secret_key = 'RtRo%wKe4!'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERINFO_CSV_PATH = os.path.join(BASE_DIR, 'data', 'userinfo.csv')

# ======================= 实验开关（给学生改造用） =======================
# TODO(实验任务): 打开/完善这些开关与函数，实现“登录防御”并做前后对比复测
STORE_HASHED_PASSWORDS = True
HIDE_ENUMERATION_ERRORS = False
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


# =============== TODO(实验任务): 在线爆破防护：限速/退避/锁定 =================
# 下面的默认实现是“未开启防护”的空壳，方便学生在实验中自己实现并复测对比。
# 建议实现：按 (username, ip) 记录失败次数与时间窗口；指数退避；短期锁定；记录日志。
FAILED_LOGIN_STATE = {}


def get_client_ip() -> str:
    return request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()


def check_login_throttle(username: str, ip: str) -> Tuple[bool, int, Optional[str]]:
    # 返回 (是否允许本次尝试, 需要等待的秒数, 拒绝原因/提示)
    return True, 0, None


def record_login_failure(username: str, ip: str) -> None:
    _ = (username, ip)
    _ = time.time()


def record_login_success(username: str, ip: str) -> None:
    _ = (username, ip)
    _ = time.time()
# ============================================================================

### 登录状态判断###


@app.route('/login', methods=['POST'])
def login():
    # 获取用户输入的用户名和密码
    input_username = request.form.get('username')
    input_password = request.form.get('password')
    client_ip = get_client_ip()

    allowed, wait_seconds, deny_reason = check_login_throttle(input_username or '', client_ip)
    if not allowed:
        if wait_seconds > 0:
            time.sleep(wait_seconds)
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
                if HIDE_ENUMERATION_ERRORS:
                    return render_template('login.html', error='用户名或密码错误')
                return render_template('login.html', error='密码错误')

    # 没有找到匹配的用户名
    record_login_failure(input_username or '', client_ip)
    if HIDE_ENUMERATION_ERRORS:
        return render_template('login.html', error='用户名或密码错误')
    return render_template('login.html', error='用户名不存在')


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

    ok, error_message = validate_register_form(input_username, input_password, input_password_confirm)
    if not ok:
        return render_template('register.html', error=error_message)

    # 5. 检查用户名是否已存在
    if check_username_exists(input_username):
        return render_template('register.html', error='用户名已存在，请换一个')

    # 6. 保存新用户到CSV文件
    password_to_store = generate_password_hash(input_password) if STORE_HASHED_PASSWORDS else input_password
    if save_user_to_csv(input_username, password_to_store):
        # 注册成功，跳转到登录页面并显示成功消息
        return render_template('login.html', success='注册成功！请登录')
    else:
        return render_template('register.html', error='注册失败，请重试')


### 默认页面###


@app.route('/')
def home():
    if session.get('logged_in'):
        print("hello1")
        return redirect(url_for('index'))
    return render_template('login.html')

### 首页###


@app.route('/index')
def index():
    print("hello")
    if not session.get('logged_in'):
        return redirect(url_for('home'))
    return render_template('index.html')

### 案例1页面###


@app.route("/example1")
def example1():
    if not session.get('logged_in'):
        return redirect(url_for('home'))

    return render_template("example1.html")

### XX案例2页面###


@app.route("/example2")
def example2():
    if not session.get('logged_in'):
        return redirect(url_for('home'))

    return render_template("example2.html")

### XX案例3页面###


@app.route("/example3")
def example3():
    if not session.get('logged_in'):
        return redirect(url_for('home'))

    return render_template("example3.html")

### XX案例4页面###


@app.route("/example4")
def example4():
    if not session.get('logged_in'):
        return redirect(url_for('home'))

    return render_template("example4.html")

### 个人中心###


@app.route("/profile")
def profile():
    if not session.get('logged_in'):
        return redirect(url_for('home'))
    userinfo = get_user_data()
    # print(userinfo)
    return render_template("profile.html", userinfo=userinfo)

### 退出页面###


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return render_template('login.html')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5051, use_reloader=False)
