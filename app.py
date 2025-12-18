from flask import Flask, render_template, request, session, redirect, url_for
from user_info import get_user_data
import csv
import os

### 初始化应用###
app = Flask(__name__)
app.secret_key = 'RtRo%wKe4!'

### 从CSV文件读取用户数据的函数###


def load_users_from_csv():
    """
    从 data/userinfo.csv 文件中读取所有用户信息
    返回用户列表，每个用户是一个字典 {'username': '...', 'password': '...'}
    """
    users = []
    csv_path = os.path.join('data', 'userinfo.csv')

    # 检查文件是否存在
    if not os.path.exists(csv_path):
        print(f"警告: {csv_path} 文件不存在！")
        return users

    # 读取CSV文件
    with open(csv_path, 'r', encoding='utf-8') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            users.append({
                'username': row['username'],
                'password': row['password']
            })

    return users


def save_user_to_csv(username, password):
    """
    将新用户保存到 data/userinfo.csv 文件
    返回 True 表示保存成功，False 表示失败
    """
    csv_path = os.path.join('data', 'userinfo.csv')

    try:
        # 以追加模式打开文件，在文件末尾添加新用户
        with open(csv_path, 'a', encoding='utf-8', newline='') as file:
            csv_writer = csv.writer(file)
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

### 登录状态判断###


@app.route('/login', methods=['POST'])
def login():
    # 获取用户输入的用户名和密码
    input_username = request.form.get('username')
    input_password = request.form.get('password')

    # 从CSV文件加载所有用户
    users = load_users_from_csv()

    # 遍历用户列表，查找匹配的用户名和密码
    for user in users:
        # 先检查用户名是否匹配
        if user['username'] == input_username:
            # 再检查密码是否匹配
            if user['password'] == input_password:
                # 登录成功：设置session并跳转到首页
                session['logged_in'] = True
                session['username'] = input_username  # 保存用户名到session
                return redirect(url_for('index'))
            else:
                # 用户名对了但密码错了
                print(f"用户 {input_username} 密码错误")
                return render_template('login.html', error='密码错误')

    # 没有找到匹配的用户名
    print(f"用户 {input_username} 不存在")
    return render_template('login.html', error='用户名不存在')


### 注册页面显示###
@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')


### 注册处理###
@app.route('/register', methods=['POST'])
def register():
    # 获取用户输入的注册信息
    input_username = request.form.get('username')
    input_password = request.form.get('password')
    input_password_confirm = request.form.get('password_confirm')

    # 1. 检查用户名是否为空
    if not input_username or not input_password:
        return render_template('register.html', error='用户名和密码不能为空')

    # 2. 检查用户名长度（至少3个字符）
    if len(input_username) < 3:
        return render_template('register.html', error='用户名至少需要3个字符')

    # 3. 检查密码长度（至少6个字符）
    if len(input_password) < 6:
        return render_template('register.html', error='密码至少需要6个字符')

    # 4. 检查两次密码是否一致
    if input_password != input_password_confirm:
        return render_template('register.html', error='两次输入的密码不一致')

    # 5. 检查用户名是否已存在
    if check_username_exists(input_username):
        return render_template('register.html', error='用户名已存在，请换一个')

    # 6. 保存新用户到CSV文件
    if save_user_to_csv(input_username, input_password):
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
