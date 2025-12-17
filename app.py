from flask import Flask, render_template, request, session, redirect, url_for
from user_info import get_user_data

###登录数据###
app = Flask(__name__)
app.secret_key = 'RtRo%wKe4!'
USERNAME = 'admin'
PASSWORD = '@#1Uc&sp0hN3E'

###登录状态判断###
@app.route('/login', methods=['POST'])  
def login():
    username = request.form.get('username')
    password = request.form.get('password') 
    
    if username == USERNAME and password == PASSWORD:
        session['logged_in'] = True
        return redirect(url_for('index'))
    return render_template('login.html')

###默认页面###
@app.route('/')
def home():
    if session.get('logged_in'):
        print("hello1")
        return redirect(url_for('index'))
    return render_template('login.html')

###首页###
@app.route('/index')
def index():
    print("hello")
    if not session.get('logged_in'):
        return redirect(url_for('home')) 
    return render_template('index.html')

###案例1页面###
@app.route("/example1")
def example1():
    if not session.get('logged_in'):
        return redirect(url_for('home'))
        
    return render_template("example1.html")

###XX案例2页面###
@app.route("/example2")
def example2():
    if not session.get('logged_in'):
        return redirect(url_for('home'))
    
    return render_template("example2.html")

###XX案例3页面###
@app.route("/example3")
def example3():
    if not session.get('logged_in'):
        return redirect(url_for('home'))
    
    return render_template("example3.html")

###XX案例4页面###
@app.route("/example4")
def example4():
    if not session.get('logged_in'):
        return redirect(url_for('home'))
    
    return render_template("example4.html")

###个人中心###
@app.route("/profile")
def profile():
    if not session.get('logged_in'):
        return redirect(url_for('home'))
    userinfo = get_user_data()
    # print(userinfo)
    return render_template("profile.html", userinfo = userinfo)

###退出页面###
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0',port=5051, use_reloader=False)

