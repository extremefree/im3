```txt
项目文件结构：
├── app.py                    # 主应用文件
├── requirements.txt          # 依赖文件
├── user_info.py             # 自定义模块（案例）
├── static/
│   ├── css/
│   │   └── style.css
│   └── images/
│       └── avatar.png
│   ├── js/
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── example1.html
│   ├── example2.html
│   ├── example3.html
│   ├── example4.html
│   └── profile.html
│   └── 模板继承使用案例（未使用）.html
└── README.md                # 项目说明（暂时未完成）
```

使用说明：
1.本地启动环境
  python app.py

 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
 * Running on http://192.168.50.208:5000


```bash
python3 tools/bruteforce_login.py --username 111 --mode pin6 --max 500
```

日志示例：
```python
[progress] attempts=50
[progress] attempts=100
[SUCCESS] username=111 password=000123 attempts=124 time=0.05s
```