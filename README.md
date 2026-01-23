```txt
项目文件结构：
├── app.py                    # 主应用文件
├── requirements.txt          # 依赖文件
├── user_info.py             # 自定义模块（案例）
├── config.py                # 配置文件（API密钥、API服务地址等）
├── static/
│   ├── css/
│   │   └── style.css
│   └── images/
│       └── avatar.png
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── AISecurity.html       # AI安全模块入口页面
│   ├── PasswordSecurity.html
│   ├── blog.html
│   ├── profile.html
│   ├── example3.html         # 越狱挑战页面（无防御）
│   └── example4.html         # 防御挑战页面（有防御）
├── AI/                       # AI 模块
│   ├── chatbot.py            # ChatBot 基类
│   ├── defense_framework.py  # 防御框架（NoDefense/MyDefense）
│   ├── evaluation.py         # LLM 评估模块
│   ├── jailbreak_samples.json
│   └── non_sensitive_samples.json
├── AI_backend/               # 后端 API 模块
│   ├── __init__.py           # 导出 chatbot_bp
│   ├── api.py                # ChatBot API 路由
│   └── chatbot_service.py    # ChatBot 服务层
├── data/
│   └── userinfo.csv          # 用户数据
├── tools/
│   └── bruteforce_login.py   # 暴力破解演示工具
└── README.md                 # 项目说明
```

使用说明：
1.本地启动环境
  python app.py

 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:8080
 * Running on http://192.168.50.208:8080


```bash
python3 tools/bruteforce_login.py --username 111 --mode pin6 --max 500
```

日志示例：
```python
[progress] attempts=50
[progress] attempts=100
[SUCCESS] username=111 password=000123 attempts=124 time=0.05s
```

主要功能模块：
- AI安全模块：越狱挑战（example3.html）和防御挑战（example4.html）
- 密码安全模块
- 用户认证系统（登录/注册）
- 博客系统
