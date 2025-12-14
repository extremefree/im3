def get_user_data():
    """
    返回用户数据字典
    """
    user = {
        "id": 1001,
        "username": "john_doe",
        "email": "john@example.com",
        "age": 28,
        "is_active": True,
        "created_at": "2025-12-14 10:30:00",
        "profile": {
            "avatar": "/static/images/avatar.png",
            "bio": "Python开发者",
            "location": "北京"
        },
        "roles": ["user", "editor"],
        "settings": {
            "theme": "dark",
            "notifications": True,
            "language": "zh-CN"
        }
    }
    return user

# 调用示例
#user_data = get_user_data()

#print(user_data)
