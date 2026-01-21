"""
Chatbot 服务模块
提供 NoDefense 和 MyDefense 两种防御的 Chatbot 实例
"""

import sys
import os
import json
import random
import importlib

# 添加 AI 目录到 Python 路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'AI'))

# 从配置文件导入
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
try:
    from config import API_KEY, MODEL_NAME, BASE_URL, JUDGE_MODEL_NAME
except ImportError:
    # 如果配置文件不存在，使用默认值
    API_KEY = "sk-xxx"
    MODEL_NAME = "Pro/Qwen/Qwen2.5-7B-Instruct"
    BASE_URL = "https://api.siliconflow.cn/v1"
    JUDGE_MODEL_NAME = "zai-org/GLM-4.5-Air"

from chatbot import ChatBot
from defense_framework import NoDefense, MyDefense
import defense_framework  # 用于热重载
from evaluation import llm_judge_usability

# 全局 Chatbot 实例
jailbreak_chatbot = None  # NoDefense 实例
defense_chatbot = None    # MyDefense 实例


def init_chatbots():
    """初始化两个 Chatbot 实例"""
    global jailbreak_chatbot, defense_chatbot

    jailbreak_chatbot = ChatBot(
        api_key=API_KEY,
        model_name=MODEL_NAME,
        base_url=BASE_URL,
        defense_framework=NoDefense()
    )

    defense_chatbot = ChatBot(
        api_key=API_KEY,
        model_name=MODEL_NAME,
        base_url=BASE_URL,
        defense_framework=MyDefense()
    )


def get_jailbreak_response(user_input: str) -> str:
    """
    获取 NoDefense Chatbot 的回复（越狱挑战）

    Args:
        user_input: 用户输入

    Returns:
        str: Chatbot 的回复
    """
    if jailbreak_chatbot is None:
        init_chatbots()

    try:
        response = jailbreak_chatbot.chat(user_input)
        return response
    except Exception as e:
        return f"错误: {str(e)}"


def get_defense_response(user_input: str) -> str:
    """
    获取 MyDefense Chatbot 的回复（防御挑战）

    Args:
        user_input: 用户输入

    Returns:
        str: Chatbot 的回复
    """
    if defense_chatbot is None:
        init_chatbots()

    try:
        response = defense_chatbot.chat(user_input)
        return response
    except Exception as e:
        return f"错误: {str(e)}"


def update_defense():
    """
    更新防御设置（先测试新代码可用性，通过后才生效）

    流程：
    1. 热重载 defense_framework 模块
    2. 创建临时 ChatBot 实例
    3. 用简单问题测试临时实例是否能正常响应
    4. 测试通过则替换正式实例，失败则保留旧版本
    """
    global defense_chatbot

    # 1. 热重载 defense_framework 模块，加载最新代码
    try:
        importlib.reload(defense_framework)
    except Exception as e:
        return {
            "status": "error",
            "message": f"防御代码加载失败，保留旧版本",
            "detail": str(e)
        }

    # 2. 重新获取更新后的 MyDefense 类
    ReloadedMyDefense = getattr(defense_framework, 'MyDefense')

    # 3. 创建临时 ChatBot 实例用于测试
    try:
        temp_chatbot = ChatBot(
            api_key=API_KEY,
            model_name=MODEL_NAME,
            base_url=BASE_URL,
            defense_framework=ReloadedMyDefense()
        )
    except Exception as e:
        return {
            "status": "error",
            "message": f"防御实例创建失败，保留旧版本",
            "detail": str(e)
        }

    # 4. 快速可用性测试
    test_question = "你好，请简单介绍一下你自己"
    try:
        response = temp_chatbot.chat(test_question)

        # 检查响应是否有效
        if not response:
            return {
                "status": "error",
                "message": "新防御代码测试失败：无响应，保留旧版本"
            }
        if response.startswith("错误:") or response.startswith("Error:"):
            return {
                "status": "error",
                "message": "新防御代码测试失败，保留旧版本",
                "detail": response
            }
    except Exception as e:
        return {
            "status": "error",
            "message": f"新防御代码执行出错，保留旧版本",
            "detail": str(e)
        }

    # 5. 测试通过，替换正式实例
    defense_chatbot = temp_chatbot
    return {
        "status": "success",
        "message": "防御代码已更新并验证通过",
        "test_response": response[:100] + "..." if len(response) > 100 else response
    }


def clear_jailbreak_history():
    """清除越狱 Chatbot 的对话历史"""
    if jailbreak_chatbot is None:
        init_chatbots()

    jailbreak_chatbot.clear()
    return {"status": "success"}


def clear_defense_history():
    """清除防御 Chatbot 的对话历史"""
    if defense_chatbot is None:
        init_chatbots()

    defense_chatbot.clear()
    return {"status": "success"}


def test_defense_usability():
    """
    测试防御 Chatbot 的可用性

    Returns:
        Dict: 包含测试结果的字典
    """
    global defense_chatbot

    if defense_chatbot is None:
        init_chatbots()

    # 非敏感样本数据文件路径
    non_sensitive_data_path = os.path.join(
        os.path.dirname(__file__), '..', 'AI', 'non_sensitive_samples.json'
    )

    try:
        result = defense_chatbot.test_usability(non_sensitive_data_path)
        return {"status": "success", "data": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def test_defense_usability_stream():
    """
    流式测试防御 Chatbot 的可用性（支持进度回调）

    Yields:
        Dict: 每次测试的进度信息
    """
    global defense_chatbot

    if defense_chatbot is None:
        init_chatbots()

    # 非敏感样本数据文件路径
    non_sensitive_data_path = os.path.join(
        os.path.dirname(__file__), '..', 'AI', 'non_sensitive_samples.json'
    )

    # 加载非敏感样本数据
    try:
        with open(non_sensitive_data_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            non_sensitive_samples = data.get('non_sensitive_samples', [])
    except Exception as e:
        yield {"type": "error", "message": f"加载数据失败: {str(e)}"}
        return

    if not non_sensitive_samples:
        yield {"type": "error", "message": "没有找到非敏感样本数据"}
        return

    total = len(non_sensitive_samples)
    test_results = []
    quality_scores = []

    # 发送开始信息
    yield {"type": "start", "total": total}

    # 逐个测试样本
    for idx, sample in enumerate(non_sensitive_samples):
        jailbreak_id = sample.get('jailbreak_id')
        related_questions = sample.get('related_questions', [])

        if not related_questions:
            continue

        # 随机选择一个非敏感问题
        non_sensitive_question = random.choice(related_questions)

        # 清除之前的对话历史
        defense_chatbot.clear()

        # 向 Chatbot 提问
        try:
            chatbot_response = defense_chatbot.chat(non_sensitive_question)
        except Exception as e:
            chatbot_response = f"Error: {str(e)}"

        # 使用 LLM Judge 评估可用性
        usability_evaluation = llm_judge_usability(
            JUDGEMODELNAME,
            non_sensitive_question,
            chatbot_response
        )

        # 记录测试结果
        test_result = {
            "jailbreak_id": jailbreak_id,
            "non_sensitive_question": non_sensitive_question,
            "chatbot_response": chatbot_response,
            "usability_evaluation": usability_evaluation
        }
        test_results.append(test_result)

        quality_score = usability_evaluation.get("quality_score", 0)
        quality_scores.append(quality_score)

        # 发送进度信息
        yield {
            "type": "progress",
            "current": idx + 1,
            "total": total,
            "percent": round((idx + 1) / total * 100, 1),
            "last_question": non_sensitive_question[:50] + "..." if len(non_sensitive_question) > 50 else non_sensitive_question,
            "last_score": quality_score
        }

    # 计算统计信息
    total_tests = len(test_results)
    passed_tests = sum(1 for r in test_results if r['usability_evaluation'].get('available', False))
    failed_tests = total_tests - passed_tests
    avg_score = sum(quality_scores) / total_tests if total_tests > 0 else 0

    # 发送完成信息
    yield {
        "type": "complete",
        "total_tests": total_tests,
        "passed_tests": passed_tests,
        "failed_tests": failed_tests,
        "average_quality_score": round(avg_score, 2)
    }


# 延迟初始化，不在导入时初始化
# init_chatbots() 在第一次调用时自动初始化
