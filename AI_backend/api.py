"""
Chatbot API 路由
为前端提供 HTTP 接口
"""

from flask import Blueprint, request, jsonify, Response
import json
import os
from .chatbot_service import (
    get_jailbreak_response,
    get_defense_response,
    update_defense,
    clear_jailbreak_history,
    clear_defense_history,
    test_defense_usability,
    test_defense_usability_stream
)

chatbot_bp = Blueprint('chatbot', __name__, url_prefix='/api/chatbot')


@chatbot_bp.route('/jailbreak', methods=['POST'])
def jailbreak_chat():
    """
    越狱挑战接口（NoDefense Chatbot）

    请求体:
        {
            "message": "用户输入"
        }

    返回:
        {
            "response": "机器人回复",
            "status": "success" | "error"
        }
    """
    try:
        data = request.json
        user_input = data.get('message', '').strip()

        if not user_input:
            return jsonify({"status": "error", "message": "输入不能为空"}), 400

        response = get_jailbreak_response(user_input)
        return jsonify({"status": "success", "response": response})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@chatbot_bp.route('/defense', methods=['POST'])
def defense_chat():
    """
    防御挑战接口（MyDefense Chatbot）

    请求体:
        {
            "message": "用户输入"
        }

    返回:
        {
            "response": "机器人回复",
            "status": "success" | "error"
        }
    """
    try:
        data = request.json
        user_input = data.get('message', '').strip()

        if not user_input:
            return jsonify({"status": "error", "message": "输入不能为空"}), 400

        response = get_defense_response(user_input)
        return jsonify({"status": "success", "response": response})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@chatbot_bp.route('/update-defense', methods=['POST'])
def update_defense_endpoint():
    """
    更新防御设置接口

    返回:
        {
            "status": "success" | "error",
            "message": "更新信息"
        }
    """
    try:
        result = update_defense()
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@chatbot_bp.route('/clear-jailbreak', methods=['POST'])
def clear_jailbreak():
    """清除越狱 Chatbot 的对话历史"""
    try:
        clear_jailbreak_history()
        return jsonify({"status": "success", "message": "越狱对话历史已清除"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@chatbot_bp.route('/clear-defense', methods=['POST'])
def clear_defense():
    """清除防御 Chatbot 的对话历史"""
    try:
        clear_defense_history()
        return jsonify({"status": "success", "message": "防御对话历史已清除"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@chatbot_bp.route('/jailbreak-samples', methods=['GET'])
def get_jailbreak_samples():
    """获取越狱样本列表"""
    try:
        # 获取 jailbreak_samples.json 文件路径
        samples_path = os.path.join(os.path.dirname(__file__), '..', 'AI', 'jailbreak_samples.json')

        if not os.path.exists(samples_path):
            return jsonify({"status": "error", "message": "样本文件不存在"}), 404

        with open(samples_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        return jsonify({
            "status": "success",
            "samples": data.get("jailbreak samples", [])
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@chatbot_bp.route('/test-usability', methods=['POST'])
def test_usability_endpoint():
    """
    测试防御 Chatbot 可用性接口

    返回:
        {
            "status": "success" | "error",
            "data": {
                "total_tests": int,
                "passed_tests": int,
                "failed_tests": int,
                "average_quality_score": float,
                "test_results": [...]
            }
        }
    """
    try:
        result = test_defense_usability()
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@chatbot_bp.route('/test-usability-stream', methods=['GET'])
def test_usability_stream_endpoint():
    """
    流式测试防御 Chatbot 可用性接口 (SSE)

    返回: Server-Sent Events 流
    """
    def generate():
        try:
            for progress in test_defense_usability_stream():
                yield f"data: {json.dumps(progress, ensure_ascii=False)}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)}, ensure_ascii=False)}\n\n"

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )
