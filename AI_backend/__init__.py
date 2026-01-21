"""AI-backend 包"""

from .api import chatbot_bp
from .competition import competition_bp

__all__ = ['chatbot_bp', 'competition_bp']
