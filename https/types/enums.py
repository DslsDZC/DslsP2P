"""
枚举定义
"""

from enum import Enum

class NodeType(Enum):
    """节点类型"""
    D_NODE = "D节点"  # 全功能节点
    U_NODE = "U节点"  # 受限功能节点
    R_NODE = "R节点"  # 中继依赖节点

class FragmentPriority(Enum):
    """分片优先级"""
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    BACKGROUND = 0

class RequestType(Enum):
    """请求类型"""
    HTTPS = "https"
    HTTP = "http"
    OTHER = "other"

class MessageType(Enum):
    """消息类型"""
    DISCOVERY = 1
    HTTPS_TASK = 2
    DATA_RETURN = 3
    HEARTBEAT = 4
    ERROR = 5
    