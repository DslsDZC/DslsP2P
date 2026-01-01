"""
数据类定义
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime

@dataclass
class NodeInfo:
    """节点信息"""
    node_id: str
    host: str
    port: int
    node_type: str = "D_NODE"
    last_seen: float = 0
    status: str = "offline"
    capabilities: Dict[str, Any] = field(default_factory=dict)
    reputation: int = 1000

@dataclass
class HTTPSRequest:
    """HTTPS请求"""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    timestamp: float = 0

@dataclass
class TaskAssignment:
    """任务分配"""
    task_id: int
    session_id: str
    url: str
    range_start: int = 0
    range_end: int = 0
    task_type: str = "full_request"
    source_node: str = ""
    timestamp: float = 0

@dataclass
class FragmentData:
    """分片数据"""
    session_id: str
    fragment_index: int
    total_fragments: int
    data: bytes
    range_info: Tuple[int, int] = (0, 0)
    checksum: str = ""
    timestamp: float = 0
    