"""
会话管理
"""

import asyncio
import hashlib
import time
from typing import Dict, List, Any, Optional

class HTTPSRequestSession:
    """HTTPS请求会话"""
    
    def __init__(self, session_id: str, url: str, source_node: str):
        self.session_id = session_id
        self.url = url
        self.source_node = source_node
        self.created_at = time.time()
        
        # 数据收集
        self.received_data: Dict[int, Dict] = {}
        self.expected_tasks = 0
        self.completed_tasks = 0
        
        # 同步事件
        self.completion_event = asyncio.Event()
        self.result_data: Optional[bytes] = None
        self.error: Optional[str] = None
    
    async def add_task_result(self, task_id: int, data: bytes, range_info: tuple):
        """添加任务结果"""
        self.received_data[task_id] = {
            "data": data,
            "range": range_info,
            "timestamp": time.time()
        }
        self.completed_tasks += 1
        
        # 检查是否完成
        if self.completed_tasks >= self.expected_tasks:
            self.result_data = self._reassemble_data()
            self.completion_event.set()
    
    def set_error(self, error: str):
        """设置错误"""
        self.error = error
        self.completion_event.set()
    
    def _reassemble_data(self) -> bytes:
        """重组数据"""
        if not self.received_data:
            return b""
        
        # 按任务ID排序
        sorted_tasks = sorted(self.received_data.items(), key=lambda x: x[0])
        
        # 合并数据
        reassembled = bytearray()
        for task_id, task_data in sorted_tasks:
            reassembled.extend(task_data['data'])
        
        return bytes(reassembled)
    
    async def wait_for_completion(self, timeout: int = 60) -> Dict[str, Any]:
        """等待完成"""
        try:
            await asyncio.wait_for(self.completion_event.wait(), timeout)
            
            if self.error:
                return {
                    "status": "error",
                    "error": self.error,
                    "completed_tasks": self.completed_tasks,
                    "expected_tasks": self.expected_tasks,
                    "duration": time.time() - self.created_at
                }
            
            return {
                "status": "completed",
                "data": self.result_data,
                "total_tasks": self.expected_tasks,
                "completed_tasks": self.completed_tasks,
                "duration": time.time() - self.created_at
            }
        except asyncio.TimeoutError:
            return {
                "status": "timeout",
                "completed_tasks": self.completed_tasks,
                "expected_tasks": self.expected_tasks,
                "duration": time.time() - self.created_at
            }
        