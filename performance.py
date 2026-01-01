"""
性能监控
"""

import time
import asyncio
from collections import deque
from typing import Dict, List, Any

class PerformanceMonitor:
    """性能监控器"""
    
    def __init__(self):
        self.metrics = {
            "requests": deque(maxlen=1000),
            "latency": deque(maxlen=1000),
            "errors": deque(maxlen=100),
            "node_performance": {}
        }
        self.start_time = time.time()
        self.is_monitoring = False
    
    async def start_monitoring(self):
        """启动监控"""
        self.is_monitoring = True
        
    def record_request(self, url: str, duration: float, success: bool):
        """记录请求"""
        self.metrics["requests"].append({
            "url": url,
            "timestamp": time.time(),
            "duration": duration,
            "success": success
        })
    
    def record_latency(self, peer_id: str, latency: float):
        """记录延迟"""
        self.metrics["latency"].append({
            "peer_id": peer_id,
            "latency": latency,
            "timestamp": time.time()
        })
    
    def record_error(self, error_type: str, details: str = ""):
        """记录错误"""
        self.metrics["errors"].append({
            "type": error_type,
            "details": details,
            "timestamp": time.time()
        })
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        latencies = [m["latency"] for m in self.metrics["latency"]]
        
        return {
            "uptime": time.time() - self.start_time,
            "total_requests": len(self.metrics["requests"]),
            "success_rate": self._calculate_success_rate(),
            "avg_latency": sum(latencies) / len(latencies) if latencies else 0,
            "error_count": len(self.metrics["errors"])
        }
    
    def _calculate_success_rate(self) -> float:
        """计算成功率"""
        if not self.metrics["requests"]:
            return 0.0
        
        successful = sum(1 for r in self.metrics["requests"] if r["success"])
        return successful / len(self.metrics["requests"])
    