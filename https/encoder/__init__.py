"""
TCP时间戳伪装系统 - 与P2P节点集成
"""

import time
from .compact32_encoder import Compact32Encoder
from .tcp_timestamp_builder import TCPTimestampBuilder
from .network_params import NetworkParamsManager
from .timestamp_validator import TimestampValidator

class P2PEncoderIntegration:
    """P2P节点编码器集成类"""
    
    def __init__(self, node_id: str = ""):
        self.encoder = Compact32Encoder()
        self.builder = TCPTimestampBuilder(self.encoder)
        self.params_manager = NetworkParamsManager()
        self.validator = TimestampValidator()
        self.node_id = node_id
    
    def create_task_with_encoding(self, task_data: dict, fragment_index: int = 0) -> dict:
        """创建带编码信息的任务数据"""
        # 创建会话（如果不存在）
        session_id = task_data.get("session_id", f"session_{int(time.time())}")
        if not self.params_manager.current_session:
            self.params_manager.create_session(
                session_id=session_id,
                total_hops=task_data.get("total_hops", 4),
                total_fragments=task_data.get("total_fragments", 1)
            )
        
        # 获取编码参数
        total_hops, current_hop, frag_idx = self.params_manager.get_timestamp_params(
            fragment_index
        )
        
        # 编码时间戳
        encoded_ts = self.encoder.encode(
            real_timestamp=int(time.time()),
            total_hops=total_hops,
            current_hop=current_hop,
            fragment_index=frag_idx
        )
        
        # 更新任务数据
        task_data.update({
            "_encoded_ts": encoded_ts,
            "_encoder_version": self.encoder.VERSION,
            "_fragment_index": frag_idx,
            "_current_hop": current_hop,
            "_total_hops": total_hops
        })
        
        return task_data
    
    def decode_and_validate_response(self, response_data: dict) -> tuple:
        """解码和验证响应数据"""
        encoded_ts = response_data.get("_encoded_ts")
        if not encoded_ts:
            return response_data, False
        
        # 验证时间戳
        if not self.validator.is_plausible_timestamp(encoded_ts, self.encoder):
            return response_data, False
        
        # 解码时间戳
        ts_info = self.encoder.decode(encoded_ts)
        
        # 更新网络参数
        session_id = response_data.get("session_id")
        if session_id and self.params_manager.current_session:
            session = self.params_manager.current_session
            session.increment_hop()
            session.mark_fragment_received(ts_info["fragment_index"])
        
        # 将解码信息添加到响应数据
        response_data["_ts_decoded"] = ts_info
        
        return response_data, True

# 导出主要类
__all__ = [
    'Compact32Encoder',
    'TCPTimestampBuilder',
    'NetworkParamsManager',
    'TimestampValidator',
    'P2PEncoderIntegration',
    'MessageProtocol'
]
