"""
消息协议定义 - 集成encoder编码功能
"""

import struct
import json
import time
import base64
from enum import IntEnum
from typing import Dict, Any, Tuple, Optional
from encoder import compact32_encoder, tcp_timestamp_builder, network_params, timestamp_validator

logger = logging.getLogger("MessageProtocol")

class MessageType(IntEnum):
    """消息类型枚举"""
    DISCOVERY = 1      # 节点发现
    HTTPS_TASK = 2     # HTTPS任务
    DATA_RETURN = 3    # 数据返回
    HEARTBEAT = 4      # 心跳
    ERROR = 5          # 错误
    TIMESTAMP_SYNC = 6 # 时间戳同步

class MessageProtocol:
    """消息协议处理器 - 集成编码功能"""
    
    def __init__(self, node_id: str = ""):
        self.encoder = compact32_encoder.Compact32Encoder()
        self.timestamp_builder = tcp_timestamp_builder.TCPTimestampBuilder(self.encoder)
        self.params_manager = network_params.NetworkParamsManager()
        self.validator = timestamp_validator.TimestampValidator()
        self.node_id = node_id
    
    @staticmethod
    def encode_message(msg_type: MessageType, data: Dict[str, Any]) -> bytes:
        """编码消息 - 基本版本"""
        data_bytes = json.dumps(data).encode()
        return struct.pack('>II', msg_type, len(data_bytes)) + data_bytes
    
    def encode_message_with_timestamp(self, 
                                    msg_type: MessageType, 
                                    data: Dict[str, Any],
                                    total_hops: int = 2,
                                    current_hop: int = 0,
                                    fragment_index: int = 0) -> bytes:
        """编码消息并添加时间戳信息"""
        # 获取时间戳参数
        timestamp_params = self.params_manager.get_timestamp_params(fragment_index)
        if timestamp_params:
            total_hops, current_hop, fragment_index = timestamp_params
        
        # 创建时间戳
        encoded_timestamp = self.encoder.encode(
            real_timestamp=int(time.time()),
            total_hops=total_hops,
            current_hop=current_hop,
            fragment_index=fragment_index
        )
        
        # 在数据中添加时间戳信息
        data_with_ts = data.copy()
        data_with_ts.update({
            "_ts": encoded_timestamp,
            "_ts_info": {
                "total_hops": total_hops,
                "current_hop": current_hop,
                "fragment_index": fragment_index,
                "source": self.node_id
            }
        })
        
        return self.encode_message(msg_type, data_with_ts)
    
    @staticmethod
    def decode_message_header(header: bytes) -> Tuple[MessageType, int]:
        """解码消息头"""
        if len(header) < 8:
            raise ValueError("消息头长度不足")
        
        msg_type_int, length = struct.unpack('>II', header)
        return MessageType(msg_type_int), length
    
    def decode_message_body(self, body: bytes) -> Dict[str, Any]:
        """解码消息体 - 解析时间戳信息"""
        data = json.loads(body.decode())
        
        # 检查是否有时间戳信息
        if "_ts" in data:
            encoded_timestamp = data["_ts"]
            
            # 验证时间戳
            if self.validator.is_plausible_timestamp(encoded_timestamp, self.encoder):
                # 解码时间戳
                ts_info = self.encoder.decode(encoded_timestamp)
                data["_ts_decoded"] = ts_info
                
                # 处理网络参数
                params_info = self.params_manager.process_incoming_timestamp(
                    encoded_timestamp, self.encoder
                )
                if "error" not in params_info:
                    data["_network_params"] = params_info
            else:
                logger.warning(f"无效的时间戳: {encoded_timestamp}")
                data["_ts_valid"] = False
        
        return data
    
    def create_tcp_timestamp_option(self,
                                  session_id: str,
                                  fragment_index: int = 0,
                                  extended: bool = False) -> bytes:
        """创建TCP时间戳选项"""
        # 获取或创建会话
        if not self.params_manager.current_session:
            # 创建临时会话
            session = self.params_manager.create_session(
                session_id=session_id,
                total_hops=4,  # 默认总跳数
                total_fragments=8  # 默认总分片数
            )
        
        # 获取当前参数
        total_hops, current_hop, frag_idx = self.params_manager.get_timestamp_params(
            fragment_index
        )
        
        # 构建TCP选项
        if extended:
            return self.timestamp_builder.create_extended_option(
                total_hops=total_hops,
                current_hop=current_hop,
                fragment_index=frag_idx,
                session_id=hash(session_id) & 0xFF  # 会话ID哈希
            )
        else:
            return self.timestamp_builder.build_timestamp_option(
                total_hops=total_hops,
                current_hop=current_hop,
                fragment_index=frag_idx
            )
    
    def validate_and_update_network_params(self, 
                                         encoded_timestamp: int,
                                         session_id: str = "") -> bool:
        """验证时间戳并更新网络参数"""
        if not self.validator.is_plausible_timestamp(encoded_timestamp, self.encoder):
            return False
        
        # 解码时间戳
        info = self.encoder.decode(encoded_timestamp)
        
        # 更新网络参数管理器
        if session_id and self.params_manager.current_session:
            session = self.params_manager.current_session
            if info["current_hop"] < info["total_hops"] - 1:
                # 增加跳数
                session.increment_hop()
            
            # 标记分片已接收
            session.mark_fragment_received(info["fragment_index"])
        
        return True