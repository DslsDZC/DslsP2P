"""
节点主类 - 集成encoder功能
"""

import asyncio
import socket
import struct
import json
import logging
import time
from typing import Dict, List, Any, Optional
from types.dataclasses import NodeInfo
from types.enums import NodeType
from client import HTTPSClientProcessor
from server import HTTPSRequestHandler
from performance import PerformanceMonitor
from message_protocol import MessageProtocol, MessageType

logger = logging.getLogger("P2PNode")

class P2PNode:
    """P2P节点 - 集成encoder功能"""
    
    def __init__(self, node_id: str, host: str, port: int, config: Dict[str, Any] = None):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.config = config or {}
        
        # 节点类型
        self.node_type = NodeType.D_NODE
        
        # 对等节点列表
        self.peer_nodes: Dict[str, NodeInfo] = {}
        
        # 网络组件
        self.client_processor: Optional[HTTPSClientProcessor] = None
        self.server_handler: Optional[HTTPSRequestHandler] = None
        self.message_protocol = MessageProtocol(node_id)
        
        # 性能监控
        self.performance_monitor = PerformanceMonitor()
        
        # 运行状态
        self.is_running = False
        self.tcp_server = None
        
        # 添加初始节点
        self._add_initial_peers()
    
    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理传入连接，集成encoder功能"""
        try:
            # 读取消息类型（4字节）
            msg_type_data = await reader.read(4)
            if not msg_type_data:
                return
            
            # 检查是否是心跳或其他控制消息
            if len(msg_type_data) == 4:
                msg_type_int = struct.unpack('>I', msg_type_data)[0]
                msg_type = MessageType(msg_type_int)
                
                # 读取消息长度
                length_data = await reader.read(4)
                if not length_data or len(length_data) < 4:
                    logger.warning("消息长度不完整")
                    return
                
                data_length = struct.unpack('>I', length_data)[0]
                
                # 根据消息类型处理
                if msg_type == MessageType.HEARTBEAT:
                    # 心跳消息可能很短
                    if data_length > 0:
                        data_bytes = await reader.read(min(data_length, 1024))
                        await self._handle_heartbeat(data_bytes, writer)
                elif msg_type == MessageType.HTTPS_TASK:
                    # HTTPS任务消息
                    if data_length > 0 and data_length < 10 * 1024 * 1024:  # 限制10MB
                        data_bytes = await reader.read(data_length)
                        await self.server_handler.handle_encoded_https_task(
                            reader, writer, msg_type_data + length_data + data_bytes
                        )
                elif msg_type == MessageType.DATA_RETURN:
                    # 数据返回消息
                    if data_length > 0 and data_length < 10 * 1024 * 1024:
                        data_bytes = await reader.read(data_length)
                        await self._handle_data_return(data_bytes, writer)
                else:
                    logger.warning(f"未知消息类型: {msg_type}")
                    
        except asyncio.CancelledError:
            logger.info("连接处理被取消")
        except Exception as e:
            logger.error(f"连接处理失败: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def request_https_with_encoder(self, url: str, use_peers: bool = True) -> Dict[str, Any]:
        """发起HTTPS请求，使用encoder编码"""
        if not self.client_processor:
            return {"status": "error", "error": "客户端处理器未初始化"}
        
        # 编码请求信息
        request_info = {
            "url": url,
            "source_node": self.node_id,
            "timestamp": time.time(),
            "use_encoder": True
        }
        
        # 使用encoder进行编码（可选）
        encoded_info = self.message_protocol.encoder.encode(
            real_timestamp=int(time.time()),
            total_hops=4,  # 默认值
            current_hop=0,
            fragment_index=0
        )
        request_info["encoded_ts"] = encoded_info
        
        # 传递给客户端处理器
        return await self.client_processor.request_https_url(url, use_peers)
    