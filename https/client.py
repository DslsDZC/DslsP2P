"""
客户端处理器 - 集成encoder功能
"""

import asyncio
import aiohttp
import struct
import json
import base64
import hashlib
import time
import logging
from typing import Dict, List, Any, Optional, Tuple
from session import HTTPSRequestSession
from types.dataclasses import NodeInfo
from message_protocol import MessageProtocol, MessageType

logger = logging.getLogger("HTTPSClient")

class HTTPSClientProcessor:
    """HTTPS客户端处理器 - 集成encoder"""
    
    def __init__(self, node):
        self.node = node
        self.http_client = aiohttp.ClientSession()
        self.active_sessions: Dict[str, HTTPSRequestSession] = {}
        self.message_protocol = MessageProtocol(node.node_id)
    
    async def request_https_url(self, url: str, use_peers: bool = True) -> Dict[str, Any]:
        """发起HTTPS请求"""
        try:
            # 创建会话
            session_id = self._generate_session_id(url)
            session = HTTPSRequestSession(session_id, url, self.node.node_id)
            self.active_sessions[session_id] = session
            
            # 探测资源
            resource_info = await self._probe_resource(url)
            
            # 选择处理模式
            if use_peers and self.node.peer_nodes:
                # 使用对等节点
                result = await self._distribute_to_peers(url, session, resource_info)
            else:
                # 本地处理
                result = await self._process_locally(url, session_id)
            
            # 清理会话
            del self.active_sessions[session_id]
            
            return result
            
        except Exception as e:
            logger.error(f"HTTPS请求失败: {e}")
            return {"status": "error", "error": str(e)}
    
    async def _distribute_to_peers(self, url: str, session: HTTPSRequestSession, 
                                  resource_info: Dict[str, Any]) -> Dict[str, Any]:
        """分配给对等节点"""
        total_size = resource_info.get('content_length', 0)
        supports_range = resource_info.get('supports_range', False)
        
        # 选择对等节点
        selected_peers = self._select_peers(total_size)
        
        if not selected_peers:
            return await self._process_locally(url, session.session_id)
        
        # 为会话创建网络参数
        self.message_protocol.params_manager.create_session(
            session_id=session.session_id,
            total_hops=len(selected_peers) + 1,  # 包括源节点
            total_fragments=len(selected_peers)
        )
        
        # 分配任务
        if supports_range and total_size > 10240:
            await self._assign_range_tasks(url, session, total_size, selected_peers)
        else:
            await self._assign_full_tasks(url, session, len(selected_peers), selected_peers)
        
        # 等待结果
        return await session.wait_for_completion()
    
    async def _assign_range_tasks(self, url: str, session: HTTPSRequestSession, 
                                 total_size: int, peers: List[NodeInfo]):
        """分配范围任务"""
        ranges = self._split_ranges(total_size, len(peers))
        session.expected_tasks = len(ranges)
        
        tasks = []
        for i, peer in enumerate(peers):
            start, end = ranges[i]
            
            # 创建任务数据（包含时间戳编码）
            task_data = {
                "type": "range_request",
                "session_id": session.session_id,
                "url": url,
                "range_start": start,
                "range_end": end,
                "task_id": i,
                "source_node": self.node.node_id,
                "timestamp": time.time(),
                "fragment_index": i
            }
            
            # 编码消息（带时间戳）
            message_bytes = self.message_protocol.encode_message_with_timestamp(
                msg_type=MessageType.HTTPS_TASK,
                data=task_data,
                total_hops=len(peers) + 1,
                current_hop=0,  # 当前是第一跳
                fragment_index=i
            )
            
            task = asyncio.create_task(
                self._send_encoded_task_to_peer(peer, message_bytes, session, i)
            )
            tasks.append(task)
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _send_encoded_task_to_peer(self, 
                                       peer: NodeInfo, 
                                       message_bytes: bytes,
                                       session: HTTPSRequestSession,
                                       task_id: int) -> bool:
        """发送编码后的任务给对等节点"""
        try:
            reader, writer = await asyncio.open_connection(peer.host, peer.port)
            
            # 发送完整消息
            writer.write(message_bytes)
            await writer.drain()
            
            # 接收确认
            ack_data = await reader.read(4)
            ack = struct.unpack('>I', ack_data)[0]
            
            if ack != 1:
                logger.warning(f"节点 {peer.node_id} 拒绝任务")
                writer.close()
                await writer.wait_closed()
                return False
            
            # 接收响应（使用消息协议解码）
            header = await reader.read(8)
            if len(header) < 8:
                logger.warning(f"节点 {peer.node_id} 响应头不完整")
                writer.close()
                await writer.wait_closed()
                return False
            
            msg_type_int, length = struct.unpack('>II', header)
            msg_type = MessageType(msg_type_int)
            
            if msg_type == MessageType.DATA_RETURN:
                resp_bytes = await reader.read(length)
                response = self.message_protocol.decode_message_body(resp_bytes)
                
                if response.get("status") == "success":
                    data = base64.b64decode(response.get("data", ""))
                    range_info = response.get("range", (0, len(data)-1))
                    
                    # 验证响应中的时间戳
                    if "_ts" in response:
                        ts_valid = self.message_protocol.validate_and_update_network_params(
                            response["_ts"],
                            session.session_id
                        )
                        if not ts_valid:
                            logger.warning(f"任务 {task_id} 时间戳验证失败")
                    
                    await session.add_task_result(task_id, data, range_info)
            
            writer.close()
            await writer.wait_closed()
            return True
            
        except Exception as e:
            logger.error(f"发送任务到节点 {peer.node_id} 失败: {e}")
            session.set_error(f"节点 {peer.node_id} 处理失败: {str(e)}")
            return False
        