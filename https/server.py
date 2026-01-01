"""
服务器处理器 - 集成encoder功能
"""

import asyncio
import aiohttp
import struct
import json
import base64
import logging
import time
from typing import Dict, Any
from message_protocol import MessageProtocol, MessageType

logger = logging.getLogger("HTTPServer")

class HTTPSRequestHandler:
    """HTTPS请求处理器 - 集成encoder"""
    
    def __init__(self, node):
        self.node = node
        self.http_client = aiohttp.ClientSession()
        self.message_protocol = MessageProtocol(node.node_id)
    
    async def handle_encoded_https_task(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理编码的HTTPS任务"""
        try:
            # 读取消息头
            header = await reader.read(8)
            if len(header) < 8:
                logger.warning("消息头不完整")
                return
            
            msg_type_int, length = struct.unpack('>II', header)
            msg_type = MessageType(msg_type_int)
            
            if msg_type != MessageType.HTTPS_TASK:
                logger.warning(f"非HTTPS任务消息: {msg_type}")
                return
            
            # 读取消息体
            body_bytes = await reader.read(length)
            
            # 解码消息（包含时间戳验证）
            task_data = self.message_protocol.decode_message_body(body_bytes)
            
            # 验证时间戳
            ts_valid = False
            if "_ts" in task_data:
                ts_valid = self.message_protocol.validate_and_update_network_params(
                    task_data["_ts"],
                    task_data.get("session_id", "")
                )
            
            if not ts_valid and "_ts" in task_data:
                logger.warning(f"任务时间戳验证失败: {task_data.get('session_id', 'unknown')}")
            
            # 发送确认
            writer.write(struct.pack('>I', 1))
            await writer.drain()
            
            # 处理任务
            task_type = task_data.get('type')
            
            # 更新网络参数中的当前跳数
            if "_network_params" in task_data:
                net_params = task_data["_network_params"]
                current_hop = net_params.get("current_hop", 0) + 1
                fragment_index = net_params.get("fragment_index", 0)
                
                # 创建响应时使用更新后的跳数
                task_data["_current_hop"] = current_hop
                task_data["_fragment_index"] = fragment_index
            
            if task_type == 'range_request':
                await self._process_range_request_with_timestamp(task_data, writer)
            elif task_type == 'full_request':
                await self._process_full_request_with_timestamp(task_data, writer)
            else:
                await self._send_error_response(writer, task_data, "未知任务类型")
        
        except Exception as e:
            logger.error(f"处理编码任务失败: {e}")
            await self._send_error_response(writer, {}, str(e))
    
    async def _process_range_request_with_timestamp(self, task_data: Dict[str, Any], writer: asyncio.StreamWriter):
        """处理带时间戳的范围请求"""
        try:
            url = task_data['url']
            start = task_data['range_start']
            end = task_data['range_end']
            task_id = task_data.get('task_id', 0)
            
            # 发送范围请求
            headers = {'Range': f'bytes={start}-{end}'}
            
            async with self.http_client.get(url, headers=headers, ssl=False) as response:
                if response.status in (200, 206):
                    data = await response.read()
                    
                    # 构建响应数据（包含时间戳）
                    response_data = {
                        "type": "range_response",
                        "session_id": task_data['session_id'],
                        "task_id": task_id,
                        "status": "success",
                        "data": base64.b64encode(data).decode(),
                        "range": (start, start + len(data) - 1),
                        "timestamp": time.time()
                    }
                    
                    # 添加时间戳编码
                    current_hop = task_data.get("_current_hop", 1)
                    fragment_index = task_data.get("_fragment_index", task_id)
                    
                    # 编码响应消息
                    message_bytes = self.message_protocol.encode_message_with_timestamp(
                        msg_type=MessageType.DATA_RETURN,
                        data=response_data,
                        total_hops=4,  # 默认值
                        current_hop=current_hop,
                        fragment_index=fragment_index
                    )
                    
                    writer.write(message_bytes)
                    await writer.drain()
                    
                else:
                    # 回退到完整请求
                    await self._fallback_full_request_with_timestamp(task_data, writer, start, end)
        
        except Exception as e:
            logger.error(f"范围请求处理失败: {e}")
            await self._send_encoded_error_response(writer, task_data, str(e))
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def _send_encoded_error_response(self, writer: asyncio.StreamWriter, task_data: Dict[str, Any], error: str):
        """发送编码的错误响应"""
        try:
            error_data = {
                "type": "error",
                "session_id": task_data.get('session_id', ''),
                "task_id": task_data.get('task_id', 0),
                "status": "error",
                "error": error,
                "timestamp": time.time()
            }
            
            message_bytes = self.message_protocol.encode_message_with_timestamp(
                msg_type=MessageType.ERROR,
                data=error_data,
                total_hops=4,
                current_hop=1,
                fragment_index=0
            )
            
            writer.write(message_bytes)
            await writer.drain()
            
        except Exception as e:
            logger.error(f"发送编码错误响应失败: {e}")
            