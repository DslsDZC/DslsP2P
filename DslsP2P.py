#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import time
import json
import os
import hashlib
import struct
import random
import requests
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
import argparse
from urllib.parse import urlparse, urljoin
from collections import defaultdict
import re
import ipaddress
import sys
import select
import queue

# 尝试导入 Selenium
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

class MessageType(Enum):
    """消息类型枚举"""
    NODE_REGISTER = 1
    NODE_LIST = 2
    ANON_REQUEST = 3
    ANON_RESPONSE = 4
    DATA_RELAY = 5
    HEARTBEAT = 7
    ERROR = 99

class AnonP2PProtocol:
    """匿名P2P通信协议"""
    
    HEADER_FORMAT = '!IBI'  # 总长度(4B) + 消息类型(1B) + 序列号(4B)
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
    
    @staticmethod
    def create_message(msg_type: MessageType, data: bytes, seq_num: int = 0):
        """创建消息"""
        header = struct.pack(AnonP2PProtocol.HEADER_FORMAT, 
                           len(data) + AnonP2PProtocol.HEADER_SIZE, 
                           msg_type.value, seq_num)
        return header + data
    
    @staticmethod
    def parse_header(data):
        """解析消息头"""
        if len(data) < AnonP2PProtocol.HEADER_SIZE:
            raise ValueError(f"Header data too short: {len(data)} bytes")
        return struct.unpack(AnonP2PProtocol.HEADER_FORMAT, data[:AnonP2PProtocol.HEADER_SIZE])

class LogManager:
    """日志管理器 - 分离命令和日志"""
    
    def __init__(self, log_file=None):
        self.log_queue = queue.Queue()
        self.log_file = log_file
        self.running = True
        
        # 启动日志处理线程
        self.log_thread = threading.Thread(target=self._log_processor, daemon=True)
        self.log_thread.start()
        
        # 如果指定了日志文件，创建文件
        if log_file:
            try:
                with open(log_file, 'w', encoding='utf-8') as f:
                    f.write(f"=== P2P网络日志 - 开始时间: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
            except:
                pass
    
    def log(self, message):
        """添加日志到队列"""
        if self.running:
            timestamp = time.strftime('%H:%M:%S')
            log_entry = f"[{timestamp}] {message}"
            self.log_queue.put(log_entry)
    
    def _log_processor(self):
        """日志处理线程 - 专门负责输出日志"""
        while self.running:
            try:
                # 从队列获取日志，最多等待1秒
                log_entry = self.log_queue.get(timeout=1)
                
                # 输出到控制台
                print(log_entry)
                
                # 输出到文件（如果指定）
                if self.log_file:
                    try:
                        with open(self.log_file, 'a', encoding='utf-8') as f:
                            f.write(log_entry + '\n')
                    except:
                        pass
                
                self.log_queue.task_done()
                
            except queue.Empty:
                continue
            except:
                break
    
    def stop(self):
        """停止日志管理器"""
        self.running = False
        # 等待队列中的日志处理完毕
        self.log_queue.join()

# 全局日志管理器
log_manager = None

def get_logger():
    """获取日志管理器"""
    global log_manager
    if log_manager is None:
        log_manager = LogManager()
    return log_manager

class NetworkHelper:
    """网络帮助类"""
    
    @staticmethod
    def get_local_ip():
        """获取本地IP地址"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    @staticmethod
    def get_broadcast_address(ip=None):
        """获取广播地址"""
        if ip is None:
            ip = NetworkHelper.get_local_ip()
        
        try:
            if ip.startswith('172.') and ip.count('.') == 3:
                parts = ip.split('.')
                return f"{parts[0]}.{parts[1]}.{parts[2]}.255"
            elif ip.startswith('192.168.'):
                parts = ip.split('.')
                return f"{parts[0]}.{parts[1]}.{parts[2]}.255"
            elif ip.startswith('10.'):
                parts = ip.split('.')
                return f"{parts[0]}.{parts[1]}.255.255"
            else:
                return "255.255.255.255"
        except:
            return "255.255.255.255"

class BrowserEngine:
    """浏览器引擎"""
    
    def __init__(self):
        self.driver = None
        self.initialized = False
        self.init_browser()
    
    def init_browser(self):
        """初始化浏览器"""
        if not SELENIUM_AVAILABLE:
            get_logger().log("[浏览器] 警告: Selenium 不可用，请安装: pip install selenium")
            return False
        
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-extensions")
            chrome_options.add_argument("--disable-default-apps")
            chrome_options.add_argument("--disable-infobars")
            chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            
            try:
                self.driver = webdriver.Chrome(options=chrome_options)
            except:
                try:
                    from selenium.webdriver.chrome.service import Service
                    service = Service()
                    self.driver = webdriver.Chrome(service=service, options=chrome_options)
                except:
                    get_logger().log("[浏览器] 错误: 无法启动Chrome浏览器")
                    return False
            
            self.driver.set_page_load_timeout(30)
            self.driver.set_script_timeout(30)
            
            self.initialized = True
            get_logger().log("[浏览器] Chrome浏览器引擎初始化成功")
            return True
            
        except Exception as e:
            get_logger().log(f"[浏览器] 初始化失败: {e}")
            return False
    
    def load_page_with_browser(self, url, wait_time=5):
        """使用浏览器加载页面"""
        if not self.initialized or not self.driver:
            get_logger().log("[浏览器] 浏览器引擎未初始化")
            return None
        
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            get_logger().log(f"[浏览器] 加载页面: {url}")
            
            self.driver.get(url)
            
            WebDriverWait(self.driver, wait_time).until(
                lambda driver: driver.execute_script("return document.readyState") == "complete"
            )
            
            page_source = self.driver.page_source
            current_url = self.driver.current_url
            title = self.driver.title
            
            get_logger().log(f"[浏览器] 页面加载成功: {title}")
            get_logger().log(f"[浏览器] 最终URL: {current_url}")
            get_logger().log(f"[浏览器] 页面大小: {len(page_source)} 字符")
            
            return {
                'success': True,
                'url': current_url,
                'title': title,
                'content': page_source.encode('utf-8'),
                'content_type': 'text/html',
                'loaded_with_browser': True
            }
            
        except TimeoutException:
            get_logger().log(f"[浏览器] 页面加载超时: {url}")
            return {
                'success': False,
                'url': url,
                'error': '页面加载超时'
            }
        except Exception as e:
            get_logger().log(f"[浏览器] 页面加载失败: {e}")
            return {
                'success': False,
                'url': url,
                'error': str(e)
            }
    
    def close(self):
        """关闭浏览器"""
        if self.driver:
            try:
                self.driver.quit()
                get_logger().log("[浏览器] 浏览器已关闭")
            except:
                pass

class AnonymousWebClient:
    """匿名网页客户端"""
    
    def __init__(self, enable_browser=True):
        self.session = requests.Session()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
        ]
        
        self.browser_engine = None
        if enable_browser:
            self.browser_engine = BrowserEngine()
    
    def fetch_anonymously(self, url, use_browser=False, timeout=10):
        """获取网页内容"""
        if use_browser and self.browser_engine and self.browser_engine.initialized:
            result = self.browser_engine.load_page_with_browser(url)
            if result and result['success']:
                return result
            else:
                get_logger().log("[网页] 浏览器引擎失败，回退到普通请求")
        
        # 普通HTTP请求
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            headers = {
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            }
            
            get_logger().log(f"[网页] 普通请求: {url}")
            
            response = self.session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            
            if response.status_code == 200:
                content = response.content
                content_type = response.headers.get('Content-Type', '')
                
                get_logger().log(f"[网页] 获取成功: {len(content)} 字节")
                
                return {
                    'success': True,
                    'url': url,
                    'content': content,
                    'content_type': content_type,
                    'status_code': 200,
                    'loaded_with_browser': False
                }
            else:
                get_logger().log(f"[网页] 获取失败, 状态码: {response.status_code}")
                return {
                    'success': False,
                    'url': url,
                    'status_code': response.status_code,
                    'error': f"HTTP {response.status_code}",
                    'loaded_with_browser': False
                }
                
        except Exception as e:
            get_logger().log(f"[网页] 获取URL失败: {e}")
            return {
                'success': False,
                'url': url,
                'error': str(e),
                'loaded_with_browser': False
            }
    
    def close(self):
        """关闭资源"""
        if self.browser_engine:
            self.browser_engine.close()

class AnonymousP2PNode:
    """匿名P2P节点"""
    
    def __init__(self, node_id=None, tcp_port=8889, udp_port=8888, enable_browser=True):
        self.node_id = node_id or self._generate_node_id()
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        
        # 核心组件
        self.web_client = AnonymousWebClient(enable_browser=enable_browser)
        
        # 节点状态
        self.known_nodes = {}
        self.active_requests = {}
        self.node_counter = 0
        self.enable_browser = enable_browser
        
        # 网络组件
        self.udp_listener = None
        self.tcp_socket = None
        self.running = False
        
        # 线程池
        self.thread_pool = ThreadPoolExecutor(max_workers=10)
        
        get_logger().log(f"[系统] 匿名P2P节点 {self.node_id} 初始化完成")
        get_logger().log(f"[网络] TCP端口: {tcp_port}, UDP端口: {udp_port}")
        get_logger().log(f"[IP] 本地IP: {NetworkHelper.get_local_ip()}")
        if enable_browser:
            status = "可用" if (self.web_client.browser_engine and self.web_client.browser_engine.initialized) else "不可用"
            get_logger().log(f"[浏览器] 浏览器引擎: {status}")
    
    def _generate_node_id(self):
        """生成节点ID"""
        return f"node_{int(time.time())}_{random.randint(1000, 9999)}"
    
    def start(self):
        """启动节点"""
        self.running = True
        
        # 启动UDP监听器
        udp_thread = threading.Thread(target=self._start_udp_listener, daemon=True)
        udp_thread.start()
        
        # 启动TCP服务器
        tcp_thread = threading.Thread(target=self._start_tcp_server, daemon=True)
        tcp_thread.start()
        
        # 启动节点发现
        advertise_thread = threading.Thread(target=self._advertise_periodically, daemon=True)
        advertise_thread.start()
        
        # 启动维护线程
        maintenance_thread = threading.Thread(target=self._maintenance_loop, daemon=True)
        maintenance_thread.start()
        
        get_logger().log(f"[系统] 节点启动成功，等待其他节点...")
    
    def _start_udp_listener(self):
        """启动UDP监听器"""
        self.udp_listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_listener.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.udp_listener.bind(('0.0.0.0', self.udp_port))
        self.udp_listener.settimeout(1.0)
        
        get_logger().log(f"[UDP] 开始监听UDP端口 {self.udp_port}")
        
        while self.running:
            try:
                data, addr = self.udp_listener.recvfrom(1024)
                self._handle_udp_message(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    get_logger().log(f"[UDP错误] 接收错误: {e}")
    
    def _start_tcp_server(self):
        """启动TCP服务器"""
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_socket.bind(('0.0.0.0', self.tcp_port))
        self.tcp_socket.listen(5)
        self.tcp_socket.settimeout(1.0)
        
        get_logger().log(f"[TCP] 开始监听TCP端口 {self.tcp_port}")
        
        while self.running:
            try:
                client_sock, addr = self.tcp_socket.accept()
                if addr[0] not in ['127.0.0.1', 'localhost']:
                    self.thread_pool.submit(self._handle_tcp_connection, client_sock, addr)
                else:
                    client_sock.close()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    get_logger().log(f"[TCP错误] 接受连接错误: {e}")
    
    def _advertise_periodically(self):
        """定期广播节点信息"""
        time.sleep(2)
        
        broadcast_count = 0
        while self.running:
            try:
                self._broadcast_presence()
                broadcast_count += 1
                
                if broadcast_count % 10 == 0:
                    get_logger().log(f"[广播] 已发送 {broadcast_count} 次广播，发现 {len(self.known_nodes)} 个节点")
                
                time.sleep(5)
            except Exception as e:
                if self.running:
                    get_logger().log(f"[广播错误] 发送失败: {e}")
    
    def _maintenance_loop(self):
        """维护循环"""
        while self.running:
            try:
                self._cleanup_expired_nodes()
                time.sleep(30)
            except Exception as e:
                get_logger().log(f"[维护错误] {e}")
    
    def _cleanup_expired_nodes(self):
        """清理过期节点"""
        current_time = time.time()
        expired_nodes = []
        
        for node_id, (ip, port, last_seen) in self.known_nodes.items():
            if current_time - last_seen > 60:
                expired_nodes.append(node_id)
        
        for node_id in expired_nodes:
            del self.known_nodes[node_id]
            get_logger().log(f"[清理] 移除过期节点: {node_id}")
    
    def _broadcast_presence(self):
        """广播节点存在信息"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            message = {
                'type': 'node_announce',
                'node_id': self.node_id,
                'ip': NetworkHelper.get_local_ip(),
                'tcp_port': self.tcp_port,
                'timestamp': time.time(),
                'capabilities': {
                    'browser_engine': self.enable_browser and self.web_client.browser_engine and self.web_client.browser_engine.initialized
                }
            }
            
            data = json.dumps(message).encode()
            broadcast_addr = NetworkHelper.get_broadcast_address()
            sock.sendto(data, (broadcast_addr, self.udp_port))
            
            sock.close()
            
        except Exception as e:
            get_logger().log(f"[广播错误] {e}")
    
    def _handle_udp_message(self, data, addr):
        """处理UDP消息"""
        try:
            message = json.loads(data.decode())
            
            if message.get('type') == 'node_announce':
                node_id = message.get('node_id')
                node_ip = addr[0]
                tcp_port = message.get('tcp_port')
                capabilities = message.get('capabilities', {})
                
                if node_id != self.node_id:
                    if node_id not in self.known_nodes:
                        self.known_nodes[node_id] = (node_ip, tcp_port, time.time())
                        self.node_counter += 1
                        browser_cap = capabilities.get('browser_engine', False)
                        get_logger().log(f"[发现] 新节点: {node_id} ({node_ip}:{tcp_port}) {'[支持浏览器]' if browser_cap else ''}")
                        get_logger().log(f"[网络] 当前已知节点: {len(self.known_nodes)} 个")
                    else:
                        ip, port, _ = self.known_nodes[node_id]
                        self.known_nodes[node_id] = (ip, port, time.time())
                    
        except Exception as e:
            get_logger().log(f"[UDP错误] 处理消息失败: {e}")
    
    def _handle_tcp_connection(self, sock, addr):
        """处理TCP连接"""
        client_ip, client_port = addr
        get_logger().log(f"[TCP] 新连接: {client_ip}:{client_port}")
        
        try:
            sock.settimeout(30.0)
            
            while self.running:
                header_data = b''
                start_time = time.time()
                
                while len(header_data) < AnonP2PProtocol.HEADER_SIZE:
                    try:
                        remaining = AnonP2PProtocol.HEADER_SIZE - len(header_data)
                        chunk = sock.recv(remaining)
                        if not chunk:
                            break
                        header_data += chunk
                        
                        if time.time() - start_time > 10:
                            break
                            
                    except socket.timeout:
                        break
                    except Exception as e:
                        get_logger().log(f"[TCP错误] 读取头数据失败: {e}")
                        break
                
                if len(header_data) < AnonP2PProtocol.HEADER_SIZE:
                    break
                
                try:
                    total_len, msg_type, seq_num = AnonP2PProtocol.parse_header(header_data)
                except ValueError as e:
                    get_logger().log(f"[协议错误] 解析头失败: {e}")
                    break
                
                body_len = total_len - AnonP2PProtocol.HEADER_SIZE
                if body_len < 0 or body_len > 10 * 1024 * 1024:
                    get_logger().log(f"[协议错误] 无效的消息体长度: {body_len}")
                    break
                
                body_data = b''
                start_time = time.time()
                
                while len(body_data) < body_len:
                    try:
                        remaining = min(4096, body_len - len(body_data))
                        chunk = sock.recv(remaining)
                        if not chunk:
                            break
                        body_data += chunk
                        
                        if time.time() - start_time > 30:
                            break
                            
                    except socket.timeout:
                        break
                    except Exception as e:
                        get_logger().log(f"[TCP错误] 读取体数据失败: {e}")
                        break
                
                if len(body_data) < body_len:
                    get_logger().log(f"[协议错误] 消息体不完整: {len(body_data)}/{body_len}")
                    break
                
                self._process_tcp_message(msg_type, body_data, sock, addr)
                
        except Exception as e:
            get_logger().log(f"[TCP错误] 处理连接失败 {addr}: {e}")
        finally:
            try:
                sock.close()
            except:
                pass
            get_logger().log(f"[TCP] 连接关闭: {client_ip}:{client_port}")
    
    def _process_tcp_message(self, msg_type, data, sock, addr):
        """处理TCP消息"""
        try:
            if msg_type == MessageType.ANON_REQUEST.value:
                self._handle_anon_request(data, sock, addr)
            elif msg_type == MessageType.DATA_RELAY.value:
                self._handle_data_relay(data, sock, addr)
            elif msg_type == MessageType.HEARTBEAT.value:
                self._handle_heartbeat(data, sock, addr)
            else:
                get_logger().log(f"[警告] 未知消息类型: {msg_type}")
                
        except Exception as e:
            get_logger().log(f"[处理错误] TCP消息处理失败: {e}")
    
    def _handle_anon_request(self, data, sock, addr):
        """处理匿名请求"""
        try:
            request = json.loads(data.decode())
            url = request.get('url')
            client_node = request.get('client_node')
            use_browser = request.get('use_browser', False)
            
            get_logger().log(f"[请求] 来自 {client_node}: {url}")
            if use_browser:
                get_logger().log(f"[请求] 使用浏览器引擎加载")
            
            web_result = self.web_client.fetch_anonymously(url, use_browser=use_browser)
            
            response_data = {
                'success': web_result['success'],
                'url': url,
                'client_node': client_node,
                'loaded_with_browser': web_result.get('loaded_with_browser', False)
            }
            
            if web_result['success']:
                response_data.update({
                    'content': web_result['content'].hex(),
                    'content_type': web_result['content_type'],
                    'title': web_result.get('title', '')
                })
                load_method = "浏览器" if web_result.get('loaded_with_browser') else "普通"
                get_logger().log(f"[请求] {load_method}方式获取成功: {len(web_result['content'])} 字节")
            else:
                response_data.update({
                    'error': web_result.get('error', 'Unknown error')
                })
                get_logger().log(f"[请求] 获取失败: {web_result.get('error')}")
            
            response_bytes = json.dumps(response_data).encode()
            message = AnonP2PProtocol.create_message(MessageType.ANON_RESPONSE, response_bytes)
            sock.send(message)
            
        except Exception as e:
            get_logger().log(f"[请求错误] 处理失败: {e}")
    
    def _handle_data_relay(self, data, sock, addr):
        """处理数据中继"""
        try:
            relay_msg = json.loads(data.decode())
            target_node = relay_msg.get('target_node')
            
            get_logger().log(f"[中继] 目标: {target_node}")
            
            if target_node == self.node_id:
                get_logger().log(f"[中继] 目标为本节点")
                return
            
            if target_node in self.known_nodes:
                node_ip, node_port, _ = self.known_nodes[target_node]
                self._send_to_node(target_node, MessageType.DATA_RELAY, relay_msg)
                get_logger().log(f"[中继] 转发到: {target_node}")
            else:
                get_logger().log(f"[中继错误] 未知目标: {target_node}")
                
        except Exception as e:
            get_logger().log(f"[中继错误] 处理失败: {e}")
    
    def _handle_heartbeat(self, data, sock, addr):
        """处理心跳"""
        try:
            heartbeat = json.loads(data.decode())
            node_id = heartbeat.get('node_id')
            
            if node_id in self.known_nodes:
                ip, port, _ = self.known_nodes[node_id]
                self.known_nodes[node_id] = (ip, port, time.time())
            
            response = {'node_id': self.node_id}
            response_bytes = json.dumps(response).encode()
            message = AnonP2PProtocol.create_message(MessageType.HEARTBEAT, response_bytes)
            sock.send(message)
            
        except Exception as e:
            get_logger().log(f"[心跳错误] 处理失败: {e}")
    
    def _send_to_node(self, node_id, msg_type, data_dict):
        """发送消息到指定节点"""
        if node_id not in self.known_nodes:
            get_logger().log(f"[发送错误] 未知节点: {node_id}")
            return False
        
        node_ip, node_port, _ = self.known_nodes[node_id]
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((node_ip, node_port))
            
            data_bytes = json.dumps(data_dict).encode()
            message = AnonP2PProtocol.create_message(msg_type, data_bytes)
            sock.send(message)
            sock.close()
            
            get_logger().log(f"[发送] 到 {node_id} ({node_ip}:{node_port})")
            return True
            
        except Exception as e:
            get_logger().log(f"[发送错误] 到 {node_id} 失败: {e}")
            if node_id in self.known_nodes:
                del self.known_nodes[node_id]
            return False
    
    def request_web_page(self, url, via_node_id=None, use_browser=False):
        """请求网页"""
        if not self.known_nodes:
            get_logger().log(f"[错误] 没有可用节点")
            return None
        
        if not via_node_id:
            via_node_id = random.choice(list(self.known_nodes.keys()))
            get_logger().log(f"[请求] 随机选择节点: {via_node_id}")
        
        request_data = {
            'url': url,
            'client_node': self.node_id,
            'use_browser': use_browser
        }
        
        return self._send_to_node(via_node_id, MessageType.ANON_REQUEST, request_data)
    
    def get_node_info(self):
        """获取节点信息"""
        browser_status = "可用" if (self.enable_browser and self.web_client.browser_engine and self.web_client.browser_engine.initialized) else "不可用"
        
        return {
            'node_id': self.node_id,
            'ip': NetworkHelper.get_local_ip(),
            'tcp_port': self.tcp_port,
            'known_nodes': len(self.known_nodes),
            'nodes_discovered': self.node_counter,
            'browser_engine': browser_status
        }
    
    def list_known_nodes(self):
        """列出已知节点"""
        nodes = []
        for node_id, (ip, port, last_seen) in self.known_nodes.items():
            nodes.append({
                'id': node_id,
                'address': f"{ip}:{port}",
                'last_seen': time.time() - last_seen
            })
        return nodes
    
    def manual_add_node(self, node_id, ip, port):
        """手动添加节点"""
        try:
            port = int(port)
            self.known_nodes[node_id] = (ip, port, time.time())
            self.node_counter += 1
            get_logger().log(f"[手动] 添加节点: {node_id} ({ip}:{port})")
            return True
        except ValueError:
            get_logger().log(f"[手动] 无效的端口号")
            return False
    
    def stop(self):
        """停止节点"""
        self.running = False
        if self.udp_listener:
            self.udp_listener.close()
        if self.tcp_socket:
            self.tcp_socket.close()
        if self.web_client:
            self.web_client.close()
        self.thread_pool.shutdown()

def print_menu():
    """打印菜单"""
    print("\n" + "="*50)
    print("匿名P2P代理系统 - 支持浏览器引擎")
    print("1. 查看节点信息")
    print("2. 列出已知节点")
    print("3. 手动添加节点")
    print("4. 请求网页 (普通模式)")
    print("5. 请求网页 (浏览器模式)")
    print("6. 网络测试")
    print("7. 退出")
    print("="*50)

def network_test():
    """网络测试"""
    get_logger().log("=== 网络连通性测试 ===")
    local_ip = NetworkHelper.get_local_ip()
    broadcast_ip = NetworkHelper.get_broadcast_address()
    
    get_logger().log(f"本地IP: {local_ip}")
    get_logger().log(f"广播地址: {broadcast_ip}")
    
    if SELENIUM_AVAILABLE:
        get_logger().log("Selenium: 已安装")
        try:
            test_browser = BrowserEngine()
            if test_browser.initialized:
                get_logger().log("浏览器引擎: 可用")
                test_browser.close()
            else:
                get_logger().log("浏览器引擎: 不可用")
        except:
            get_logger().log("浏览器引擎: 测试失败")
    else:
        get_logger().log("Selenium: 未安装")
    
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_sock.bind(('0.0.0.0', 8888))
        test_sock.close()
        get_logger().log("UDP端口绑定: 成功")
    except Exception as e:
        get_logger().log(f"UDP端口绑定: 失败 - {e}")
    
    get_logger().log("=====================")

def run_command_interface(node):
    """运行命令界面 - 在单独的线程中运行"""
    while node.running:
        try:
            print_menu()
            choice = input("请选择操作 (1-7): ").strip()
            
            if choice == '1':
                info = node.get_node_info()
                print(f"\n节点信息:")
                print(f"  节点ID: {info['node_id']}")
                print(f"  地址: {info['ip']}:{info['tcp_port']}")
                print(f"  已知节点: {info['known_nodes']} 个")
                print(f"  累计发现: {info['nodes_discovered']} 次")
                print(f"  浏览器引擎: {info['browser_engine']}")
                input("\n按回车键继续...")
                
            elif choice == '2':
                nodes = node.list_known_nodes()
                print(f"\n已知节点 ({len(nodes)} 个):")
                for i, node_info in enumerate(nodes, 1):
                    print(f"  {i}. {node_info['id']}")
                    print(f"     地址: {node_info['address']}")
                    print(f"     最后活跃: {node_info['last_seen']:.1f} 秒前")
                input("\n按回车键继续...")
                    
            elif choice == '3':
                node_input = input("请输入节点信息 (格式: node_id:ip:port): ").strip()
                try:
                    node_id, ip, port_str = node_input.split(':')
                    node.manual_add_node(node_id, ip, port_str)
                except ValueError:
                    print("[错误] 节点格式错误，应为 node_id:ip:port")
                input("\n按回车键继续...")
                    
            elif choice == '4':
                url = input("请输入网页URL: ").strip()
                if node.list_known_nodes():
                    via_node = input("通过节点 (回车随机): ").strip()
                    if not via_node:
                        via_node = None
                else:
                    via_node = None
                    print("[警告] 没有已知节点，无法发送请求")
                    input("\n按回车键继续...")
                    continue
                
                success = node.request_web_page(url, via_node, use_browser=False)
                if success:
                    print("[成功] 普通模式请求已发送")
                else:
                    print("[失败] 请求发送失败")
                input("\n按回车键继续...")
                    
            elif choice == '5':
                url = input("请输入网页URL: ").strip()
                if node.list_known_nodes():
                    via_node = input("通过节点 (回车随机): ").strip()
                    if not via_node:
                        via_node = None
                else:
                    via_node = None
                    print("[警告] 没有已知节点，无法发送请求")
                    input("\n按回车键继续...")
                    continue
                
                success = node.request_web_page(url, via_node, use_browser=True)
                if success:
                    print("[成功] 浏览器模式请求已发送")
                else:
                    print("[失败] 请求发送失败")
                input("\n按回车键继续...")
                    
            elif choice == '6':
                network_test()
                input("\n按回车键继续...")
                
            elif choice == '7':
                break
            else:
                print("[错误] 无效选择")
                input("\n按回车键继续...")
                
        except (EOFError, KeyboardInterrupt):
            break
        except Exception as e:
            print(f"[命令错误] {e}")
            input("\n按回车键继续...")

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='匿名P2P代理节点 - 分离命令和日志界面')
    parser.add_argument('--port', type=int, default=8889, help='TCP端口号')
    parser.add_argument('--udp-port', type=int, default=8888, help='UDP广播端口')
    parser.add_argument('--node-id', type=str, help='节点ID')
    parser.add_argument('--fetch', type=str, help='要获取的网页URL')
    parser.add_argument('--via-node', type=str, help='通过哪个节点获取')
    parser.add_argument('--browser', action='store_true', help='使用浏览器引擎')
    parser.add_argument('--no-browser', action='store_true', help='禁用浏览器引擎')
    parser.add_argument('--add-node', type=str, help='手动添加节点 (格式: node_id:ip:port)')
    parser.add_argument('--test', action='store_true', help='测试网络连通性')
    parser.add_argument('--log-file', type=str, help='日志文件路径')
    
    args = parser.parse_args()
    
    # 初始化全局日志管理器
    global log_manager
    log_manager = LogManager(log_file=args.log_file)
    
    if args.test:
        network_test()
        log_manager.stop()
        return
    
    # 创建节点
    enable_browser = not args.no_browser
    node = AnonymousP2PNode(
        node_id=args.node_id,
        tcp_port=args.port,
        udp_port=args.udp_port,
        enable_browser=enable_browser
    )
    
    # 启动节点
    node.start()
    
    try:
        # 手动添加节点
        if args.add_node:
            try:
                node_id, ip, port_str = args.add_node.split(':')
                node.manual_add_node(node_id, ip, port_str)
            except ValueError:
                get_logger().log("[错误] 节点格式错误，应为 node_id:ip:port")
        
        # 获取网页
        if args.fetch:
            use_browser = args.browser
            success = node.request_web_page(args.fetch, args.via_node, use_browser=use_browser)
            if success:
                mode = "浏览器" if use_browser else "普通"
                get_logger().log(f"[成功] {mode}模式请求已发送")
            else:
                get_logger().log("[失败] 请求发送失败")
        
        # 启动命令界面（在主线程中运行）
        run_command_interface(node)
                
    except KeyboardInterrupt:
        get_logger().log("\n[系统] 收到中断信号")
    finally:
        node.stop()
        log_manager.stop()

if __name__ == "__main__":
    main()
