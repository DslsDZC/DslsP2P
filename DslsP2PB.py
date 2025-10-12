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
import http.server
import socketserver
import ssl
from http import HTTPStatus

# 浏览器渲染相关
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.common.by import By
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

class MessageType(Enum):
    """扩展消息类型"""
    NODE_REGISTER = 1
    NODE_LIST = 2
    ANON_REQUEST = 3
    ANON_RESPONSE = 4
    DATA_RELAY = 5
    CHUNK_REQUEST = 6
    CHUNK_RESPONSE = 7
    HEARTBEAT = 8
    RENDER_REQUEST = 9
    RENDER_RESPONSE = 10
    ERROR = 99

class AnonP2PProtocol:
    """匿名P2P通信协议"""
    
    HEADER_FORMAT = '!IBI'
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
    """日志管理器"""
    
    def __init__(self, log_file=None):
        self.log_queue = queue.Queue()
        self.log_file = log_file
        self.running = True
        
        self.log_thread = threading.Thread(target=self._log_processor, daemon=True)
        self.log_thread.start()
        
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
        """日志处理线程"""
        while self.running:
            try:
                log_entry = self.log_queue.get(timeout=1)
                print(log_entry)
                
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
                return f"{parts[0]}.{parts[1]}.{parts[2]}.255"
            else:
                return "255.255.255.255"
        except:
            return "255.255.255.255"

class ChunkManager:
    """块管理器"""
    
    def __init__(self, chunk_size=1024):
        self.chunk_size = chunk_size
        self.chunk_storage = {}
        self.completed_requests = {}
    
    def split_content(self, content, request_id):
        """将内容分割成块"""
        chunks = {}
        total_size = len(content)
        total_chunks = (total_size + self.chunk_size - 1) // self.chunk_size
        
        for i in range(total_chunks):
            start = i * self.chunk_size
            end = min(start + self.chunk_size, total_size)
            chunk_data = content[start:end]
            
            chunk_info = {
                'request_id': request_id,
                'chunk_index': i,
                'total_chunks': total_chunks,
                'data': chunk_data.hex(),
                'data_size': len(chunk_data),
                'hash': hashlib.md5(chunk_data).hexdigest()
            }
            chunks[i] = chunk_info
        
        return chunks
    
    def add_chunk(self, chunk_info):
        """添加块数据"""
        request_id = chunk_info['request_id']
        chunk_index = chunk_info['chunk_index']
        
        if request_id not in self.chunk_storage:
            self.chunk_storage[request_id] = {}
        
        try:
            chunk_data = bytes.fromhex(chunk_info['data'])
            self.chunk_storage[request_id][chunk_index] = chunk_data
            
            if hashlib.md5(chunk_data).hexdigest() != chunk_info['hash']:
                return False
            
            if self.is_request_complete(request_id, chunk_info['total_chunks']):
                self._reconstruct_content(request_id, chunk_info['total_chunks'])
                return True
            return True
        except Exception as e:
            return False
    
    def is_request_complete(self, request_id, total_chunks):
        """检查请求是否完成"""
        if request_id not in self.chunk_storage:
            return False
        return len(self.chunk_storage[request_id]) == total_chunks
    
    def _reconstruct_content(self, request_id, total_chunks):
        """重组内容"""
        chunks = self.chunk_storage[request_id]
        content = b''
        
        for i in range(total_chunks):
            if i in chunks:
                content += chunks[i]
            else:
                return False
        
        self.completed_requests[request_id] = content
        del self.chunk_storage[request_id]
        return True
    
    def get_completed_content(self, request_id):
        """获取已完成的内容"""
        return self.completed_requests.get(request_id)

class DistributedBrowserEngine:
    """分布式浏览器引擎"""
    
    def __init__(self, node):
        self.node = node
        self.driver = None
        self.initialized = False
        self.resource_cache = {}
        self.init_browser()
    
    def init_browser(self):
        """修复的浏览器初始化方法"""
        if not SELENIUM_AVAILABLE:
            get_logger().log("[浏览器] 警告: Selenium 不可用")
            return False
        
        try:
            # 检查是否安装了webdriver_manager
            try:
                from webdriver_manager.chrome import ChromeDriverManager
                from selenium.webdriver.chrome.service import Service
                webdriver_manager_available = True
                get_logger().log("[浏览器] webdriver_manager 可用")
            except ImportError:
                webdriver_manager_available = False
                get_logger().log("[浏览器] webdriver_manager 未安装")
            
            from selenium.webdriver.chrome.options import Options
            import tempfile
            import os
            
            chrome_options = Options()
            
            # 创建唯一的用户数据目录
            user_data_dir = os.path.join(tempfile.gettempdir(), f"chrome_p2p_{self.node.node_id}")
            os.makedirs(user_data_dir, exist_ok=True)
            
            chrome_options.add_argument(f"--user-data-dir={user_data_dir}")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--remote-debugging-port=0")
            chrome_options.add_argument("--no-first-run")
            chrome_options.add_argument("--no-default-browser-check")
            
            # 禁用扩展
            chrome_options.add_argument("--disable-extensions")
            chrome_options.add_argument("--disable-plugins")
            chrome_options.add_argument("--disable-translate")
            chrome_options.add_argument("--disable-default-apps")
            
            # 设置用户代理
            chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
            
            get_logger().log("[浏览器] 正在创建浏览器实例...")
            
            try:
                if webdriver_manager_available:
                    from webdriver_manager.chrome import ChromeDriverManager
                    from selenium.webdriver.chrome.service import Service
                    service = Service(ChromeDriverManager().install())
                    self.driver = webdriver.Chrome(service=service, options=chrome_options)
                    get_logger().log("[浏览器] 使用webdriver_manager自动管理的ChromeDriver")
                else:
                    self.driver = webdriver.Chrome(options=chrome_options)
                    get_logger().log("[浏览器] 使用系统ChromeDriver")
                    
            except Exception as e:
                get_logger().log(f"[浏览器] Chrome启动失败: {e}")
                return False
            
            # 配置超时设置
            self.driver.set_page_load_timeout(30)
            self.driver.set_script_timeout(20)
            self.driver.implicitly_wait(10)
            
            # 测试浏览器功能
            try:
                self.driver.get("about:blank")
                test_title = self.driver.title
                get_logger().log(f"[浏览器] 浏览器测试成功")
                
                self.initialized = True
                get_logger().log("[浏览器] ✓ Chrome浏览器引擎初始化成功")
                return True
                
            except Exception as e:
                get_logger().log(f"[浏览器] 浏览器功能测试失败: {e}")
                if self.driver:
                    self.driver.quit()
                return False
                
        except Exception as e:
            get_logger().log(f"[浏览器] 初始化过程出错: {e}")
            return False
    
    def render_page_distributed(self, url, request_id):
        """分布式渲染页面"""
        if not self.initialized:
            get_logger().log("[渲染] 浏览器未初始化，无法渲染")
            return None
        
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            get_logger().log(f"[渲染] 开始渲染: {url}")
            
            # 加载页面
            self.driver.get(url)
            
            # 等待页面加载完成
            WebDriverWait(self.driver, 15).until(
                lambda driver: driver.execute_script("return document.readyState") == "complete"
            )
            
            # 额外等待确保动态内容加载
            time.sleep(2)
            
            # 获取页面HTML
            page_source = self.driver.page_source.encode('utf-8')
            current_url = self.driver.current_url
            title = self.driver.title
            
            get_logger().log(f"[渲染] 页面渲染完成: {title}")
            get_logger().log(f"[渲染] 最终URL: {current_url}")
            get_logger().log(f"[渲染] 页面大小: {len(page_source)} 字节")
            
            # 获取所有资源链接
            resources = self._extract_resources(current_url)
            get_logger().log(f"[渲染] 发现 {len(resources)} 个资源文件")
            
            # 分布式获取资源
            distributed_resources = self._fetch_resources_distributed(resources, request_id)
            
            # 构建完整的页面数据
            page_data = {
                'html': page_source.hex(),
                'resources': distributed_resources,
                'url': current_url,
                'title': title
            }
            
            return page_data
            
        except Exception as e:
            get_logger().log(f"[渲染错误] {e}")
            return None
    
    def _extract_resources(self, base_url):
        """提取页面资源"""
        resources = []
        
        try:
            # CSS文件
            css_links = self.driver.find_elements(By.CSS_SELECTOR, 'link[rel="stylesheet"]')
            for link in css_links:
                href = link.get_attribute('href')
                if href:
                    resources.append({'url': href, 'type': 'css'})
            
            # JS文件
            js_scripts = self.driver.find_elements(By.CSS_SELECTOR, 'script[src]')
            for script in js_scripts:
                src = script.get_attribute('src')
                if src:
                    resources.append({'url': src, 'type': 'js'})
            
            # 图片
            images = self.driver.find_elements(By.CSS_SELECTOR, 'img[src]')
            for img in images:
                src = img.get_attribute('src')
                if src:
                    resources.append({'url': src, 'type': 'image'})
        
        except Exception as e:
            get_logger().log(f"[资源提取错误] {e}")
        
        return resources
    
    def _fetch_resources_distributed(self, resources, request_id):
        """分布式获取资源"""
        results = {}
        
        for i, resource in enumerate(resources):
            resource_id = f"{request_id}_resource_{i}"
            
            # 通过P2P网络获取资源
            resource_data = self.node.fetch_resource_distributed(
                resource['url'], 
                resource_id
            )
            
            if resource_data:
                results[resource['url']] = {
                    'type': resource['type'],
                    'data': resource_data.hex() if resource_data else None
                }
        
        return results
    
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
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15',
        ]
    
    def fetch_anonymously(self, url, use_browser=False, timeout=10):
        """获取网页内容"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            headers = {
               'User-Agent': random.choice(self.user_agents),
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
               'Accept-Language': 'zh-CN,zh;q=0.9',
               'Connection': 'keep-alive'
            }
            response = self.session.get(url, headers=headers, timeout=timeout)
            
            get_logger().log(f"[网页] 普通请求: {url}")
            
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

class P2PProxyHandler(http.server.SimpleHTTPRequestHandler):
    """P2P代理HTTP处理器"""
    
    def __init__(self, *args, node=None, **kwargs):
        self.node = node
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """处理GET请求"""
        try:
            # 解析请求的URL
            if self.path.startswith('/http://') or self.path.startswith('/https://'):
                target_url = self.path[1:]  # 去掉开头的/
            elif '?url=' in self.path:
                # 从查询参数获取URL
                import urllib.parse
                parsed = urllib.parse.urlparse(self.path)
                query_params = urllib.parse.parse_qs(parsed.query)
                target_url = query_params.get('url', [''])[0]
            else:
                # 默认行为，显示使用说明
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"""
                <html><body>
                <h1>P2P Browser Proxy</h1>
                <p>Usage:</p>
                <ul>
                <li>Access any site: http://localhost:8080/http://example.com</li>
                <li>Or use query parameter: http://localhost:8080/?url=http://example.com</li>
                </ul>
                </body></html>
                """)
                return
            
            if not target_url:
                self.send_error(400, "Missing URL parameter")
                return
            
            get_logger().log(f"[代理] 请求URL: {target_url}")
            
            # 通过P2P网络获取页面（使用浏览器渲染）
            result = self.node.request_web_page_distributed(target_url, use_browser=True)
            
            if result and result.get('success'):
                content = result.get('content', b'')
                
                # 发送响应
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                
                get_logger().log(f"[代理] 成功返回: {len(content)} 字节")
            else:
                error_msg = result.get('error', 'Unknown error') if result else 'No response'
                self.send_error(502, f"P2P fetch failed: {error_msg}")
                get_logger().log(f"[代理] 获取失败: {error_msg}")
                
        except Exception as e:
            self.send_error(500, f"Server error: {str(e)}")
            get_logger().log(f"[代理错误] {e}")
    
    def log_message(self, format, *args):
        """重写日志方法，使用我们的日志系统"""
        get_logger().log(f"[HTTP] {format % args}")

class P2PProxyServer:
    """P2P代理服务器"""
    
    def __init__(self, node, host='localhost', port=8080, https_port=8443, ssl_certfile=None, ssl_keyfile=None):
        self.node = node
        self.host = host
        self.port = port
        self.https_port = https_port
        self.ssl_certfile = ssl_certfile
        self.ssl_keyfile = ssl_keyfile
        self.http_server = None
        self.https_server = None
        self.running = False
    
    def start(self):
        """启动代理服务器"""
        # 启动HTTP服务器
        handler = lambda *args, **kwargs: P2PProxyHandler(*args, node=self.node, **kwargs)
        self.http_server = socketserver.TCPServer((self.host, self.port), handler)
        http_thread = threading.Thread(target=self._serve_http, daemon=True)
        http_thread.start()
        get_logger().log(f"[代理] HTTP代理服务器启动在 http://{self.host}:{self.port}")
        
        # 如果提供了SSL证书，启动HTTPS服务器
        if self.ssl_certfile and self.ssl_keyfile and os.path.exists(self.ssl_certfile) and os.path.exists(self.ssl_keyfile):
            self.https_server = socketserver.TCPServer((self.host, self.https_port), handler)
            self.https_server.socket = ssl.wrap_socket(
                self.https_server.socket,
                keyfile=self.ssl_keyfile,
                certfile=self.ssl_certfile,
                server_side=True
            )
            https_thread = threading.Thread(target=self._serve_https, daemon=True)
            https_thread.start()
            get_logger().log(f"[代理] HTTPS代理服务器启动在 https://{self.host}:{self.https_port}")
        else:
            get_logger().log("[代理] 未找到SSL证书，HTTPS服务未启动")
        
        self.running = True
    
    def _serve_http(self):
        """运行HTTP服务器"""
        try:
            self.http_server.serve_forever()
        except Exception as e:
            get_logger().log(f"[代理错误] HTTP服务器错误: {e}")
    
    def _serve_https(self):
        """运行HTTPS服务器"""
        try:
            self.https_server.serve_forever()
        except Exception as e:
            get_logger().log(f"[代理错误] HTTPS服务器错误: {e}")
    
    def stop(self):
        """停止代理服务器"""
        self.running = False
        if self.http_server:
            self.http_server.shutdown()
        if self.https_server:
            self.https_server.shutdown()

class AnonymousP2PNode:
    """增强的匿名P2P节点 - 支持分布式浏览器渲染"""
    
    def __init__(self, node_id=None, tcp_port=8889, udp_port=8888, enable_browser=True):
        self.node_id = node_id or self._generate_node_id()
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        
        # 核心组件
        self.chunk_manager = ChunkManager()
        self.web_client = AnonymousWebClient(enable_browser=enable_browser)
        self.browser_engine = DistributedBrowserEngine(self) if enable_browser else None
        self.enable_browser = enable_browser
        
        # 节点状态
        self.known_nodes = {}
        self.active_requests = {}
        self.pending_responses = {}
        self.pending_chunks = defaultdict(dict)  # {request_id: {chunk_index: [node_ids]}}
        self.render_results = {}
        self.node_counter = 0
        
        # 网络组件
        self.udp_listener = None
        self.tcp_socket = None
        self.running = False
        
        # 线程池
        self.thread_pool = ThreadPoolExecutor(max_workers=20)
        
        get_logger().log(f"[系统] 分布式浏览器节点 {self.node_id} 初始化完成")
        get_logger().log(f"[网络] TCP端口: {tcp_port}, UDP端口: {udp_port}")
        get_logger().log(f"[IP] 本地IP: {NetworkHelper.get_local_ip()}")
        if enable_browser:
            status = "可用" if (self.browser_engine and self.browser_engine.initialized) else "不可用"
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
        
        for node_id, (ip, port, last_seen, capabilities) in self.known_nodes.items():
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
                    'browser_engine': self.enable_browser and self.browser_engine and self.browser_engine.initialized
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
                        self.known_nodes[node_id] = (node_ip, tcp_port, time.time(), capabilities)
                        self.node_counter += 1
                        browser_cap = capabilities.get('browser_engine', False)
                        get_logger().log(f"[发现] 新节点: {node_id} ({node_ip}:{tcp_port}) {'[支持浏览器]' if browser_cap else ''}")
                        get_logger().log(f"[网络] 当前已知节点: {len(self.known_nodes)} 个")
                    else:
                        ip, port, _, caps = self.known_nodes[node_id]
                        self.known_nodes[node_id] = (ip, port, time.time(), capabilities)
                    
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
            elif msg_type == MessageType.ANON_RESPONSE.value:
                self._handle_anon_response(data, sock, addr)
            elif msg_type == MessageType.RENDER_REQUEST.value:
                self._handle_render_request(data, sock, addr)
            elif msg_type == MessageType.RENDER_RESPONSE.value:
                self._handle_render_response(data, sock, addr)
            elif msg_type == MessageType.CHUNK_RESPONSE.value:
                self._handle_chunk_response(data, sock, addr)
            elif msg_type == MessageType.CHUNK_REQUEST.value:
                self._handle_chunk_request(data, sock, addr)
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
            request_id = request.get('request_id')
            return_address = request.get('return_address', {})
            distributed = request.get('distributed', False)
            
            get_logger().log(f"[请求] 来自 {client_node}: {url}")
            
            if use_browser and self.browser_engine and self.browser_engine.initialized:
                get_logger().log(f"[请求] 使用浏览器引擎加载")
            
            # 获取网页内容
            web_result = self.web_client.fetch_anonymously(url, use_browser=use_browser)
            
            response_data = {
                'success': web_result['success'],
                'url': url,
                'client_node': client_node,
                'request_id': request_id,
                'loaded_with_browser': web_result.get('loaded_with_browser', False)
            }
            
            if web_result['success']:
                # 如果启用分布式模式，将内容分块
                if distributed and len(web_result['content']) > 1024:
                    chunks = self.chunk_manager.split_content(web_result['content'], request_id)
                    
                    # 分发块到多个节点
                    if return_address:
                        self._distribute_chunks(chunks, request_id, return_address)
                    
                    response_data.update({
                        'distributed': True,
                        'total_chunks': len(chunks),
                        'content_type': web_result['content_type']
                    })
                    get_logger().log(f"[分布式] 内容已分割为 {len(chunks)} 个块")
                else:
                    # 直接发送内容
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
            
            # 如果有返回地址，直接发送响应
            if return_address:
                target_node_id = return_address.get('node_id')
                if target_node_id:
                    self._send_to_node(target_node_id, MessageType.ANON_RESPONSE, response_data)
                    get_logger().log(f"[响应] 已发送响应到 {target_node_id}")
                else:
                    # 回退到原连接发送
                    response_bytes = json.dumps(response_data).encode()
                    message = AnonP2PProtocol.create_message(MessageType.ANON_RESPONSE, response_bytes)
                    sock.send(message)
            else:
                # 原连接发送
                response_bytes = json.dumps(response_data).encode()
                message = AnonP2PProtocol.create_message(MessageType.ANON_RESPONSE, response_bytes)
                sock.send(message)
            
        except Exception as e:
            get_logger().log(f"[请求错误] 处理失败: {e}")
    
    def _handle_anon_response(self, data, sock, addr):
        """处理匿名响应"""
        try:
            response = json.loads(data.decode())
            request_id = response.get('request_id')
            
            get_logger().log(f"[响应] 收到响应 (ID: {request_id})")
            
            if request_id in self.pending_responses:
                # 如果是分布式响应，设置事件通知
                if response.get('distributed', False):
                    self.pending_responses[request_id]['distributed'] = True
                    self.pending_responses[request_id]['total_chunks'] = response.get('total_chunks', 0)
                    get_logger().log(f"[响应] 分布式响应，等待 {response.get('total_chunks')} 个块")
                else:
                    # 转换十六进制内容回字节
                    if response.get('success') and 'content' in response:
                        response['content'] = bytes.fromhex(response['content'])
                    
                    self.pending_responses[request_id]['response'] = response
                    self.pending_responses[request_id]['event'].set()
                    
                    get_logger().log(f"[响应] 响应已处理: {response.get('url')}")
            else:
                get_logger().log(f"[响应] 未知的请求ID: {request_id}")
                
        except Exception as e:
            get_logger().log(f"[响应错误] 处理失败: {e}")
    
    def _handle_render_request(self, data, sock, addr):
        """处理渲染请求"""
        try:
            request = json.loads(data.decode())
            url = request.get('url')
            request_id = request.get('request_id')
            client_node = request.get('client_node')
            return_address = request.get('return_address')
            
            get_logger().log(f"[渲染] 收到渲染请求: {url} (ID: {request_id})")
            get_logger().log(f"[渲染] 客户端: {client_node}, 返回地址: {return_address}")
            
            if not self.browser_engine or not self.browser_engine.initialized:
                # 回退到普通模式
                get_logger().log(f"[渲染] ✗ 浏览器引擎不可用，状态: {self.browser_engine.initialized if self.browser_engine else '未创建'}")
                normal_request = {
                    'url': url,
                    'client_node': client_node,
                    'request_id': request_id,
                    'return_address': return_address,
                    'distributed': True
                }
                self._handle_anon_request(json.dumps(normal_request).encode(), sock, addr)
                return
            
            # 执行浏览器渲染
            render_result = self.browser_engine.render_page_distributed(url, request_id)

            get_logger().log(f"[渲染] ✓ 浏览器引擎可用，开始渲染...")

            if render_result:
                # 将渲染结果分块分发
                get_logger().log(f"[渲染] ✓ 渲染成功，开始分块分发")
                html_content = bytes.fromhex(render_result['html'])
                chunks = self.chunk_manager.split_content(html_content, request_id)
                
                # 分发块到多个节点
                self._distribute_chunks(chunks, request_id, return_address)
                
                # 发送渲染元数据
                render_response = {
                    'request_id': request_id,
                    'success': True,
                    'url': render_result['url'],
                    'title': render_result['title'],
                    'resources': render_result['resources'],
                    'total_chunks': len(chunks),
                    'content_type': 'text/html',
                    'loaded_with_browser': True
                }
                
                self._send_to_node(return_address['node_id'], MessageType.RENDER_RESPONSE, render_response)
                get_logger().log(f"[渲染] 渲染完成，分发 {len(chunks)} 个块")
                
            else:
                get_logger().log(f"[渲染] ✗ 渲染失败")
                error_response = {
                    'request_id': request_id,
                    'success': False,
                    'error': '渲染失败'
                }
                self._send_to_node(return_address['node_id'], MessageType.RENDER_RESPONSE, error_response)
                get_logger().log(f"[渲染] 渲染失败")
                
        except Exception as e:
            get_logger().log(f"[渲染错误] 处理失败: {e}")
            import traceback
            get_logger().log(f"[渲染错误] 详细: {traceback.format_exc()}")
    
    def _handle_render_response(self, data, sock, addr):
        """处理渲染响应"""
        try:
            response = json.loads(data.decode())
            request_id = response.get('request_id')
            
            get_logger().log(f"[渲染响应] 收到渲染元数据 (ID: {request_id})")
            
            # 存储渲染结果
            self.render_results[request_id] = response
            
        except Exception as e:
            get_logger().log(f"[渲染响应错误] 处理失败: {e}")
    
    def _handle_chunk_response(self, data, sock, addr):
        """处理块响应"""
        try:
            chunk_data = json.loads(data.decode())
            
            if 'chunk_data' in chunk_data:
                # 这是实际的块数据
                chunk_info = chunk_data['chunk_data']
                request_id = chunk_info['request_id']
                
                # 存储块
                success = self.chunk_manager.add_chunk(chunk_info)
                if success:
                    get_logger().log(f"[块] 接收并存储块 {chunk_info['chunk_index']+1}/{chunk_info['total_chunks']}")
                    
                    # 如果这是最后一个块，通知等待的请求
                    if self.chunk_manager.is_request_complete(request_id, chunk_info['total_chunks']):
                        if request_id in self.pending_responses:
                            completed_content = self.chunk_manager.get_completed_content(request_id)
                            if completed_content:
                                response = {
                                    'success': True,
                                    'content': completed_content,
                                    'url': f"chunked_{request_id}",
                                    'content_type': 'application/octet-stream',
                                    'loaded_with_browser': False
                                }
                                self.pending_responses[request_id]['response'] = response
                                self.pending_responses[request_id]['event'].set()
                                get_logger().log(f"[块] 所有块接收完成: {request_id}")
                else:
                    get_logger().log(f"[块] 块验证失败")
                    
            elif 'chunk_nodes' in chunk_data:
                # 这是块分布图
                request_id = chunk_data['request_id']
                chunk_nodes = chunk_data['chunk_nodes']
                
                # 更新待处理块信息
                self.pending_chunks[request_id] = chunk_nodes
                get_logger().log(f"[块] 收到块分布图，共 {chunk_data['total_chunks']} 个块")
                
        except Exception as e:
            get_logger().log(f"[块错误] 处理失败: {e}")
    
    def _handle_chunk_request(self, data, sock, addr):
        """处理块请求"""
        try:
            request = json.loads(data.decode())
            request_id = request.get('request_id')
            chunk_index = request.get('chunk_index')
            return_address = request.get('return_address')
            
            # 检查是否有这个块
            if (request_id in self.chunk_manager.chunk_storage and 
                chunk_index in self.chunk_manager.chunk_storage[request_id]):
                
                chunk_data = self.chunk_manager.chunk_storage[request_id][chunk_index]
                chunk_info = {
                    'request_id': request_id,
                    'chunk_index': chunk_index,
                    'total_chunks': len(self.chunk_manager.chunk_storage[request_id]),
                    'data': chunk_data.hex(),
                    'data_size': len(chunk_data),
                    'hash': hashlib.md5(chunk_data).hexdigest()
                }
                
                chunk_response = {
                    'chunk_data': chunk_info
                }
                
                self._send_to_node(return_address['node_id'], MessageType.CHUNK_RESPONSE, chunk_response)
                get_logger().log(f"[块] 发送块 {chunk_index} 到 {return_address['node_id']}")
                
        except Exception as e:
            get_logger().log(f"[块错误] 处理请求失败: {e}")
    
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
                node_ip, node_port, _, _ = self.known_nodes[target_node]
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
                ip, port, _, caps = self.known_nodes[node_id]
                self.known_nodes[node_id] = (ip, port, time.time(), caps)
            
            response = {'node_id': self.node_id}
            response_bytes = json.dumps(response).encode()
            message = AnonP2PProtocol.create_message(MessageType.HEARTBEAT, response_bytes)
            sock.send(message)
            
        except Exception as e:
            get_logger().log(f"[心跳错误] 处理失败: {e}")
    
    def _distribute_chunks(self, chunks, request_id, return_address):
        """分发块到多个节点"""
        chunk_nodes = {}
        
        for chunk_index, chunk_info in chunks.items():
            # 选择3个随机节点存储这个块
            available_nodes = list(self.known_nodes.keys())
            if len(available_nodes) > 3:
                selected_nodes = random.sample(available_nodes, 3)
            else:
                selected_nodes = available_nodes
            
            chunk_nodes[chunk_index] = selected_nodes
            
            # 发送块到每个节点
            for node_id in selected_nodes:
                chunk_relay = {
                    'target_node': return_address['node_id'],
                    'chunk_data': chunk_info,
                    'request_id': request_id
                }
                self._send_to_node(node_id, MessageType.CHUNK_RESPONSE, chunk_relay)
        
        # 通知客户端哪些节点有哪个块
        chunk_map = {
            'request_id': request_id,
            'chunk_nodes': chunk_nodes,
            'total_chunks': len(chunks)
        }
        self._send_to_node(return_address['node_id'], MessageType.CHUNK_RESPONSE, chunk_map)
    
    def _send_to_node(self, node_id, msg_type, data_dict):
        """发送消息到指定节点"""
        if node_id not in self.known_nodes:
            get_logger().log(f"[发送错误] 未知节点: {node_id}")
            return False
        
        node_ip, node_port, _, _ = self.known_nodes[node_id]
        
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
    
    def request_web_page_distributed(self, url, use_browser=True):
        """分布式请求网页"""
        if not self.known_nodes:
            get_logger().log("[错误] 没有可用节点")
            return None
        
        request_id = f"req_{int(time.time())}_{random.randint(1000, 9999)}"
        
        if use_browser and self.browser_engine and self.browser_engine.initialized:
            # 浏览器渲染模式
            return self._request_browser_render(url, request_id)
        else:
            # 普通分布式模式
            return self._request_distributed_fetch(url, request_id)
    
    def _request_browser_render(self, url, request_id):
        """请求浏览器渲染"""
        # 选择具有浏览器能力的节点
        browser_nodes = []
        for node_id, (ip, port, last_seen, capabilities) in self.known_nodes.items():
            if capabilities.get('browser_engine', False):
                browser_nodes.append(node_id)
        
        if not browser_nodes:
            get_logger().log("[错误] 没有可用的浏览器节点")
            return self._request_distributed_fetch(url, request_id)
        
        # 随机选择浏览器节点
        target_node = random.choice(browser_nodes)
        
        render_request = {
            'url': url,
            'request_id': request_id,
            'client_node': self.node_id,
            'return_address': {
                'node_id': self.node_id,
                'ip': NetworkHelper.get_local_ip(),
                'port': self.tcp_port
            }
        }
        
        # 创建响应等待事件
        response_event = threading.Event()
        self.pending_responses[request_id] = {
            'event': response_event,
            'response': None,
            'distributed': False
        }
        
        # 发送渲染请求
        success = self._send_to_node(target_node, MessageType.RENDER_REQUEST, render_request)
        
        if success:
            get_logger().log(f"[渲染] 渲染请求已发送到 {target_node}")
            # 等待渲染结果
            return self._wait_for_render_result(request_id, response_event)
        return None
    
    def _request_distributed_fetch(self, url, request_id):
        """分布式获取网页"""
        # 通过随机节点发起请求
        target_node = random.choice(list(self.known_nodes.keys()))
        
        fetch_request = {
            'url': url,
            'request_id': request_id,
            'client_node': self.node_id,
            'return_address': {
                'node_id': self.node_id,
                'ip': NetworkHelper.get_local_ip(),
                'port': self.tcp_port
            },
            'distributed': True  # 启用分布式模式
        }
        
        # 创建响应等待事件
        response_event = threading.Event()
        self.pending_responses[request_id] = {
            'event': response_event,
            'response': None,
            'distributed': False
        }
        
        success = self._send_to_node(target_node, MessageType.ANON_REQUEST, fetch_request)
        
        if success:
            get_logger().log(f"[分布式] 请求已发送到 {target_node}")
            return self._wait_for_distributed_result(request_id, response_event)
        return None
    
    def fetch_resource_distributed(self, url, resource_id):
        """分布式获取资源"""
        if not self.known_nodes:
            return None
        
        target_node = random.choice(list(self.known_nodes.keys()))
        
        resource_request = {
            'url': url,
            'request_id': resource_id,
            'client_node': self.node_id,
            'resource_type': 'asset',
            'return_address': {
                'node_id': self.node_id,
                'ip': NetworkHelper.get_local_ip(),
                'port': self.tcp_port
            },
            'distributed': True
        }
        
        # 创建响应等待事件
        response_event = threading.Event()
        self.pending_responses[resource_id] = {
            'event': response_event,
            'response': None,
            'distributed': False
        }
        
        success = self._send_to_node(target_node, MessageType.ANON_REQUEST, resource_request)
        
        if success:
            result = self._wait_for_distributed_result(resource_id, response_event)
            if result and result.get('success'):
                return result.get('content', b'')
        return None
    
    def _wait_for_render_result(self, request_id, response_event, timeout=60):
        """等待渲染结果"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            # 检查是否收到渲染响应
            if request_id in self.render_results:
                render_meta = self.render_results[request_id]
                
                # 等待HTML内容块
                html_content = self._wait_for_distributed_result(request_id, response_event, timeout - (time.time() - start_time))
                
                if html_content and html_content.get('success'):
                    # 合并渲染结果
                    final_result = {
                        'success': True,
                        'url': render_meta.get('url'),
                        'title': render_meta.get('title'),
                        'content': html_content.get('content', b''),
                        'resources': render_meta.get('resources', {}),
                        'content_type': 'text/html',
                        'loaded_with_browser': True
                    }
                    
                    del self.render_results[request_id]
                    return final_result
            
            # 检查块是否完成
            completed_content = self.chunk_manager.get_completed_content(request_id)
            if completed_content:
                return {
                    'success': True,
                    'content': completed_content,
                    'content_type': 'application/octet-stream',
                    'loaded_with_browser': True
                }
            
            time.sleep(0.1)
        
        return None
    
    def _wait_for_distributed_result(self, request_id, response_event, timeout=60):
        """等待分布式结果"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            # 检查是否有直接响应
            if (request_id in self.pending_responses and 
                self.pending_responses[request_id]['response'] is not None):
                result = self.pending_responses[request_id]['response']
                del self.pending_responses[request_id]
                return result
            
            # 检查块是否完成
            completed_content = self.chunk_manager.get_completed_content(request_id)
            if completed_content:
                result = {
                    'success': True,
                    'content': completed_content,
                    'content_type': 'application/octet-stream',
                    'loaded_with_browser': False
                }
                if request_id in self.pending_responses:
                    del self.pending_responses[request_id]
                return result
            
            # 请求缺失的块
            self._request_missing_chunks(request_id)
            
            time.sleep(0.5)
        
        # 超时清理
        if request_id in self.pending_responses:
            del self.pending_responses[request_id]
        return None
    
    def _request_missing_chunks(self, request_id):
        """请求缺失的块"""
        if request_id not in self.pending_chunks:
            return
        
        # 找出缺失的块
        stored_chunks = set(self.chunk_manager.chunk_storage.get(request_id, {}).keys())
        pending_chunks = set(self.pending_chunks[request_id].keys())
        missing_chunks = pending_chunks - stored_chunks
        
        for chunk_index in missing_chunks:
            # 从不同的节点请求块
            available_nodes = self.pending_chunks[request_id][chunk_index]
            if available_nodes:
                target_node = random.choice(available_nodes)
                
                chunk_request = {
                    'request_id': request_id,
                    'chunk_index': chunk_index,
                    'client_node': self.node_id,
                    'return_address': {
                        'node_id': self.node_id,
                        'ip': NetworkHelper.get_local_ip(),
                        'port': self.tcp_port
                    }
                }
                
                self._send_to_node(target_node, MessageType.CHUNK_REQUEST, chunk_request)
    
    def get_node_info(self):
        """获取节点信息"""
        browser_status = "可用" if (self.enable_browser and self.browser_engine and self.browser_engine.initialized) else "不可用"
        
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
        for node_id, (ip, port, last_seen, capabilities) in self.known_nodes.items():
            nodes.append({
                'id': node_id,
                'address': f"{ip}:{port}",
                'last_seen': time.time() - last_seen,
                'browser_capable': capabilities.get('browser_engine', False)
            })
        return nodes
    
    def manual_add_node(self, node_id, ip, port):
        """手动添加节点"""
        try:
            port = int(port)
            self.known_nodes[node_id] = (ip, port, time.time(), {})
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
        if self.browser_engine:
            self.browser_engine.close()
        self.thread_pool.shutdown()

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='分布式浏览器渲染P2P节点')
    parser.add_argument('--port', type=int, default=8889, help='TCP端口号')
    parser.add_argument('--udp-port', type=int, default=8888, help='UDP广播端口')
    parser.add_argument('--node-id', type=str, help='节点ID')
    parser.add_argument('--enable-browser', action='store_true', help='启用浏览器引擎')
    parser.add_argument('--proxy-port', type=int, default=8080, help='HTTP代理端口')
    parser.add_argument('--https-port', type=int, default=8443, help='HTTPS代理端口')
    parser.add_argument('--ssl-cert', type=str, help='SSL证书文件路径')
    parser.add_argument('--ssl-key', type=str, help='SSL密钥文件路径')
    parser.add_argument('--log-file', type=str, help='日志文件路径')
    
    args = parser.parse_args()
    
    # 初始化全局日志管理器
    global log_manager
    log_manager = LogManager(log_file=args.log_file)
    
    # 创建节点
    node = AnonymousP2PNode(
        node_id=args.node_id,
        tcp_port=args.port,
        udp_port=args.udp_port,
        enable_browser=args.enable_browser
    )
    
    # 启动节点
    node.start()
    
    # 启动代理服务器
    proxy = P2PProxyServer(
        node=node,
        port=args.proxy_port,
        https_port=args.https_port,
        ssl_certfile=args.ssl_cert,
        ssl_keyfile=args.ssl_key
    )
    proxy.start()
    
    try:
                
    except KeyboardInterrupt:
        get_logger().log("\n[系统] 收到中断信号")
    finally:
        node.stop()
        proxy.stop()
        log_manager.stop()

if __name__ == "__main__":
    main()