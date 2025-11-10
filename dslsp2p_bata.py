#!/usr/bin/env python3
"""
分布式匿名网络系统 - 完整实现
作者: DslsDZC
日期: 2024
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import random
import socket
import struct
import time
import os
import serialization
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any
import aiohttp
from Crypto.PublicKey import RSA
from Crypto.Cipher import ChaCha20, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import upnpclient
import hashlib

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DistributedAnonymousNetwork")

class NodeType(Enum):
    """节点类型枚举"""
    D_NODE = "D节点"  # 全功能节点
    U_NODE = "U节点"  # 受限功能节点  
    R_NODE = "R节点"  # 中继依赖节点

class FragmentPriority(Enum):
    """分片优先级枚举"""
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    BACKGROUND = 0

@dataclass
class NodeConfig:
    """节点配置类"""
    scan_domain: str = "dsls.top"
    exclude_subdomains: List[str] = field(default_factory=lambda: ["mail", "www", "ftp", "admin"])
    initial_nodes: List[str] = field(default_factory=list)
    upnp_enabled: bool = True
    performance_params: Dict[str, Any] = field(default_factory=dict)
    tcp_port_range: Tuple[int, int] = (20000, 60000)
    dns_ttl: int = 300
    heartbeat_interval: int = 45
    discovery_interval: int = 1800  # 30分钟
    maintenance_interval: int = 600  # 10分钟

@dataclass
class NodeIdentity:
    """节点身份信息"""
    node_id: str
    reputation: int = 1000
    public_key: bytes = None
    private_key: bytes = None
    certificate: bytes = None
    node_type: NodeType = None
    capabilities: Dict[str, Any] = field(default_factory=dict)

@dataclass
class NetworkFragment:
    """网络数据分片"""
    session_id: str
    fragment_index: int
    total_fragments: int
    data: bytes
    priority: FragmentPriority
    offset: int
    checksum: str
    timestamp: float
    flags: int = 0

@dataclass
class RoutingInfo:
    """路由信息"""
    max_hops: int
    current_hops: int = 0
    path_hash: str = ""
    ttl: int = 300
    target_info: Dict[str, Any] = field(default_factory=dict)

class DistributedAnonymousNetwork:
    """分布式匿名网络系统主类"""
    
    def __init__(self, config_file: str = None):
        self.config = self._load_config(config_file)
        self.identity = None
        self.core_services = {}
        self.node_list = {}
        self.routing_table = {}
        self.session_manager = SessionManager()
        self.performance_monitor = PerformanceMonitor()
        self.is_running = False
        
    def _load_config(self, config_file: str) -> NodeConfig:
        """加载配置文件 - 实现自研 .dpdsls 格式"""
        if not config_file:
            # 如果没有指定配置文件，使用默认配置
            return self._get_default_config()
    
        try:
            logger.info(f"加载配置文件: {config_file}")
        
            # 检查文件是否存在
            if not os.path.exists(config_file):
                logger.warning(f"配置文件不存在: {config_file}，使用默认配置")
                return self._get_default_config()
        
            # 解析 .dpdsls 文件
            config_data = self._parse_dpdsls_file(config_file)
        
            # 转换为 NodeConfig 对象
            return self._build_node_config(config_data)
        
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}，使用默认配置")
            return self._get_default_config()

    def _parse_dpdsls_file(self, config_file: str) -> Dict[str, Any]:
        """
        解析 .dpdsls 配置文件格式，支持条件表达式解析
        """
        config_data = {}
        current_section = None
        nested_level = 0  # 处理嵌套条件块

        with open(config_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        line_num = 0
        while line_num < len(lines):
            try:
                line = lines[line_num].strip()
                original_line = line  # 保存原始行用于错误提示
                line_num += 1

                # 忽略空行和注释
                if not line or line.startswith('#'):
                    continue

                # 处理区块定义 [section]
                if line.startswith('[') and line.endswith(']'):
                    current_section = line[1:-1].strip()
                    config_data[current_section] = {}
                    continue

                # 处理条件配置块
                if line.startswith('@if '):
                    condition_expr = line[4:].strip()
                    nested_level += 1
                
                    # 解析并计算条件表达式
                    condition_met = self._evaluate_condition(condition_expr, config_data)
                
                    # 收集整个条件块内容（包括嵌套）
                    condition_block = []
                    while line_num < len(lines) and nested_level > 0:
                        current_line = lines[line_num].strip()
                        if current_line.startswith('@if '):
                            nested_level += 1
                        elif current_line.startswith('@endif'):
                            nested_level -= 1
                            if nested_level == 0:
                                line_num += 1
                                break
                        condition_block.append(lines[line_num])
                        line_num += 1

                    # 如果条件满足，解析条件块内容
                    if condition_met:
                        # 临时解析条件块内容
                        temp_lines = condition_block
                        temp_line_num = 0
                        while temp_line_num < len(temp_lines):
                            temp_line = temp_lines[temp_line_num].strip()
                            if not temp_line or temp_line.startswith('#'):
                                temp_line_num += 1
                                continue
                            
                            # 处理嵌套区块
                            if temp_line.startswith('[') and temp_line.endswith(']'):
                                current_section = temp_line[1:-1].strip()
                                if current_section not in config_data:
                                    config_data[current_section] = {}
                                temp_line_num += 1
                                continue
                            
                            # 处理键值对
                            if '=' in temp_line and current_section is not None:
                                key, value = temp_line.split('=', 1)
                                key = key.strip()
                                value = value.strip()
                                value = self._resolve_environment_vars(value)
                                parsed_value = self._parse_config_value(value)
                            
                                if '.' in key:
                                    self._set_nested_value(config_data[current_section], key, parsed_value)
                                else:
                                    config_data[current_section][key] = parsed_value
                                
                            temp_line_num += 1
                    continue

                # 处理普通键值对
                if current_section is None:
                    logger.warning(f"配置文件第{line_num}行：键值对不在任何区块内")
                    continue

                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                
                    # 解析环境变量
                    value = self._resolve_environment_vars(value)
                
                    # 解析配置值类型
                    parsed_value = self._parse_config_value(value)
                
                    # 处理嵌套键
                    if '.' in key:
                        self._set_nested_value(config_data[current_section], key, parsed_value)
                    else:
                        config_data[current_section][key] = parsed_value

            except Exception as e:
                logger.warning(f"配置文件第{line_num}行解析错误：{e}（内容：{original_line}）")
                continue

        return config_data

    def _evaluate_condition(self, expr: str, config_data: Dict[str, Any]) -> bool:
        """
        解析并计算条件表达式
        支持的表达式格式：
        - 环境变量判断：${VAR} == "value"
        - 配置值判断：network.scan_domain == "dsls.top"
        - 支持的运算符：==, !=, >, <, >=, <=, in, not in
        - 支持的类型：字符串、数字、布尔值
        """
        import re
    
        # 提取操作数和运算符
        pattern = r'(\S+)\s*([=!<>]=?|in|not in)\s*(\S+)'
        match = re.match(pattern, expr.strip())
        if not match:
            logger.warning(f"无效的条件表达式: {expr}")
            return False

        left_operand, operator, right_operand = match.groups()

        # 解析左操作数（可能是环境变量或配置值）
        left_value = self._resolve_operand(left_operand, config_data)
    
        # 解析右操作数（可能是字符串、数字或布尔值）
        right_value = self._parse_config_value(right_operand.strip('"\''))

        # 执行比较运算
        try:
            if operator == '==':
                return left_value == right_value
            elif operator == '!=':
                return left_value != right_value
            elif operator == '>':
                return float(left_value) > float(right_value)
            elif operator == '<':
                return float(left_value) < float(right_value)
            elif operator == '>=':
                return float(left_value) >= float(right_value)
            elif operator == '<=':
                return float(left_value) <= float(right_value)
            elif operator == 'in':
                return left_value in right_value if isinstance(right_value, list) else False
            elif operator == 'not in':
                return left_value not in right_value if isinstance(right_value, list) else True
            else:
                logger.warning(f"不支持的运算符: {operator}")
                return False
        except (TypeError, ValueError) as e:
            logger.warning(f"条件比较失败: {e}（表达式: {expr}）")
            return False

    def _resolve_operand(self, operand: str, config_data: Dict[str, Any]) -> Any:
        """解析操作数，可能是环境变量或配置值"""
        # 处理环境变量 ${VAR_NAME}
        if operand.startswith('${') and operand.endswith('}'):
            var_name = operand[2:-1]
            return self._resolve_environment_vars(operand)
    
        # 处理配置值 section.key 或 section.parent.child
        if '.' in operand:
            parts = operand.split('.')
            section = parts[0]
            key_path = parts[1:]
        
            if section not in config_data:
                return None
            
            current = config_data[section]
            for key in key_path:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return None
            return current
    
        # 直接返回字符串值
        return operand

    def _resolve_environment_vars(self, value: str) -> str:
        """解析环境变量引用 ${VAR_NAME}"""
        import re
    
        def replace_env_var(match):
            var_name = match.group(1)
            # 首先尝试从环境变量获取
            env_value = os.getenv(var_name)
            if env_value is not None:
                return env_value
            # 如果环境变量不存在，尝试从系统配置获取
            elif var_name == "HOSTNAME":
                return socket.gethostname()
            elif var_name == "IP_ADDRESS":
                return self._get_local_ip()
            else:
                logger.warning(f"环境变量 {var_name} 未设置，使用空值")
                return ""
    
        # 匹配 ${VAR_NAME} 格式
        pattern = r'\$\{([A-Za-z0-9_]+)\}'
        return re.sub(pattern, replace_env_var, value)

    def _get_local_ip(self) -> str:
        """获取本地IP地址"""
        try:
            # 创建一个临时socket来获取本地IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return "127.0.0.1"

    def _parse_config_value(self, value: str) -> Any:
        """解析配置值，支持多种数据类型"""
    
        # 移除引号
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            return value[1:-1]
    
        # 布尔值
        if value.lower() in ('true', 'yes', 'on', '1'):
            return True
        if value.lower() in ('false', 'no', 'off', '0'):
            return False
    
        # 数组/列表 (逗号分隔)
        if ',' in value:
            items = [self._parse_config_value(item.strip()) for item in value.split(',')]
            return items
    
        # 端口范围 (20000-60000)
        if '-' in value and value.replace('-', '').isdigit():
            parts = value.split('-')
            if len(parts) == 2:
                return (int(parts[0]), int(parts[1]))
    
        # 整数
        if value.isdigit():
            return int(value)
    
        # 浮点数
        try:
            return float(value)
        except ValueError:
            pass
    
        # 默认返回字符串
        return value

    def _set_nested_value(self, config_dict: Dict[str, Any], key: str, value: Any):
        """设置嵌套键值 (parent.child格式)"""
        keys = key.split('.')
        current = config_dict
    
        for i, k in enumerate(keys[:-1]):
            if k not in current:
                current[k] = {}
            elif not isinstance(current[k], dict):
                # 如果已存在但不是字典，转换为字典
                current[k] = {"_value": current[k]}
        
            current = current[k]
    
        # 设置最终值
        current[keys[-1]] = value

    def _build_node_config(self, config_data: Dict[str, Any]) -> NodeConfig:
        """将解析的配置数据构建为 NodeConfig 对象"""
    
        # 网络配置
        network_config = config_data.get('network', {})
        scan_domain = network_config.get('scan_domain', 'dsls.top')
        exclude_subdomains = network_config.get('exclude_subdomains', ['mail', 'www', 'ftp', 'admin'])
        initial_nodes = network_config.get('initial_nodes', [])
    
        # 确保exclude_subdomains是列表
        if isinstance(exclude_subdomains, str):
            exclude_subdomains = [exclude_subdomains]
    
        # 确保initial_nodes是列表
        if isinstance(initial_nodes, str):
            initial_nodes = [initial_nodes]
    
        # UPnP配置
        upnp_config = config_data.get('upnp', {})
        upnp_enabled = upnp_config.get('enabled', True)
        tcp_port_range = upnp_config.get('port_range', (20000, 60000))
    
        # 性能配置
        perf_config = config_data.get('performance', {})
        dns_ttl = perf_config.get('dns_ttl', 300)
        heartbeat_interval = perf_config.get('heartbeat_interval', 45)
        discovery_interval = perf_config.get('discovery_interval', 1800)
        maintenance_interval = perf_config.get('maintenance_interval', 600)
    
        # 安全配置
        security_config = config_data.get('security', {})
        encryption_level = security_config.get('encryption_level', 'high')
        max_hops = security_config.get('max_hops', 8)
    
        # 高级配置
        advanced_config = config_data.get('advanced', {})
        log_level = advanced_config.get('log_level', 'INFO')
        max_connections = advanced_config.get('max_connections', 1000)
    
        # 构建性能参数字典
        performance_params = {
            'dns_ttl': dns_ttl,
            'heartbeat_interval': heartbeat_interval,
            'discovery_interval': discovery_interval,
            'maintenance_interval': maintenance_interval,
            'encryption_level': encryption_level,
            'max_hops': max_hops,
            'log_level': log_level,
            'max_connections': max_connections
        }
    
        return NodeConfig(
            scan_domain=scan_domain,
            exclude_subdomains=exclude_subdomains,
            initial_nodes=initial_nodes,
            upnp_enabled=upnp_enabled,
            performance_params=performance_params,
            tcp_port_range=tcp_port_range,
            dns_ttl=dns_ttl,
            heartbeat_interval=heartbeat_interval,
            discovery_interval=discovery_interval,
            maintenance_interval=maintenance_interval
        )

    def _get_default_config(self) -> NodeConfig:
        """获取默认配置"""
        return NodeConfig()

    def save_config_template(self, file_path: str = "config.dpdsls"):
        """保存配置文件模板"""
        template = """# 分布式匿名网络系统配置文件
    # 文件格式: .dpdsls (Distributed Privacy Network Configuration)
    # 编码: UTF-8

    [network]
    # 扫描域名
    scan_domain = dsls.top

    # 排除的子域名列表 (逗号分隔)
    exclude_subdomains = mail, www, ftp, admin

    # 初始节点列表 (逗号分隔)
    initial_nodes = ${HOSTNAME}.dsls.top:8080, backup-node.dsls.top:9090

    [upnp]
    # 是否启用UPnP
    enabled = true

    # TCP端口范围
    port_range = 20000-60000

    [performance]
    # DNS记录TTL (秒)
    dns_ttl = 300

    # 心跳检测间隔 (秒)
    heartbeat_interval = 45

    # 节点发现间隔 (秒)
    discovery_interval = 1800

    # 维护任务间隔 (秒)
    maintenance_interval = 600

    # 最大连接数
    max_connections = 1000

    [security]
    # 加密等级: low, medium, high
    encryption_level = high

    # 最大跳数
    max_hops = 8

    # 数据混淆级别
    obfuscation_level = medium

    [advanced]
    # 日志级别: DEBUG, INFO, WARNING, ERROR
    log_level = INFO

    # 性能监控采样率 (0.0-1.0)
    monitoring_sample_rate = 0.1

    # 缓存大小 (MB)
    cache_size = 100

    # 启用调试模式
    debug_mode = false

    [routing]
    # 路由算法: simple, advanced, adaptive
    algorithm = adaptive

    # 路径选择权重
    weights.reputation = 0.4
    weights.latency = 0.25
    weights.bandwidth = 0.2
    weights.stability = 0.15

    [fragmentation]
    # 默认分片策略
    default_strategy = adaptive

    # 最小分片大小 (字节)
    min_fragment_size = 512

    # 最大分片大小 (字节)
    max_fragment_size = 16384

    # 冗余系数
    redundancy_factor = 1.5
    """
    
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(template)
            logger.info(f"配置文件模板已保存: {file_path}")
            return True
        except Exception as e:
            logger.error(f"保存配置文件模板失败: {e}")
            return False

    def validate_config(self, config: NodeConfig) -> Tuple[bool, List[str]]:
        """验证配置有效性"""
        errors = []
    
        # 验证域名格式
        if not self._is_valid_domain(config.scan_domain):
            errors.append(f"无效的扫描域名: {config.scan_domain}")
    
        # 验证端口范围
        if config.tcp_port_range[0] >= config.tcp_port_range[1]:
            errors.append("TCP端口范围无效")
    
        if config.tcp_port_range[0] < 1024 or config.tcp_port_range[1] > 65535:
            errors.append("TCP端口必须在1024-65535范围内")
    
        # 验证时间间隔
        if config.heartbeat_interval < 10:
            errors.append("心跳间隔不能小于10秒")
    
        if config.discovery_interval < 300:
            errors.append("发现间隔不能小于300秒")
    
        # 验证初始节点格式
        for node in config.initial_nodes:
            if not self._is_valid_node_address(node):
                errors.append(f"无效的节点地址格式: {node}")
    
        return len(errors) == 0, errors

    def _is_valid_domain(self, domain: str) -> bool:
        """验证域名格式"""
        import re
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, domain))

    def _is_valid_node_address(self, address: str) -> bool:
        """验证节点地址格式"""
        import re
        # 格式: hostname:port 或 ip:port
        pattern = r'^[a-zA-Z0-9.-]+:\d+$'
        return bool(re.match(pattern, address))

    def get_config_summary(self, config: NodeConfig) -> Dict[str, Any]:
        """获取配置摘要"""
        return {
            "node_type": getattr(config, 'node_type', '未知'),
            "scan_domain": config.scan_domain,
            "exclude_subdomains": config.exclude_subdomains,
            "initial_nodes_count": len(config.initial_nodes),
            "upnp_enabled": config.upnp_enabled,
            "tcp_port_range": config.tcp_port_range,
            "performance_params": {
                k: v for k, v in config.performance_params.items() 
                if not k.startswith('_')
            }
        }
    
    async def start(self):
        """启动系统"""
        logger.info("开始启动分布式匿名网络系统...")
        
        # 1. 节点初始化流程
        await self._initialize_node()
        
        # 2. 网络环境检测
        await self._detect_network_environment()
        
        # 3. 节点注册
        await self._register_node()
        
        # 4. 启动核心服务
        await self._start_core_services()
        
        self.is_running = True
        logger.info("系统启动完成，准备接收网络请求")
        
        # 启动维护任务
        asyncio.create_task(self._maintenance_loop())
        
    async def _initialize_node(self):
        """节点初始化流程"""
        logger.info("开始节点初始化...")
        
        # 生成节点身份
        self.identity = await self._generate_node_identity()
        logger.info(f"节点身份生成完成: {self.identity.node_id}")
        
    async def _generate_node_identity(self) -> NodeIdentity:
        """生成节点身份信息"""
        # 生成时间戳和随机数据创建节点ID
        timestamp = int(time.time() * 1000)
        random_data = random.getrandbits(128).to_bytes(16, 'big')
        node_id = hashlib.sha256(f"{timestamp}{random_data}".encode()).hexdigest()[:16]
    
        # 使用pycryptodome生成RSA密钥对
        private_key = RSA.generate(2048)
        public_key = private_key.publickey()
        
        # 序列化密钥
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return NodeIdentity(
            node_id=node_id,
            reputation=1000,
            public_key=pub_pem,
            private_key=priv_pem,
            certificate=None  # 简化实现，实际应注册证书
        )
    
    async def _detect_network_environment(self):
        """网络环境检测逻辑"""
        logger.info("开始网络环境检测...")
        
        # 并行执行检测任务
        dns_result = await self._test_dns_reachability()
        upnp_result = await self._test_upnp_capability()
        perf_result = await self._test_network_performance()
        
        # 节点类型判定
        if dns_result["success"] and upnp_result["success"]:
            self.identity.node_type = NodeType.D_NODE
        elif not dns_result["success"] and upnp_result["success"]:
            self.identity.node_type = NodeType.U_NODE
        else:
            self.identity.node_type = NodeType.R_NODE
            
        logger.info(f"节点类型判定: {self.identity.node_type.value}")
        
        # 记录节点能力信息
        self.identity.capabilities = {
            "dns": dns_result,
            "upnp": upnp_result,
            "performance": perf_result
        }
    
    async def _test_dns_reachability(self) -> Dict[str, Any]:
        """DNS可达性测试"""
        try:
            # 测试阿里云DNS API连通性
            async with aiohttp.ClientSession() as session:
                # 这里简化实现，实际应调用阿里云DNS API
                resp = await session.get(f"http://dns.alidns.com", timeout=10)
                success = resp.status == 200
                
            return {
                "success": success,
                "details": "DNS API测试完成"
            }
        except Exception as e:
            logger.warning(f"DNS可达性测试失败: {e}")
            return {"success": False, "error": str(e)}
    
    async def _test_upnp_capability(self) -> Dict[str, Any]:
        """UPnP能力检测"""
        if not self.config.upnp_enabled:
            return {"success": False, "reason": "UPnP已禁用"}
            
        try:
            # 发现UPnP网关
            devices = upnpclient.discover()
            if not devices:
                return {"success": False, "reason": "未发现UPnP设备"}
                
            gateway = devices[0]
            
            # 测试端口映射
            external_port = random.randint(20000, 60000)
            internal_port = external_port
            
            # 添加端口映射
            gateway.AddPortMapping(
                NewRemoteHost='',
                NewExternalPort=external_port,
                NewProtocol='TCP',
                NewInternalPort=internal_port,
                NewInternalClient=socket.gethostbyname(socket.gethostname()),
                NewEnabled='1',
                NewPortMappingDescription='Distributed Anonymous Network',
                NewLeaseDuration=3600
            )
            
            # 验证映射
            mapping = gateway.GetSpecificPortMappingEntry(
                NewRemoteHost='',
                NewExternalPort=external_port,
                NewProtocol='TCP'
            )
            
            success = mapping is not None
            
            # 清理测试映射
            if success:
                gateway.DeletePortMapping(
                    NewRemoteHost='',
                    NewExternalPort=external_port,
                    NewProtocol='TCP'
                )
            
            return {
                "success": success,
                "gateway": gateway.friendly_name,
                "details": "UPnP端口映射测试完成"
            }
            
        except Exception as e:
            logger.warning(f"UPnP能力检测失败: {e}")
            return {"success": False, "error": str(e)}
    
    async def _test_network_performance(self) -> Dict[str, Any]:
        """网络性能基准测试（详细实现）"""
        logger.info("开始网络性能基准测试...")
    
        # 测试目标选择（使用初始节点或公共测试服务器）
        test_targets = self.config.initial_nodes.copy()
        if not test_targets:
            # 若无初始节点，使用公共测试服务器
            test_targets = [
                "ping.baidu.com:80",
                "ping.aliyun.com:80",
                "203.119.162.10:80"  # 公共DNS服务器
            ]
    
        # 1. 延迟测试（ICMP模拟，实际环境可能需要权限）
        latency_results = await self._test_latency(test_targets)
    
        # 2. 带宽测试（上传/下载速度）
        bandwidth_results = await self._test_bandwidth()
    
        # 3. 连接稳定性测试
        stability_results = await self._test_stability(test_targets[:2])
    
        # 4. 包丢失率测试
        packet_loss = await self._test_packet_loss(test_targets[0])
    
        # 综合结果计算
        performance_score = (
            (1 - packet_loss) * 0.3 +
            (1 - latency_results["avg_latency"] / 1000) * 0.2 +
            (bandwidth_results["download_mbps"] / 100) * 0.3 +
            stability_results["stability_score"] * 0.2
        )
    
        logger.info("网络性能基准测试完成")
        return {
            "latency": {
                "avg_latency": latency_results["avg_latency"],
                "min_latency": latency_results["min_latency"],
                "max_latency": latency_results["max_latency"],
                "jitter": latency_results["jitter"]
            },
            "bandwidth": {
                "download_mbps": bandwidth_results["download_mbps"],
                "upload_mbps": bandwidth_results["upload_mbps"],
                "test_duration": bandwidth_results["duration"]
            },
            "stability": {
                "stability_score": stability_results["stability_score"],
                "connection_drops": stability_results["drops"],
                "retry_count": stability_results["retries"]
            },
            "packet_loss": packet_loss,
            "overall_score": round(performance_score, 2)
        }

    async def _test_latency(self, targets: List[str], samples: int = 10) -> Dict[str, float]:
        """测试延迟和抖动"""
        latency_samples = defaultdict(list)
    
        for target in targets:
            host, _ = target.split(':') if ':' in target else (target, 80)
        
            for _ in range(samples):
                try:
                    start = time.time()
                    # 使用TCP连接模拟ICMP ping（避免权限问题）
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(2.0)
                        s.connect((host, 80))
                    end = time.time()
                    latency = (end - start) * 1000  # 转换为毫秒
                    latency_samples[host].append(latency)
                    await asyncio.sleep(0.1)  # 间隔测试
                except (socket.timeout, ConnectionRefusedError):
                    continue
    
        # 计算统计值
        all_latencies = [lat for host_lats in latency_samples.values() for lat in host_lats]
        if not all_latencies:
            return {"avg_latency": 1000.0, "min_latency": 1000.0, "max_latency": 1000.0, "jitter": 100.0}
    
        avg_latency = sum(all_latencies) / len(all_latencies)
        min_latency = min(all_latencies)
        max_latency = max(all_latencies)
    
        # 计算抖动（连续样本差值的平均值）
        jitter = 0.0
        if len(all_latencies) > 1:
            diffs = [abs(all_latencies[i] - all_latencies[i-1]) for i in range(1, len(all_latencies))]
            jitter = sum(diffs) / len(diffs)
    
        return {
            "avg_latency": round(avg_latency, 2),
            "min_latency": round(min_latency, 2),
            "max_latency": round(max_latency, 2),
            "jitter": round(jitter, 2)
        }

    async def _test_bandwidth(self, test_url: str = "https://speed.hetzner.de/100MB.bin", duration: int = 10) -> Dict[str, float]:
        """测试下载/上传带宽"""
        download_speed = 0.0
        upload_speed = 0.0
    
        try:
            # 下载测试
            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.get(test_url, timeout=duration + 5) as resp:
                    data = b''
                    chunk_size = 1024 * 1024  # 1MB块
                    start = time.time()
                
                    async for chunk in resp.content.iter_chunked(chunk_size):
                        data += chunk
                        elapsed = time.time() - start
                        if elapsed >= duration:
                            break
                
                    downloaded_size = len(data) / (1024 * 1024)  # MB
                    download_time = time.time() - start_time
                    download_speed = (downloaded_size * 8) / download_time  # Mbps
        
            # 上传测试（使用随机数据）
            upload_data = os.urandom(10 * 1024 * 1024)  # 10MB测试数据
            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://httpbin.org/post", 
                    data=upload_data,
                    timeout=duration + 5
                ) as resp:
                    await resp.text()
        
            upload_time = time.time() - start_time
            upload_speed = (len(upload_data) * 8 / (1024 * 1024)) / upload_time  # Mbps
        
        except Exception as e:
            logger.warning(f"带宽测试失败: {e}")
    
        return {
            "download_mbps": round(download_speed, 2),
            "upload_mbps": round(upload_speed, 2),
            "duration": round(download_time + upload_time, 2)
        }

    async def _test_stability(self, targets: List[str], test_duration: int = 30) -> Dict[str, Any]:
        """测试连接稳定性"""
        drops = 0
        retries = 0
        total_attempts = 0
        start_time = time.time()
    
        while time.time() - start_time < test_duration:
            for target in targets:
                host, port = target.split(':') if ':' in target else (target, 80)
                port = int(port)
                total_attempts += 1
            
                try:
                    # 建立连接并保持1秒
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(2.0)
                        s.connect((host, port))
                        await asyncio.sleep(1)
                except (socket.timeout, ConnectionResetError):
                    drops += 1
                    # 重试一次
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.settimeout(2.0)
                            s.connect((host, port))
                        retries += 1
                    except:
                        pass
        
            await asyncio.sleep(1)  # 测试间隔
    
        # 稳定性得分（0-1.0）
        stability_score = 1.0 - (drops / total_attempts) if total_attempts > 0 else 0.5
    
        return {
            "stability_score": round(stability_score, 2),
            "drops": drops,
            "retries": retries,
            "total_attempts": total_attempts
        }

    async def _test_packet_loss(self, target: str, packet_count: int = 50) -> float:
        """测试丢包率"""
        host, _ = target.split(':') if ':' in target else (target, 80)
        lost = 0
        sent = 0
    
        for _ in range(packet_count):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    s.connect((host, 80))
                    sent += 1
            except:
                lost += 1
            await asyncio.sleep(0.05)  # 控制发包速率
    
        if sent == 0:
            return 1.0  # 全部丢失
    
        return round(lost / (sent + lost), 4)
    
    async def _register_node(self):
        """节点注册执行逻辑"""
        logger.info(f"开始节点注册，类型: {self.identity.node_type.value}")
        
        if self.identity.node_type == NodeType.D_NODE:
            await self._register_d_node()
        elif self.identity.node_type == NodeType.U_NODE:
            await self._register_u_node()
        else:  # R_NODE
            await self._register_r_node()
            
        logger.info("节点注册完成")
    
    async def _register_d_node(self):
        """D节点注册流程"""
        try:
            # 生成随机子域名
            subdomain = self._generate_random_subdomain()
            
            # 调用DNS API注册A记录
            success = await self._register_dns_record(subdomain)
            if success:
                logger.info(f"D节点DNS注册成功: {subdomain}.{self.config.scan_domain}")
                
                # 在DHT中发布节点能力
                await self._publish_to_dht()
                
                # 加入负载均衡池
                await self._join_load_balancer()
                
        except Exception as e:
            logger.error(f"D节点注册失败: {e}")
    
    async def _register_u_node(self):
        """U节点注册流程"""
        try:
            # 执行UPnP端口映射
            external_port = await self._setup_upnp_mapping()
            
            # 寻找可用D节点
            d_nodes = [node for node in self.node_list.values() 
                      if node.get("type") == NodeType.D_NODE and node.get("active")]
            
            if d_nodes:
                proxy_node = random.choice(d_nodes)
                
                # 发送代理注册请求
                success = await self._send_proxy_registration(proxy_node, external_port)
                if success:
                    logger.info(f"U节点通过代理注册成功")
                    
        except Exception as e:
            logger.error(f"U节点注册失败: {e}")
    
    async def _register_r_node(self):
        """R节点注册流程"""
        try:
            # 连接手动配置的初始节点
            for node_addr in self.config.initial_nodes:
                if await self._connect_to_initial_node(node_addr):
                    logger.info(f"R节点通过初始节点连接成功: {node_addr}")
                    break
            else:
                logger.warning("所有初始节点连接失败")
                
        except Exception as e:
            logger.error(f"R节点注册失败: {e}")
    
    def _generate_random_subdomain(self) -> str:
        """生成随机子域名 (Base58格式)"""
        base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        return ''.join(random.choices(base58_chars, k=8))
    
    async def _start_core_services(self):
        """启动核心服务"""
        logger.info("启动核心服务...")
        
        self.core_services = {
            "tcp_stack": TCPExtensionStack(self),
            "upnp_manager": UPNPManager(self),
            "routing_engine": RoutingEngine(self),
            "discovery_service": NodeDiscoveryService(self),
            "performance_monitor": PerformanceMonitor()
        }
        
        # 启动所有服务
        for service_name, service in self.core_services.items():
            if hasattr(service, 'start'):
                await service.start()
            logger.info(f"服务 {service_name} 已启动")
    
    async def _maintenance_loop(self):
        """维护循环"""
        while self.is_running:
            try:
                # 根据节点类型调整维护周期
                interval = self._get_maintenance_interval()
                logger.debug(f"开始维护周期，间隔 {interval} 秒")
            
                # 健康监控
                await self._health_monitoring()
            
                # DNS记录维护（仅D节点）
                if self.identity.node_type == NodeType.D_NODE:
                    await self._dns_maintenance()
            
                # 路由表优化
                await self._routing_table_optimization()
            
                # 节点清理（移除长期离线节点）
                await self._cleanup_inactive_nodes()
            
                # 等待下一个维护周期
                await asyncio.sleep(interval)
            
            except Exception as e:
                logger.error(f"维护循环异常: {e}", exc_info=True)
                await asyncio.sleep(10)  # 异常后缩短等待时间

    def _get_maintenance_interval(self) -> int:
        """根据节点负载动态调整维护间隔"""
        load_factor = self.performance_monitor.get_system_load()
        base_interval = self.config.maintenance_interval
    
        # 高负载时延长间隔，低负载时缩短间隔
        if load_factor > 0.8:
            return int(base_interval * 1.5)
        elif load_factor < 0.3:
            return int(base_interval * 0.7)
        return base_interval

    async def _health_monitoring(self):
        """健康监控（多维度检查）"""
        logger.info(f"开始健康监控，共 {len(self.node_list)} 个节点需要检查")
    
        # 并发检查节点健康状态（限制并发数避免网络拥塞）
        semaphore = asyncio.Semaphore(10)  # 最多同时检查10个节点
    
        async def check_node(node_id, node_info):
            async with semaphore:
                return await self._check_node_health(node_id, node_info)
    
        # 创建所有检查任务
        check_tasks = [
            check_node(node_id, node_info) 
            for node_id, node_info in self.node_list.items()
        ]
    
        # 执行所有检查并收集结果
        results = await asyncio.gather(*check_tasks)
    
        # 更新节点状态
        for (node_id, is_healthy, details), node_info in zip(results, self.node_list.values()):
            prev_state = node_info.get("active", False)
            node_info["last_check"] = time.time()
            node_info["health_details"] = details
        
            if is_healthy:
                node_info["active"] = True
                node_info["last_seen"] = time.time()
                # 健康状态奖励信誉分
                self._adjust_reputation(node_id, 1)
                if not prev_state:
                    logger.info(f"节点 {node_id} 恢复健康状态")
            else:
                node_info["active"] = False
                # 不健康状态惩罚信誉分
                self._adjust_reputation(node_id, -5)
                consecutive_fails = node_info.get("consecutive_fails", 0) + 1
                node_info["consecutive_fails"] = consecutive_fails
                if consecutive_fails >= 3:
                    logger.warning(f"节点 {node_id} 连续 {consecutive_fails} 次健康检查失败")

    async def _check_node_health(self, node_id: str, node_info: Dict[str, Any]) -> Tuple[str, bool, Dict[str, Any]]:
        """检查单个节点健康状态（多维度验证）"""
        start_time = time.time()
        details = {
            "checks": {},
            "response_time": 0.0,
            "timestamp": start_time
        }
    
        try:
            # 1. 基础连接检查（TCP握手）
            conn_result = await self._check_connection(node_info["address"])
            details["checks"]["connection"] = conn_result
            if not conn_result["success"]:
                return (node_id, False, details)
        
            # 2. 协议响应检查（自定义健康检查协议）
            proto_result = await self._check_protocol_response(node_id, node_info["address"])
            details["checks"]["protocol"] = proto_result
            if not proto_result["success"]:
                return (node_id, False, details)
        
            # 3. 性能指标检查（延迟/带宽是否在可接受范围）
            perf_result = await self._check_performance_metrics(node_id, node_info)
            details["checks"]["performance"] = perf_result
            if not perf_result["success"]:
                return (node_id, False, details)
        
            # 计算总响应时间
            details["response_time"] = time.time() - start_time
            return (node_id, True, details)
        
        except Exception as e:
            details["error"] = str(e)
            details["response_time"] = time.time() - start_time
            return (node_id, False, details)

    async def _check_connection(self, address: str) -> Dict[str, Any]:
        """检查节点基础网络连接"""
        try:
            host, port = address.split(':')
            port = int(port)
        
            start = time.time()
            # 使用非阻塞连接检查
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0  # 5秒超时
            )
            writer.close()
            await writer.wait_closed()
        
            return {
                "success": True,
                "latency": (time.time() - start) * 1000,  # 毫秒
                "timestamp": time.time()
            }
        except (asyncio.TimeoutError, ConnectionRefusedError) as e:
            return {
                "success": False,
                "error": str(e),
                "timestamp": time.time()
            }

    async def _check_protocol_response(self, node_id: str, address: str) -> Dict[str, Any]:
        """检查节点协议响应（自定义健康检查命令）"""
        try:
            host, port = address.split(':')
            port = int(port)
        
            # 发送健康检查协议包
            reader, writer = await asyncio.open_connection(host, port)
        
            # 构建健康检查请求
            request = {
                "type": "health_check",
                "sender_id": self.identity.node_id,
                "timestamp": time.time(),
                "nonce": random.getrandbits(64)
            }
        
            # 发送请求（简单协议：JSON字符串+换行符）
            writer.write(json.dumps(request).encode() + b'\n')
            await writer.drain()
        
            # 等待响应
            data = await asyncio.wait_for(reader.readuntil(b'\n'), timeout=3.0)
            response = json.loads(data.decode().strip())
        
            writer.close()
            await writer.wait_closed()
        
            # 验证响应合法性
            if (response.get("type") == "health_response" and 
                response.get("node_id") == node_id and 
                response.get("status") == "ok"):
            
                return {
                    "success": True,
                    "load": response.get("system_load", 0.0),
                    "connections": response.get("active_connections", 0),
                    "timestamp": time.time()
                }
        
            return {"success": False, "error": "无效响应格式", "timestamp": time.time()}
        
        except Exception as e:
            return {"success": False, "error": str(e), "timestamp": time.time()}

    async def _check_performance_metrics(self, node_id: str, node_info: Dict[str, Any]) -> Dict[str, Any]:
        """检查节点性能指标是否达标"""
        # 获取历史性能数据
        perf_data = self.performance_monitor.get_node_performance(node_id)
        if not perf_data:
            return {"success": True, "warning": "无历史性能数据", "timestamp": time.time()}
    
        # 检查延迟是否在可接受范围（基于历史平均值）
        avg_latency = perf_data.get("avg_latency", 100)
        current_latency = node_info["health_details"]["checks"]["connection"]["latency"]
        latency_ok = current_latency < avg_latency * 2  # 不超过历史平均的2倍
    
        # 检查节点负载
        system_load = node_info["health_details"]["checks"]["protocol"].get("load", 1.0)
        load_ok = system_load < 0.8  # 负载不超过80%
    
        # 检查连接数是否在合理范围
        connections = node_info["health_details"]["checks"]["protocol"].get("connections", 0)
        max_connections = node_info.get("max_connections", 1000)
        connections_ok = connections < max_connections * 0.8  # 不超过最大连接数的80%
    
        success = latency_ok and load_ok and connections_ok
    
        return {
            "success": success,
            "latency_check": {
                "current": current_latency,
                "average": avg_latency,
                "ok": latency_ok
            },
            "load_check": {
                "current": system_load,
                "ok": load_ok
            },
            "connections_check": {
                "current": connections,
                "max": max_connections,
                "ok": connections_ok
            },
            "timestamp": time.time()
        }

    async def _cleanup_inactive_nodes(self):
        """清理长期不活跃节点"""
        now = time.time()
        cleanup_count = 0
        threshold = 3600  # 1小时未活跃则清理
    
        for node_id in list(self.node_list.keys()):
            node_info = self.node_list[node_id]
            last_seen = node_info.get("last_seen", 0)
        
            if now - last_seen > threshold and not node_info.get("active", False):
                # 记录清理原因
                logger.info(
                    f"清理不活跃节点 {node_id}，"
                    f"最后活跃时间: {time.ctime(last_seen)}"
                )
            
                # 从路由表中移除
                self._remove_node_from_routing(node_id)
            
                # 从节点列表中移除
                del self.node_list[node_id]
                cleanup_count += 1
    
        if cleanup_count > 0:
            logger.info(f"完成节点清理，共移除 {cleanup_count} 个不活跃节点")

    def _adjust_reputation(self, node_id: str, delta: int):
        """调整节点信誉分"""
        if node_id in self.node_list:
            current = self.node_list[node_id].get("reputation", 1000)
            new_rep = max(0, min(2000, current + delta))  # 限制在0-2000范围内
            self.node_list[node_id]["reputation"] = new_rep
            if delta != 0:
                logger.debug(f"节点 {node_id} 信誉分调整: {current} → {new_rep} (Δ{delta})")

    def _remove_node_from_routing(self, node_id: str):
        """从路由表中移除节点"""
        # 移除以该节点为终点的路由
        for path_key in list(self.routing_table.keys()):
            if node_id in path_key:
                del self.routing_table[path_key]
    
        # 更新经过该节点的路由
        for path_key, route_info in self.routing_table.items():
            if node_id in route_info.get("path", []):
                logger.debug(f"路由 {path_key} 包含已移除节点 {node_id}，需要重新计算")
                # 标记为需要重新计算
                route_info["needs_recalculation"] = True
    
async def _dns_maintenance(self):
    """DNS记录维护（仅D节点执行）"""
    if self.identity.node_type != NodeType.D_NODE:
        return

    try:
        logger.info("开始DNS记录维护流程")
        
        # 1. 验证当前DNS记录状态
        current_records = await self._check_dns_records()
        
        # 2. 检查记录有效性和TTL
        records_to_update = []
        for record in current_records:
            # 检查TTL是否低于阈值
            if record.get('ttl', 0) < self.config.dns_ttl * 0.3:
                records_to_update.append(record)
                logger.debug(f"DNS记录 {record['name']} TTL不足，需要更新")
            
            # 检查IP是否变更
            if record.get('type') == 'A' and record.get('value') != self._get_public_ip():
                records_to_update.append(record)
                logger.debug(f"DNS记录 {record['name']} IP地址变更，需要更新")
        
        # 3. 处理新增/更新记录
        if records_to_update:
            update_result = await self._update_dns_records(records_to_update)
            if update_result['success']:
                logger.info(f"成功更新 {len(records_to_update)} 条DNS记录")
            else:
                logger.error(f"DNS记录更新失败: {update_result['error']}")
                # 尝试备份DNS服务
                if hasattr(self, '_backup_dns_provider'):
                    logger.info("尝试使用备份DNS服务更新")
                    backup_result = await self._backup_dns_provider.update_records(records_to_update)
                    if backup_result['success']:
                        logger.warning("已通过备份DNS服务完成更新")
                    else:
                        logger.error(f"备份DNS服务更新同样失败: {backup_result['error']}")
        
        # 4. 清理过期子域名
        expired_domains = await self._find_expired_subdomains()
        if expired_domains:
            cleanup_result = await self._delete_dns_records(expired_domains)
            if cleanup_result['success']:
                logger.info(f"成功清理 {len(expired_domains)} 个过期子域名")
            else:
                logger.error(f"过期子域名清理失败: {cleanup_result['error']}")
        
        # 5. 记录维护状态
        self.performance_monitor.record_dns_maintenance({
            'timestamp': time.time(),
            'updated': len(records_to_update),
            'cleaned': len(expired_domains),
            'status': 'completed'
        })
        
    except Exception as e:
        logger.error(f"DNS记录维护异常: {e}", exc_info=True)
        self.performance_monitor.record_dns_maintenance({
            'timestamp': time.time(),
            'status': 'failed',
            'error': str(e)
        })

async def _check_dns_records(self) -> List[Dict[str, Any]]:
    """检查当前DNS记录状态"""
    try:
        # 实现具体DNS服务商API调用（如Cloudflare、阿里云DNS等）
        async with aiohttp.ClientSession() as session:
            headers = {
                'Authorization': f"Bearer {self.config.dns_api_token}",
                'Content-Type': 'application/json'
            }
            
            # 构建查询请求（示例为Cloudflare API格式）
            url = f"https://api.cloudflare.com/client/v4/zones/{self.config.dns_zone_id}/dns_records"
            params = {'name': f"*.{self.config.scan_domain}"}
            
            async with session.get(url, headers=headers, params=params) as resp:
                data = await resp.json()
                
                if not data.get('success'):
                    raise Exception(f"DNS查询失败: {data.get('errors', ['未知错误'])}")
                
                # 提取需要的记录信息
                return [{
                    'id': record['id'],
                    'name': record['name'],
                    'type': record['type'],
                    'value': record['content'],
                    'ttl': record['ttl'],
                    'proxied': record['proxied']
                } for record in data['result']]
                
    except Exception as e:
        logger.error(f"检查DNS记录失败: {e}")
        return []

async def _update_dns_records(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """更新DNS记录"""
    updated_count = 0
    errors = []
    
    for record in records:
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    'Authorization': f"Bearer {self.config.dns_api_token}",
                    'Content-Type': 'application/json'
                }
                
                # 更新A记录IP为当前公网IP
                if record['type'] == 'A':
                    record['value'] = self._get_public_ip()
                
                # 确保TTL符合配置
                record['ttl'] = self.config.dns_ttl
                
                url = f"https://api.cloudflare.com/client/v4/zones/{self.config.dns_zone_id}/dns_records/{record['id']}"
                async with session.put(url, headers=headers, json=record) as resp:
                    data = await resp.json()
                    
                    if data.get('success'):
                        updated_count += 1
                    else:
                        errors.append(f"记录 {record['name']} 更新失败: {data.get('errors')}")
        
        except Exception as e:
            errors.append(f"记录 {record['name']} 处理异常: {str(e)}")
    
    return {
        'success': len(errors) == 0,
        'updated': updated_count,
        'errors': errors
    }

async def _find_expired_subdomains(self) -> List[Dict[str, Any]]:
    """查找过期的子域名记录"""
    expired = []
    current_time = time.time()
    
    # 检查所有关联的子域名（假设在节点列表中维护了子域名映射）
    for node_id, node_info in self.node_list.items():
        if node_info.get('type') == NodeType.U_NODE and 'subdomain' in node_info:
            # 检查节点是否长时间不活跃
            last_seen = node_info.get('last_seen', 0)
            if current_time - last_seen > self.config.dns_ttl * 2:  # 超过2个TTL周期未活跃
                expired.append({
                    'name': node_info['subdomain'],
                    'type': 'A',
                    'id': node_info.get('dns_record_id')
                })
                logger.debug(f"子域名 {node_info['subdomain']} 因节点过期将被清理")
    
    return expired

    async def _delete_dns_records(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """删除DNS记录"""
        deleted_count = 0
        errors = []
    
        for record in records:
            try:
                if not record.get('id'):
                    continue  # 没有记录ID无法删除
            
                async with aiohttp.ClientSession() as session:
                    headers = {
                        'Authorization': f"Bearer {self.config.dns_api_token}",
                        'Content-Type': 'application/json'
                    }
                
                    url = f"https://api.cloudflare.com/client/v4/zones/{self.config.dns_zone_id}/dns_records/{record['id']}"
                    async with session.delete(url, headers=headers) as resp:
                        data = await resp.json()
                    
                        if data.get('success'):
                            deleted_count += 1
                        else:
                            errors.append(f"记录 {record['name']} 删除失败: {data.get('errors')}")
        
            except Exception as e:
                errors.append(f"记录 {record['name']} 删除异常: {str(e)}")
    
        return {
            'success': len(errors) == 0,
            'deleted': deleted_count,
            'errors': errors
        }

    def _get_public_ip(self) -> str:
        """获取当前公网IP地址"""
        try:
            # 通过第三方服务获取公网IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
        
            # 检查是否为内网IP，如果是则通过HTTP服务获取
            if self._is_private_ip(local_ip):
                import requests
                return requests.get("https://api.ipify.org", timeout=10).text
        
            return local_ip
        except Exception as e:
            logger.error(f"获取公网IP失败: {e}")
            #  fallback到配置的备用IP
            return self.config.performance_params.get('fallback_ip', '127.0.0.1')

    def _is_private_ip(self, ip: str) -> bool:
        """判断是否为内网IP"""
        import ipaddress
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
    
    async def _routing_table_optimization(self):
        """路由表优化"""
        # 分析性能数据并优化路由
        performance_data = self.performance_monitor.get_performance_stats()
        
        for path, stats in performance_data.items():
            if stats["success_rate"] < 0.8:
                # 标记问题路径
                self.routing_table[path]["weight"] *= 0.8
    
    async def handle_client_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """处理客户端请求"""
        try:
            # 请求解析和准备
            parsed_request = await self._parse_request(request_data)
            
            # 智能分片规划
            fragmentation_plan = await self._plan_fragmentation(parsed_request)
            
            # 会话管理初始化
            session = await self.session_manager.create_session(parsed_request, fragmentation_plan)
            
            # 分片封装与发送
            await self._fragment_and_send(session, parsed_request)
            
            return {"session_id": session.session_id, "status": "processing"}
            
        except Exception as e:
            logger.error(f"处理客户端请求失败: {e}")
            return {"error": str(e), "status": "failed"}
    
    async def _parse_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """解析请求"""
        # 提取URL信息
        url = request_data.get("url", "")
        
        # 构建HTTP请求
        http_request = {
            "method": request_data.get("method", "GET"),
            "url": url,
            "headers": request_data.get("headers", {}),
            "body": request_data.get("body", b"")
        }
        
        # 分析请求特征
        estimated_size = len(http_request["body"]) + len(str(http_request["headers"]))
        content_type = http_request["headers"].get("Content-Type", "unknown")
        
        return {
            "http_request": http_request,
            "estimated_size": estimated_size,
            "content_type": content_type,
            "url": url
        }
    
    async def _plan_fragmentation(self, parsed_request: Dict[str, Any]) -> Dict[str, Any]:
        """智能分片规划"""
        size = parsed_request["estimated_size"]
        content_type = parsed_request["content_type"]
        
        # 基于请求大小选择分片数
        if size < 1024:  # <1KB
            num_fragments = random.randint(1, 2)
        elif size < 10240:  # 1KB-10KB
            num_fragments = random.randint(3, 5)
        elif size < 102400:  # 10KB-100KB
            num_fragments = random.randint(6, 10)
        else:  # >100KB
            num_fragments = random.randint(10, 20)
        
        # 内容感知分片策略
        if "html" in content_type:
            fragment_strategy = "tag_boundary"
        elif "json" in content_type:
            fragment_strategy = "structural"
        elif "image" in content_type or "video" in content_type:
            fragment_strategy = "binary"
        else:
            fragment_strategy = "equal_size"
        
        # 冗余策略
        redundancy_factor = 1.5  # 默认1.5倍冗余
        if size < 10240:  # 小文件增加冗余
            redundancy_factor = 2.0
        
        return {
            "num_fragments": num_fragments,
            "strategy": fragment_strategy,
            "redundancy_factor": redundancy_factor,
            "estimated_size": size
        }
    
    async def _fragment_and_send(self, session, parsed_request: Dict[str, Any]):
        """分片封装与发送"""
        data = parsed_request["http_request"]["body"]
        total_size = len(data)
        fragment_size = total_size // session.fragmentation_plan["num_fragments"]
        
        for i in range(session.fragmentation_plan["num_fragments"]):
            start = i * fragment_size
            end = start + fragment_size if i < session.fragmentation_plan["num_fragments"] - 1 else total_size
            
            fragment_data = data[start:end]
            
            # 创建分片
            fragment = NetworkFragment(
                session_id=session.session_id,
                fragment_index=i,
                total_fragments=session.fragmentation_plan["num_fragments"],
                data=fragment_data,
                priority=self._determine_fragment_priority(i, parsed_request),
                offset=start,
                checksum=hashlib.md5(fragment_data).hexdigest(),
                timestamp=time.time()
            )
            
            # 封装分片
            encapsulated_fragment = await self._encapsulate_fragment(fragment)
            
            # 选择路径并发送
            await self._send_fragment(encapsulated_fragment, session)
    
    def _determine_fragment_priority(self, index: int, parsed_request: Dict[str, Any]) -> FragmentPriority:
        """确定分片优先级"""
        content_type = parsed_request["content_type"]
        
        if index == 0:  # 第一个分片通常是关键信息
            return FragmentPriority.HIGH
        elif "html" in content_type and index < 3:  # HTML前几个分片重要
            return FragmentPriority.HIGH
        elif "image" in content_type:
            return FragmentPriority.MEDIUM
        else:
            return FragmentPriority.LOW
    
    async def _encapsulate_fragment(self, fragment: NetworkFragment) -> Dict[str, Any]:
        """分片封装"""
        # TCP扩展参数生成
        tcp_params = {
            "session_id": fragment.session_id,
            "total_fragments": fragment.total_fragments,
            "fragment_index": fragment.fragment_index,
            "fragment_size": len(fragment.data),
            "flags": fragment.flags,
            "max_hops": random.randint(4, 8),
            "current_hops": 0,
            "path_hash": hashlib.sha256(fragment.session_id.encode()).hexdigest()[:16],
            "ttl": 300
        }
        
        # 参数混淆处理
        obfuscated_params = await self._obfuscate_parameters(tcp_params)
        
        return {
            "original_fragment": fragment,
            "tcp_params": obfuscated_params,
            "encrypted_data": await self._encrypt_data(fragment.data)
        }
    
    async def _obfuscate_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """参数混淆处理"""
        obfuscated = params.copy()
        
        # 数值扰动
        if "max_hops" in obfuscated:
            obfuscated["max_hops"] += random.randint(-1, 1)
        
        if "fragment_size" in obfuscated:
            perturbation = obfuscated["fragment_size"] * random.uniform(-0.02, 0.02)
            obfuscated["fragment_size"] = int(obfuscated["fragment_size"] + perturbation)
        
        # 随机填充
        obfuscated["padding"] = os.urandom(random.randint(8, 32))
        
        # 加密混淆
        obfuscated["encrypted_params"] = await self._encrypt_params(json.dumps(obfuscated).encode())
        
        return obfuscated
    
    async def _encrypt_data(self, data: bytes) -> bytes:
        """加密数据"""
        # 使用pycryptodome的ChaCha20加密
        key = get_random_bytes(32)  # 32字节密钥
        nonce = get_random_bytes(8)  # 8字节nonce（pycryptodome的ChaCha20要求）
        cipher = ChaCha20.new(key=key, nonce=nonce)
        encrypted_data = cipher.encrypt(data)
        # 返回nonce+密文（解密时需要nonce）
        return nonce + encrypted_data

    async def _encrypt_params(self, params: bytes) -> bytes:
        """加密参数（结合ChaCha20对称加密与SHA-256完整性校验）"""
        try:
            # 1. 生成会话密钥（使用节点私钥派生，确保每次会话唯一性）
            if not self.identity.private_key:
                raise ValueError("节点私钥未初始化，无法进行参数加密")
        
            # 从私钥派生32字节密钥（用于ChaCha20）
            key_material = hashlib.pbkdf2_hmac(
                'sha256',
                self.identity.private_key,  # 私钥作为派生基础
                get_random_bytes(16),       # 随机盐值
                100000,                     # 迭代次数
                dklen=32                    # 输出32字节密钥
            )
        
            # 2. 生成8字节nonce（ChaCha20要求）
            nonce = get_random_bytes(8)
        
            # 3. 使用ChaCha20加密参数
            cipher = ChaCha20.new(key=key_material, nonce=nonce)
            encrypted_data = cipher.encrypt(params)
        
            # 4. 计算加密后数据的SHA-256哈希（确保完整性）
            checksum = hashlib.sha256(encrypted_data).digest()
        
            # 5. 组合nonce + 校验和 + 密文（解密时需解析）
            # 格式：[8字节nonce][32字节checksum][加密数据]
            encrypted_params = nonce + checksum + encrypted_data
        
            return encrypted_params
        except Exception as e:
            logger.error(f"参数加密失败: {e}")
            raise  # 抛出异常供上层处理
    
    async def _send_fragment(self, encapsulated_fragment: Dict[str, Any], session):
        """发送分片"""
        # 路径选择算法
        available_paths = await self._select_available_paths(encapsulated_fragment)
        
        # 根据优先级分配路径数量
        priority = encapsulated_fragment["original_fragment"].priority
        if priority == FragmentPriority.HIGH:
            num_paths = 3
        elif priority == FragmentPriority.MEDIUM:
            num_paths = 2
        else:
            num_paths = 1
        
        selected_paths = available_paths[:num_paths]
        
        # 并行发送
        send_tasks = []
        for path in selected_paths:
            task = asyncio.create_task(
                self._send_via_path(encapsulated_fragment, path)
            )
            send_tasks.append(task)
        
        # 等待发送完成
        await asyncio.gather(*send_tasks, return_exceptions=True)
    
    async def _select_available_paths(self, fragment: Dict[str, Any]) -> List[Dict[str, Any]]:
        """选择可用路径"""
        available_nodes = [
            node for node in self.node_list.values() 
            if node.get("active") and node.get("reputation", 0) > 500
        ]
        
        # 计算综合评分
        scored_paths = []
        for node in available_nodes:
            score = self._calculate_node_score(node)
            scored_paths.append((score, node))
        
        # 按评分排序
        scored_paths.sort(key=lambda x: x[0], reverse=True)
        
        return [path[1] for path in scored_paths]
    
    def _calculate_node_score(self, node: Dict[str, Any]) -> float:
        """计算节点综合评分"""
        reputation = node.get("reputation", 500) / 1000.0  # 归一化
        latency = max(0, 1 - (node.get("latency", 100) / 1000.0))  # 延迟越低越好
        bandwidth = min(1.0, node.get("bandwidth", 10) / 100.0)  # 带宽越高越好
        stability = node.get("stability", 0.5)
        
        # 权重计算
        weights = {
            "reputation": 0.4,
            "latency": 0.25,
            "bandwidth": 0.2,
            "stability": 0.15
        }
        
        return (
            reputation * weights["reputation"] +
            latency * weights["latency"] +
            bandwidth * weights["bandwidth"] +
            stability * weights["stability"]
        )
    
    async def _send_via_path(self, fragment: Dict[str, Any], path: Dict[str, Any]):
        """通过指定路径发送分片"""
        try:
            # 建立连接
            reader, writer = await asyncio.open_connection(
                path["host"], path["port"]
            )
            
            # 构建发送数据
            send_data = {
                "fragment": fragment,
                "timestamp": time.time(),
                "sender_id": self.identity.node_id
            }
            
            # 发送数据
            data_bytes = json.dumps(send_data).encode()
            writer.write(data_bytes)
            await writer.drain()
            
            logger.debug(f"分片通过路径发送到 {path['host']}:{path['port']}")
            
            # 关闭连接
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            logger.warning(f"通过路径发送失败: {e}")
    
    async def stop(self):
        """停止系统"""
        logger.info("正在停止分布式匿名网络系统...")
        self.is_running = False
        
        # 停止所有服务
        for service_name, service in self.core_services.items():
            if hasattr(service, 'stop'):
                await service.stop()
        
        logger.info("系统已停止")

class SessionManager:
    """会话管理器"""
    
    def __init__(self):
        self.sessions = {}
        self.fragment_buffers = defaultdict(dict)
    
    async def create_session(self, parsed_request: Dict[str, Any], fragmentation_plan: Dict[str, Any]) -> 'Session':
        """创建新会话"""
        session_id = hashlib.sha256(
            f"{time.time()}{random.getrandbits(128)}".encode()
        ).hexdigest()[:16]
        
        session = Session(
            session_id=session_id,
            request=parsed_request,
            fragmentation_plan=fragmentation_plan,
            created_at=time.time()
        )
        
        self.sessions[session_id] = session
        return session
    
    async def receive_fragment(self, fragment: NetworkFragment):
        """接收分片"""
        session_id = fragment.session_id
        
        if session_id not in self.sessions:
            logger.warning(f"收到未知会话的分片: {session_id}")
            return
        
        # 存储分片
        self.fragment_buffers[session_id][fragment.fragment_index] = fragment
        
        # 检查是否所有分片都已收到
        session = self.sessions[session_id]
        received_count = len(self.fragment_buffers[session_id])
        
        if received_count >= session.fragmentation_plan["num_fragments"]:
            await self._reassemble_session(session_id)
    
    async def _reassemble_session(self, session_id: str):
        """重组会话数据"""
        fragments = self.fragment_buffers[session_id]
        
        # 按索引排序分片
        sorted_fragments = [fragments[i] for i in sorted(fragments.keys())]
        
        # 重组数据
        reassembled_data = b"".join(fragment.data for fragment in sorted_fragments)
        
        # 验证数据完整性
        if self._verify_reassembled_data(reassembled_data, sorted_fragments):
            session = self.sessions[session_id]
            session.reassembled_data = reassembled_data
            session.completed_at = time.time()
            
            logger.info(f"会话 {session_id} 数据重组完成")
            
            # 清理缓冲区
            del self.fragment_buffers[session_id]
            
            # 触发响应处理
            await self._handle_completed_session(session)
    
    def _verify_reassembled_data(self, data: bytes, fragments: List[NetworkFragment]) -> bool:
        """验证重组数据完整性"""
        # 检查总大小
        total_size = sum(len(fragment.data) for fragment in fragments)
        if len(data) != total_size:
            logger.warning("重组数据大小不匹配")
            return False
        
        # 验证分片校验和
        for fragment in fragments:
            if hashlib.md5(fragment.data).hexdigest() != fragment.checksum:
                logger.warning(f"分片 {fragment.fragment_index} 校验和失败")
                return False
        
        return True
    
    async def _handle_completed_session(self, session: 'Session'):
        """处理完成的会话"""
        # 这里应该将重组的数据传递给出口节点或直接响应
        logger.info(f"处理完成会话: {session.session_id}")

class Session:
    """会话类"""
    
    def __init__(self, session_id: str, request: Dict[str, Any], 
                 fragmentation_plan: Dict[str, Any], created_at: float):
        self.session_id = session_id
        self.request = request
        self.fragmentation_plan = fragmentation_plan
        self.created_at = created_at
        self.completed_at = None
        self.reassembled_data = None
        self.status = "active"

class PerformanceMonitor:
    """性能监控器"""
    
    def __init__(self):
        self.metrics = {
            "latency": deque(maxlen=1000),
            "throughput": deque(maxlen=100),
            "error_rate": deque(maxlen=100),
            "node_health": {}
        }
        self.start_time = time.time()
    
    def record_latency(self, latency: float):
        """记录延迟"""
        self.metrics["latency"].append(latency)
    
    def record_throughput(self, throughput: float):
        """记录吞吐量"""
        self.metrics["throughput"].append(throughput)
    
    def record_error(self, error_type: str):
        """记录错误"""
        self.metrics["error_rate"].append(error_type)
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """获取性能统计"""
        latencies = list(self.metrics["latency"])
        throughputs = list(self.metrics["throughput"])
        
        stats = {
            "avg_latency": sum(latencies) / len(latencies) if latencies else 0,
            "max_latency": max(latencies) if latencies else 0,
            "min_latency": min(latencies) if latencies else 0,
            "avg_throughput": sum(throughputs) / len(throughputs) if throughputs else 0,
            "error_count": len(self.metrics["error_rate"]),
            "uptime": time.time() - self.start_time
        }
        
        return stats

class TCPExtensionStack:
    """TCP扩展协议栈"""
    
    def __init__(self, network: DistributedAnonymousNetwork):
        self.network = network
        self.is_running = False
    
    async def start(self):
        """启动TCP扩展协议栈"""
        self.is_running = True
        # 启动TCP监听器
        asyncio.create_task(self._tcp_listener())
    
    async def stop(self):
        """停止TCP扩展协议栈"""
        self.is_running = False
    
    async def _tcp_listener(self):
        """TCP监听器 - 处理 incoming 连接和消息"""
        # 从配置中获取端口范围
        min_port, max_port = self.config.tcp_port_range
        listen_port = random.randint(min_port, max_port)
    
        logger.info(f"启动TCP监听器，监听端口: {listen_port}")
    
        # 启动TCP服务器
        server = await asyncio.start_server(
            self._handle_tcp_connection,
            '0.0.0.0',  # 监听所有可用网络接口
            listen_port
        )
    
        # 如果启用UPnP，设置端口映射
        if self.config.upnp_enabled:
            await self._setup_upnp_port_mapping(listen_port)
    
        # 记录监听信息
        self.core_services['tcp_listener'] = {
            'port': listen_port,
            'status': 'running',
            'start_time': time.time()
        }
    
        try:
            async with server:
                await server.serve_forever()
        except Exception as e:
            logger.error(f"TCP监听器异常: {e}")
            self.core_services['tcp_listener']['status'] = 'error'
        finally:
            if self.config.upnp_enabled:
                await self._remove_upnp_port_mapping(listen_port)
            self.core_services['tcp_listener']['status'] = 'stopped'
            logger.info("TCP监听器已停止")

    async def _handle_tcp_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理新的TCP连接"""
        peer_addr = writer.get_extra_info('peername')
        logger.info(f"新的TCP连接来自: {peer_addr}")
    
        # 记录连接统计
        self.performance_monitor.record_connection(peer_addr)
    
        try:
            # 交换节点身份信息
            if not await self._exchange_identity(reader, writer):
                logger.warning(f"与 {peer_addr} 的身份验证失败，关闭连接")
                return
        
            # 持续处理消息
            while True:
                # 读取消息长度 (4字节，大端格式)
                length_data = await reader.readexactly(4)
                message_length = struct.unpack('>I', length_data)[0]
            
                # 读取消息内容
                data = await reader.readexactly(message_length)
            
                # 解密消息
                decrypted_data = await self._decrypt_message(data)
            
                # 解析消息
                message = self._parse_message(decrypted_data)
            
                # 处理消息并获取响应
                response = await self._process_message(message, peer_addr)
            
                if response:
                    # 加密响应
                    encrypted_response = await self._encrypt_message(response)
                
                    # 发送响应长度和内容
                    writer.write(struct.pack('>I', len(encrypted_response)))
                    writer.write(encrypted_response)
                    await writer.drain()
                
                # 检查是否需要关闭连接
                if message.get('type') == 'disconnect':
                    break
                
        except (asyncio.IncompleteReadError, ConnectionResetError):
            logger.info(f"与 {peer_addr} 的连接已关闭")
        except Exception as e:
            logger.error(f"处理TCP连接时出错 {peer_addr}: {e}")
        finally:
            # 清理连接
            writer.close()
            await writer.wait_closed()
            self.performance_monitor.record_disconnection(peer_addr)
            logger.info(f"与 {peer_addr} 的连接已关闭")

    async def _exchange_identity(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        """与连接的节点交换身份信息并验证"""
        # 发送自己的身份信息 (公钥)
        identity_data = json.dumps({
            'node_id': self.identity.node_id,
            'public_key': base64.b64encode(self.identity.public_key).decode(),
            'node_type': self.identity.node_type.value
        }).encode()
    
        # 发送身份信息长度和内容
        writer.write(struct.pack('>I', len(identity_data)))
        writer.write(identity_data)
        await writer.drain()
    
        # 接收对方身份信息
        length_data = await reader.readexactly(4)
        identity_length = struct.unpack('>I', length_data)[0]
        peer_identity_data = await reader.readexactly(identity_length)
        peer_identity = json.loads(peer_identity_data.decode())
    
        # 验证对方身份
        try:
            peer_public_key = RSA.import_key(base64.b64decode(peer_identity['public_key']))
            # 这里可以添加更严格的身份验证逻辑
        
            # 记录节点信息
            self.node_list[peer_identity['node_id']] = {
                'address': writer.get_extra_info('peername'),
                'public_key': peer_public_key,
                'node_type': peer_identity['node_type'],
                'last_seen': time.time()
            }
        
            logger.info(f"成功验证节点 {peer_identity['node_id']} 的身份")
            return True
        except Exception as e:
            logger.warning(f"验证节点身份失败: {e}")
            return False

    async def _encrypt_message(self, message: Dict[str, Any]) -> bytes:
        """加密消息"""
        # 序列化消息
        message_data = json.dumps(message).encode()
    
        # 生成随机密钥
        key = get_random_bytes(32)  # ChaCha20使用32字节密钥
    
        # 使用ChaCha20加密
        nonce = get_random_bytes(12)  # 96位nonce
        cipher = ChaCha20.new(key=key, nonce=nonce)
        encrypted_data = cipher.encrypt(message_data)
    
        # 使用接收方公钥加密密钥 (这里简化处理，实际应使用目标节点的公钥)
        # 从节点列表获取目标公钥的逻辑需要根据实际情况实现
        target_node_id = message.get('target_node_id')
        if not target_node_id or target_node_id not in self.node_list:
            raise ValueError("目标节点不存在或未指定")
        
        target_public_key = self.node_list[target_node_id]['public_key']
        cipher_rsa = PKCS1_OAEP.new(target_public_key)
        encrypted_key = cipher_rsa.encrypt(key)
    
        # 组合: 加密的密钥长度(4字节) + 加密的密钥 + nonce(12字节) + 加密的数据
        return struct.pack('>I', len(encrypted_key)) + encrypted_key + nonce + encrypted_data

    async def _decrypt_message(self, data: bytes) -> Dict[str, Any]:
        """解密消息"""
        # 解析数据结构
        key_length = struct.unpack('>I', data[:4])[0]
        key_end = 4 + key_length
        nonce_end = key_end + 12  # nonce长度为12字节
    
        encrypted_key = data[4:key_end]
        nonce = data[key_end:nonce_end]
        encrypted_data = data[nonce_end:]
    
        # 使用私钥解密密钥
        private_key = RSA.import_key(self.identity.private_key)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        key = cipher_rsa.decrypt(encrypted_key)
    
        # 使用ChaCha20解密数据
        cipher = ChaCha20.new(key=key, nonce=nonce)
        decrypted_data = cipher.decrypt(encrypted_data)
    
        # 反序列化消息
        return json.loads(decrypted_data.decode())

    def _parse_message(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """解析消息内容"""
        # 验证消息完整性
        if 'checksum' not in data:
            raise ValueError("消息缺少校验和")
        
        message_data = {k: v for k, v in data.items() if k != 'checksum'}
        checksum = self._calculate_checksum(message_data)
    
        if checksum != data['checksum']:
            raise ValueError("消息校验和不匹配，可能被篡改")
        
        return data

    def _calculate_checksum(self, data: Dict[str, Any]) -> str:
        """计算消息校验和"""
        data_str = json.dumps(data, sort_keys=True).encode()
        return hashlib.sha256(data_str).hexdigest()

    async def _process_message(self, message: Dict[str, Any], peer_addr: Tuple[str, int]) -> Optional[Dict[str, Any]]:
        """处理收到的消息并返回响应"""
        message_type = message.get('type')
        logger.info(f"收到来自 {peer_addr} 的消息类型: {message_type}")
    
        try:
            if message_type == 'ping':
                # 处理心跳消息
                return {
                    'type': 'pong',
                    'node_id': self.identity.node_id,
                    'timestamp': time.time(),
                    'checksum': self._calculate_checksum({
                        'type': 'pong',
                        'node_id': self.identity.node_id,
                        'timestamp': time.time()
                    })
                }
            
            elif message_type == 'discover':
                # 处理节点发现请求
                nearby_nodes = self._get_nearby_nodes(limit=5)
                return {
                    'type': 'discover_response',
                    'nodes': nearby_nodes,
                    'checksum': self._calculate_checksum({
                        'type': 'discover_response',
                        'nodes': nearby_nodes
                    })
                }
            
            elif message_type == 'fragment':
                # 处理数据分片
                fragment = NetworkFragment(
                    session_id=message['session_id'],
                    fragment_index=message['fragment_index'],
                    total_fragments=message['total_fragments'],
                    data=base64.b64decode(message['data']),
                    priority=FragmentPriority(message['priority']),
                    offset=message['offset'],
                    checksum=message['fragment_checksum'],
                    timestamp=message['timestamp']
                )
            
                # 交给会话管理器处理
                self.session_manager.add_fragment(fragment)
            
                # 返回确认
                return {
                    'type': 'fragment_ack',
                    'session_id': fragment.session_id,
                    'fragment_index': fragment.fragment_index,
                    'received': True,
                    'checksum': self._calculate_checksum({
                        'type': 'fragment_ack',
                        'session_id': fragment.session_id,
                        'fragment_index': fragment.fragment_index,
                        'received': True
                    })
                }
            
            elif message_type == 'disconnect':
                # 处理断开连接请求
                return {
                    'type': 'disconnect_ack',
                    'message': '连接已关闭',
                    'checksum': self._calculate_checksum({
                        'type': 'disconnect_ack',
                        'message': '连接已关闭'
                    })
                }
            
            else:
                logger.warning(f"收到未知类型的消息: {message_type}")
                return {
                    'type': 'error',
                    'message': f'未知消息类型: {message_type}',
                    'checksum': self._calculate_checksum({
                        'type': 'error',
                        'message': f'未知消息类型: {message_type}'
                    })
                }
            
        except Exception as e:
            logger.error(f"处理消息时出错: {e}")
            return {
                'type': 'error',
                'message': str(e),
                'checksum': self._calculate_checksum({
                    'type': 'error',
                    'message': str(e)
                })
            }

    async def _setup_upnp_port_mapping(self, port: int):
        """设置UPnP端口映射"""
        try:
            devices = upnpclient.discover()
            if not devices:
                logger.warning("未发现UPnP设备，无法设置端口映射")
                return
            
            gateway = devices[0]
            internal_ip = self._get_local_ip()
        
            # 添加端口映射
            gateway.AddPortMapping(
                NewRemoteHost='',
                NewExternalPort=port,
                NewProtocol='TCP',
                NewInternalPort=port,
                NewInternalClient=internal_ip,
                NewEnabled='1',
                NewPortMappingDescription='Distributed Anonymous Network TCP',
                NewLeaseDuration=3600  # 1小时有效期
            )
        
            logger.info(f"已设置UPnP端口映射: 外部端口 {port} -> 内部 {internal_ip}:{port}")
        
        except Exception as e:
            logger.warning(f"设置UPnP端口映射失败: {e}")

    async def _remove_upnp_port_mapping(self, port: int):
        """移除UPnP端口映射"""
        try:
            devices = upnpclient.discover()
            if devices:
                gateway = devices[0]
                gateway.DeletePortMapping(
                    NewRemoteHost='',
                    NewExternalPort=port,
                    NewProtocol='TCP'
                )
                logger.info(f"已移除UPnP端口映射: {port}")
        except Exception as e:
            logger.warning(f"移除UPnP端口映射失败: {e}")

    def _get_nearby_nodes(self, limit: int = 5) -> List[Dict[str, Any]]:
        """获取附近的节点信息"""
        # 按最后 seen 时间排序，返回最近活动的节点
        sorted_nodes = sorted(
            self.node_list.items(),
            key=lambda x: x[1]['last_seen'],
            reverse=True
        )
    
        # 格式化返回信息，不包含敏感数据
        return [
            {
                'node_id': node_id,
                'address': node_info['address'],
                'node_type': node_info['node_type'],
                'last_seen': node_info['last_seen']
            }
            for node_id, node_info in sorted_nodes[:limit]
        ]
    
    async def _handle_tcp_connection(self, reader, writer):
        """处理TCP连接"""
        try:
            data = await reader.read(4096)  # 读取数据
            
            # 检测扩展选项
            if self._detect_extension_options(data):
                # 作为中间节点处理转发
                await self._handle_intermediate_forwarding(data, writer)
            else:
                # 作为出口节点处理
                await self._handle_exit_node_processing(data, writer)
                
        except Exception as e:
            logger.error(f"TCP连接处理异常: {e}")
        finally:
            writer.close()

    def _detect_extension_options(self, data: bytes) -> bool:
        """检测TCP扩展选项"""
        # 搜索魔数 0x53464D43 (SFMC)
        return b'\x53\x46\x4D\x43' in data
    
    async def _handle_intermediate_forwarding(self, data: bytes, writer):
        """中间节点转发逻辑"""
        try:
            # 参数解码
            decoded_params = await self._decode_parameters(data)
            
            # 路由决策
            next_hop = await self._select_next_hop(decoded_params)
            
            if next_hop:
                # 更新参数
                updated_params = await self._update_routing_parameters(decoded_params)
                
                # 重新混淆和发送
                await self._forward_to_next_hop(updated_params, next_hop, data)
            
        except Exception as e:
            logger.error(f"中间节点转发失败: {e}")
    
    async def _handle_exit_node_processing(self, data: bytes, writer):
        """出口节点处理逻辑"""
        try:
            # 最终跳验证
            if not await self._validate_final_hop(data):
                return
            
            # 协议剥离
            clean_data = await self._strip_protocol_extensions(data)
            
            # 建立目标连接
            response = await self._connect_to_target(clean_data)
            
            # 发送响应
            writer.write(response)
            await writer.drain()
            
        except Exception as e:
            logger.error(f"出口节点处理失败: {e}")

class NodeDiscoveryService:
    """节点发现服务"""
    
    def __init__(self, network: DistributedAnonymousNetwork):
        self.network = network
        self.is_running = False
    
    async def start(self):
        """启动节点发现服务"""
        self.is_running = True
        asyncio.create_task(self._discovery_loop())
    
    async def stop(self):
        """停止节点发现服务"""
        self.is_running = False
    
    async def _discovery_loop(self):
        """发现循环"""
        while self.is_running:
            try:
                # DNS扫描
                await self._dns_scan()
                
                # P2P节点信息交换
                await self._p2p_exchange()
                
                # 等待下一个发现周期
                await asyncio.sleep(300)  # 5分钟
                
            except Exception as e:
                logger.error(f"节点发现异常: {e}")
                await asyncio.sleep(60)
    
    async def _dns_scan(self):
        """DNS扫描"""
        # 生成子域名候选列表
        candidates = self._generate_subdomain_candidates()
        
        # 批量DNS查询
        for candidate in candidates:
            domain = f"{candidate}.{self.network.config.scan_domain}"
            try:
                # 解析域名
                ip = socket.gethostbyname(domain)
                
                # 验证节点活跃状态
                if await self._verify_node_active(ip):
                    # 添加到节点列表
                    self.network.node_list[domain] = {
                        "host": ip,
                        "port": random.randint(20000, 60000),
                        "type": NodeType.D_NODE,  # 假设都是D节点
                        "active": True,
                        "last_seen": time.time()
                    }
                    
            except socket.gaierror:
                continue  # 域名不存在
    
    def _generate_subdomain_candidates(self) -> List[str]:
        """生成子域名候选列表"""
        candidates = []
        
        # 常用词汇组合
        common_words = ["node", "net", "anon", "proxy", "gateway", "relay"]
        for word1 in common_words:
            for word2 in common_words:
                if word1 != word2:
                    candidates.append(f"{word1}{word2}")
        
        # 随机字符序列
        for _ in range(50):
            candidates.append(self._generate_random_subdomain())
        
        return candidates
    
    def _generate_random_subdomain(self) -> str:
        """生成随机子域名"""
        base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        return ''.join(random.choices(base58_chars, k=8))
    
    async def _verify_node_active(self, ip: str) -> bool:
        """验证节点活跃状态"""
        try:
            # HTTPS握手测试
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://{ip}", timeout=5) as response:
                    return response.status == 200
        except:
            return False
    
    async def _p2p_exchange(self):
        """P2P节点信息交换"""
        # 与已知节点交换部分列表
        known_nodes = list(self.network.node_list.values())
        if known_nodes:
            # 选择几个节点进行交换
            exchange_nodes = random.sample(known_nodes, min(3, len(known_nodes)))
            
            for node in exchange_nodes:
                if node.get("active"):
                    await self._exchange_node_list(node)

class RoutingEngine:
    """路由引擎"""
    
    def __init__(self, network: DistributedAnonymousNetwork):
        self.network = network
        self.routing_table = {}
    
async def calculate_route(self, target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """计算多跳路由路径，考虑网络拓扑、节点信誉和网络性能"""
    if not target_info or "node_id" not in target_info:
        logger.error("目标节点信息不完整，无法计算路由")
        return []

    target_id = target_info["node_id"]
    
    # 1. 检查是否为直接连接的节点（0跳）
    if target_id in self.network.node_list:
        direct_node = self.network.node_list[target_id]
        if direct_node.get("active"):
            return [{
                "path": [self.identity.node_id, target_id],
                "score": 1.0,  # 直接连接得分最高
                "hops": 1,
                "latency": direct_node.get("last_latency", 0),
                "reputation": direct_node.get("reputation", 0),
                "bandwidth": direct_node.get("bandwidth", 0)
            }]

    # 2. 初始化路由发现（基于改进的Dijkstra算法）
    max_hops = self.config.performance_params.get("max_hops", 8)
    available_paths = []
    visited = set()
    queue = deque()
    
    # 从直接连接的活跃节点开始探索（1跳）
    for neighbor_id, neighbor_info in self.network.node_list.items():
        if neighbor_info.get("active") and neighbor_id != self.identity.node_id:
            initial_score = self._calculate_path_score(neighbor_info, target_info)
            queue.append({
                "current_node": neighbor_id,
                "path": [self.identity.node_id, neighbor_id],
                "score": initial_score,
                "hops": 1,
                "cumulative_latency": neighbor_info.get("last_latency", 0),
                "total_reputation": neighbor_info.get("reputation", 0)
            })
            visited.add(neighbor_id)

    # 3. 多跳路由探索
    while queue and len(available_paths) < 5:  # 限制最大候选路径数量
        current = queue.popleft()
        current_node_id = current["current_node"]
        current_hops = current["hops"]

        # 如果达到最大跳数，停止探索该路径
        if current_hops >= max_hops:
            continue

        # 获取当前节点的邻居列表（可能需要从路由表或网络查询）
        current_neighbors = await self._get_node_neighbors(current_node_id)
        if not current_neighbors:
            continue

        # 探索邻居节点
        for neighbor_id, neighbor_info in current_neighbors.items():
            # 避免循环和重复节点
            if neighbor_id in current["path"] or neighbor_id in visited:
                continue

            # 计算新路径评分
            new_path = current["path"] + [neighbor_id]
            new_hops = current_hops + 1
            new_latency = current["cumulative_latency"] + neighbor_info.get("last_latency", 0)
            new_reputation = (current["total_reputation"] + neighbor_info.get("reputation", 0)) / new_hops
            
            # 计算路径评分（综合考虑多因素）
            path_score = self._calculate_multi_hop_score(
                neighbor_info, 
                target_info, 
                new_hops, 
                new_latency, 
                new_reputation
            )

            # 检查是否到达目标节点
            if neighbor_id == target_id:
                available_paths.append({
                    "path": new_path,
                    "score": path_score,
                    "hops": new_hops,
                    "latency": new_latency,
                    "reputation": new_reputation,
                    "bandwidth": neighbor_info.get("bandwidth", 0)
                })
                continue

            # 添加到队列继续探索
            queue.append({
                "current_node": neighbor_id,
                "path": new_path,
                "score": path_score,
                "hops": new_hops,
                "cumulative_latency": new_latency,
                "total_reputation": current["total_reputation"] + neighbor_info.get("reputation", 0)
            })
            visited.add(neighbor_id)

    # 4. 补充备用路由（如果直接路径不足）
    if not available_paths and self.network.node_list:
        available_paths = await self._generate_fallback_routes(target_info, max_hops)

    # 5. 按评分排序并过滤重复路径
    unique_paths = []
    seen_paths = set()
    for path in sorted(available_paths, key=lambda x: x["score"], reverse=True):
        path_str = "-".join(path["path"])
        if path_str not in seen_paths:
            seen_paths.add(path_str)
            unique_paths.append(path)

    return unique_paths[:3]  # 返回评分最高的3条路径

def _calculate_multi_hop_score(self, node_info: Dict[str, Any], target_info: Dict[str, Any], 
                             hops: int, latency: float, reputation: float) -> float:
    """计算多跳路径评分，综合考虑多种因素"""
    # 基础权重配置（可从配置中加载）
    weights = self.config.performance_params.get("routing_weights", {
        "reputation": 0.4,
        "latency": 0.25,
        "bandwidth": 0.2,
        "hops": 0.1,
        "stability": 0.05
    })

    # 1. 信誉评分（0-1）
    rep_score = min(max(reputation / 1000, 0), 1)  # 假设最大信誉为1000

    # 2. 延迟评分（0-1，延迟越低得分越高）
    max_acceptable_latency = 5000  # 5秒作为最大可接受延迟
    latency_score = 1 - min(latency / max_acceptable_latency, 1)

    # 3. 带宽评分（0-1）
    bandwidth = node_info.get("bandwidth", 0)
    max_bandwidth = 100  # 100Mbps作为参考最大值
    bandwidth_score = min(bandwidth / max_bandwidth, 1)

    # 4. 跳数评分（0-1，跳数越少得分越高）
    max_hops = self.config.performance_params.get("max_hops", 8)
    hops_score = 1 - (hops / max_hops)

    # 5. 稳定性评分（0-1）
    uptime = node_info.get("uptime_ratio", 0)
    stability_score = min(uptime, 1)

    # 6. 目标相似度评分（0-1，基于节点类型和地理位置）
    similarity_score = self._calculate_similarity_score(node_info, target_info)

    # 综合评分（加权求和）
    total_score = (
        rep_score * weights["reputation"] +
        latency_score * weights["latency"] +
        bandwidth_score * weights["bandwidth"] +
        hops_score * weights["hops"] +
        stability_score * weights["stability"] +
        similarity_score * 0.1  # 额外增加相似度权重
    )

    return round(total_score, 4)

def _calculate_similarity_score(self, node_info: Dict[str, Any], target_info: Dict[str, Any]) -> float:
    """计算节点与目标的相似度评分（基于类型、地理位置等）"""
    score = 0.0

    # 节点类型相似度
    if node_info.get("node_type") == target_info.get("node_type"):
        score += 0.3

    # 地理位置相似度（假设存在region信息）
    if node_info.get("region") and target_info.get("region"):
        if node_info["region"] == target_info["region"]:
            score += 0.3
        elif node_info.get("country") == target_info.get("country"):
            score += 0.15

    # 能力相似度（支持的服务类型）
    node_capabilities = set(node_info.get("capabilities", {}).keys())
    target_capabilities = set(target_info.get("required_capabilities", []))
    if target_capabilities:
        overlap = len(node_capabilities & target_capabilities) / len(target_capabilities)
        score += overlap * 0.4

    return min(score, 1.0)

async def _get_node_neighbors(self, node_id: str) -> Dict[str, Any]:
    """获取指定节点的邻居列表（可能需要网络查询）"""
    # 1. 先检查本地缓存
    if node_id in self.routing_table:
        cached_neighbors = self.routing_table[node_id].get("neighbors", {})
        if cached_neighbors and time.time() - self.routing_table[node_id].get("last_updated", 0) < 300:
            return cached_neighbors

    # 2. 本地缓存失效，向节点发送查询请求
    try:
        node_info = self.network.node_list.get(node_id)
        if not node_info or not node_info.get("active"):
            return {}

        # 发送邻居查询消息
        reader, writer = await asyncio.open_connection(
            node_info["address"][0], 
            node_info["address"][1]
        )
        
        # 构建查询消息
        query = {
            "type": "neighbor_query",
            "source": self.identity.node_id,
            "target": node_id,
            "timestamp": time.time()
        }
        
        # 发送并等待响应
        data = json.dumps(query).encode()
        writer.write(struct.pack(">I", len(data)) + data)
        await writer.drain()

        # 读取响应
        length_data = await reader.readexactly(4)
        response_length = struct.unpack(">I", length_data)[0]
        response_data = await reader.readexactly(response_length)
        response = json.loads(response_data.decode())

        writer.close()
        await writer.wait_closed()

        # 更新本地缓存
        if "neighbors" in response:
            self.routing_table[node_id] = {
                "neighbors": response["neighbors"],
                "last_updated": time.time()
            }
            return response["neighbors"]

    except Exception as e:
        logger.error(f"获取节点 {node_id} 邻居列表失败: {e}")

    return {}

async def _generate_fallback_routes(self, target_info: Dict[str, Any], max_hops: int) -> List[Dict[str, Any]]:
    """生成备用路由（当直接路由发现失败时）"""
    fallback_routes = []
    target_id = target_info["node_id"]
    
    # 1. 基于节点信誉随机选择路径
    reputable_nodes = [
        (nid, ninfo) for nid, ninfo in self.network.node_list.items()
        if ninfo.get("active") and ninfo.get("reputation", 0) > 800
    ]
    
    if len(reputable_nodes) >= max_hops:
        # 随机选择节点组成路径
        path_nodes = random.sample(reputable_nodes, max_hops-1)
        path = [self.identity.node_id] + [nid for nid, _ in path_nodes] + [target_id]
        
        # 计算路径评分
        avg_reputation = sum(ninfo.get("reputation", 0) for _, ninfo in path_nodes) / len(path_nodes)
        fallback_routes.append({
            "path": path,
            "score": 0.5 + (avg_reputation / 2000),  # 基础分+信誉加成
            "hops": len(path) - 1,
            "latency": 0,  # 未知延迟
            "reputation": avg_reputation,
            "bandwidth": 0
        })
    
    return fallback_routes
    
    def _calculate_path_score(self, node_info: Dict[str, Any], target_info: Dict[str, Any]) -> float:
        """计算路径评分"""
        reputation = node_info.get("reputation", 500) / 1000.0
        latency = max(0, 1 - (node_info.get("latency", 100) / 1000.0))
        bandwidth = min(1.0, node_info.get("bandwidth", 10) / 100.0)
        stability = node_info.get("stability", 0.5)
        
        weights = {
            "reputation": 0.4,
            "latency": 0.25,
            "bandwidth": 0.2,
            "stability": 0.15
        }
        
        return (
            reputation * weights["reputation"] +
            latency * weights["latency"] +
            bandwidth * weights["bandwidth"] +
            stability * weights["stability"]
        )

class UPNPManager:
    """UPnP管理器"""
    
    def __init__(self, network: DistributedAnonymousNetwork):
        self.network = network
        self.devices = []
    
    async def discover_devices(self):
        """发现UPnP设备"""
        try:
            self.devices = upnpclient.discover()
            return len(self.devices) > 0
        except Exception as e:
            logger.warning(f"UPnP设备发现失败: {e}")
            return False
    
    async def setup_port_mapping(self, internal_port: int, external_port: int = None) -> bool:
        """设置端口映射"""
        if not self.devices:
            if not await self.discover_devices():
                return False
        
        if external_port is None:
            external_port = internal_port
        
        try:
            device = self.devices[0]
            device.AddPortMapping(
                NewRemoteHost='',
                NewExternalPort=external_port,
                NewProtocol='TCP',
                NewInternalPort=internal_port,
                NewInternalClient=socket.gethostbyname(socket.gethostname()),
                NewEnabled='1',
                NewPortMappingDescription='Distributed Anonymous Network',
                NewLeaseDuration=3600
            )
            return True
        except Exception as e:
            logger.error(f"UPnP端口映射设置失败: {e}")
            return False

class AdaptiveOptimizer:
    """自适应性能优化器，基于网络实时状态动态调整系统参数"""
    
    def __init__(self, network: DistributedAnonymousNetwork):
        self.network = network
        self.optimization_history = deque(maxlen=100)  # 保存最近100次优化记录
        self.last_optimization = 0
        self.optimization_interval = 30  # 优化检查间隔（秒）
        self.thresholds = {
            "latency": {
                "high": 500,    # 高延迟阈值（ms）
                "medium": 200,  # 中等延迟阈值（ms）
                "low": 100      # 低延迟阈值（ms）
            },
            "packet_loss": {
                "high": 0.2,    # 高丢包率阈值
                "medium": 0.1,  # 中等丢包率阈值
                "low": 0.05     # 低丢包率阈值
            },
            "error_rate": {
                "high": 0.1,    # 高错误率阈值
                "medium": 0.05, # 中等错误率阈值
                "low": 0.02     # 低错误率阈值
            }
        }

    async def start_optimization_loop(self):
        """启动持续优化循环"""
        while self.network.is_running:
            try:
                await self.optimize_performance()
                await asyncio.sleep(self.optimization_interval)
            except Exception as e:
                logger.error(f"性能优化循环出错: {e}")
                await asyncio.sleep(10)  # 出错时缩短间隔重试

    async def optimize_performance(self):
        """基于实时网络状态进行多维度性能优化"""
        current_time = time.time()
        if current_time - self.last_optimization < self.optimization_interval:
            return  # 未到优化时间间隔
        
        # 获取最新性能统计数据
        stats = self.network.performance_monitor.get_performance_stats()
        if not stats:
            logger.warning("无性能数据，无法进行优化")
            return

        optimization_actions = []
        
        # 1. 路由策略优化
        route_optimizations = await self._optimize_routing_strategy(stats)
        optimization_actions.extend(route_optimizations)
        
        # 2. 分片策略优化
        fragment_optimizations = self._optimize_fragmentation_strategy(stats)
        optimization_actions.extend(fragment_optimizations)
        
        # 3. 连接管理优化
        connection_optimizations = await self._optimize_connection_management(stats)
        optimization_actions.extend(connection_optimizations)
        
        # 4. 加密级别动态调整
        crypto_optimizations = self._optimize_crypto_strategy(stats)
        optimization_actions.extend(crypto_optimizations)
        
        # 记录优化历史
        if optimization_actions:
            self.optimization_history.append({
                "timestamp": current_time,
                "stats": {k: v for k, v in stats.items() if k in ["avg_latency", "packet_loss", "error_rate"]},
                "actions": optimization_actions
            })
            logger.info(f"执行了{len(optimization_actions)}项性能优化")
        
        self.last_optimization = current_time

    async def _optimize_routing_strategy(self, stats: Dict[str, Any]) -> List[str]:
        """优化路由策略"""
        actions = []
        current_algorithm = self.network.config.performance_params.get("routing.algorithm", "adaptive")
        current_max_hops = self.network.config.performance_params.get("max_hops", 8)
        
        # 根据延迟调整最大跳数
        if stats["avg_latency"] > self.thresholds["latency"]["high"]:
            # 高延迟网络，减少跳数
            new_max_hops = max(2, current_max_hops - 2)
            if new_max_hops != current_max_hops:
                self.network.config.performance_params["max_hops"] = new_max_hops
                actions.append(f"高延迟网络，将最大跳数从{current_max_hops}调整为{new_max_hops}")
        
        elif stats["avg_latency"] < self.thresholds["latency"]["low"]:
            # 低延迟网络，可增加跳数以提高匿名性
            new_max_hops = min(10, current_max_hops + 1)
            if new_max_hops != current_max_hops:
                self.network.config.performance_params["max_hops"] = new_max_hops
                actions.append(f"低延迟网络，将最大跳数从{current_max_hops}调整为{new_max_hops}")
        
        # 根据丢包率调整路由算法
        if stats["packet_loss"] > self.thresholds["packet_loss"]["high"]:
            # 高丢包率，切换到更稳健的路由算法
            if current_algorithm != "robust":
                self.network.config.performance_params["routing.algorithm"] = "robust"
                actions.append(f"高丢包率，路由算法从{current_algorithm}切换为robust")
                # 立即更新路由表
                await self.network.update_routing_table()
        
        elif stats["packet_loss"] < self.thresholds["packet_loss"]["low"] and current_algorithm != "fast":
            # 低丢包率，切换到更快的路由算法
            self.network.config.performance_params["routing.algorithm"] = "fast"
            actions.append(f"低丢包率，路由算法从{current_algorithm}切换为fast")
        
        # 动态调整路由权重
        if stats["error_rate"] > self.thresholds["error_rate"]["high"]:
            # 高错误率，增加节点信誉权重
            self.network.config.performance_params["routing.weights.reputation"] = 0.6
            self.network.config.performance_params["routing.weights.latency"] = 0.2
            actions.append("高错误率，增加节点信誉权重至0.6")
        
        return actions

    def _optimize_fragmentation_strategy(self, stats: Dict[str, Any]) -> List[str]:
        """优化数据分片策略"""
        actions = []
        frag_config = self.network.config.performance_params.get("fragmentation", {})
        current_min_size = frag_config.get("min_fragment_size", 512)
        current_max_size = frag_config.get("max_fragment_size", 16384)
        current_redundancy = frag_config.get("redundancy_factor", 1.5)
        
        # 根据网络状况调整分片大小
        if stats["avg_latency"] > self.thresholds["latency"]["high"] or stats["packet_loss"] > self.thresholds["packet_loss"]["high"]:
            # 网络状况差，使用更小的分片
            new_max_size = max(1024, current_max_size // 2)
            if new_max_size != current_max_size:
                frag_config["max_fragment_size"] = new_max_size
                actions.append(f"网络状况差，最大分片大小从{current_max_size}调整为{new_max_size}")
                
                # 增加冗余
                new_redundancy = min(3.0, current_redundancy + 0.5)
                if new_redundancy != current_redundancy:
                    frag_config["redundancy_factor"] = new_redundancy
                    actions.append(f"增加数据冗余，从{current_redundancy}调整为{new_redundancy}")
        
        elif stats["avg_latency"] < self.thresholds["latency"]["low"] and stats["packet_loss"] < self.thresholds["packet_loss"]["low"]:
            # 网络状况好，使用更大的分片
            new_max_size = min(32768, current_max_size * 2)
            if new_max_size != current_max_size:
                frag_config["max_fragment_size"] = new_max_size
                actions.append(f"网络状况好，最大分片大小从{current_max_size}调整为{new_max_size}")
                
                # 减少冗余
                new_redundancy = max(1.0, current_redundancy - 0.3)
                if new_redundancy != current_redundancy:
                    frag_config["redundancy_factor"] = new_redundancy
                    actions.append(f"减少数据冗余，从{current_redundancy}调整为{new_redundancy}")
        
        # 根据错误率调整分片优先级策略
        if stats["error_rate"] > self.thresholds["error_rate"]["high"]:
            frag_config["default_strategy"] = "reliable"
            actions.append("高错误率，分片策略切换为reliable模式")
        elif stats["error_rate"] < self.thresholds["error_rate"]["low"]:
            frag_config["default_strategy"] = "fast"
            actions.append("低错误率，分片策略切换为fast模式")
        
        self.network.config.performance_params["fragmentation"] = frag_config
        return actions

    async def _optimize_connection_management(self, stats: Dict[str, Any]) -> List[str]:
        """优化连接管理策略"""
        actions = []
        current_max_connections = self.network.config.performance_params.get("max_connections", 1000)
        
        # 根据节点负载调整最大连接数
        node_load = stats.get("node_load", 0.5)  # 0-1之间的负载值
        if node_load > 0.8:  # 高负载
            new_max = max(500, int(current_max_connections * 0.8))
            if new_max != current_max_connections:
                self.network.config.performance_params["max_connections"] = new_max
                actions.append(f"节点高负载，最大连接数从{current_max_connections}调整为{new_max}")
                
                # 主动断开低优先级连接
                closed_count = await self.network.close_low_priority_connections(percent=20)
                actions.append(f"主动断开{closed_count}个低优先级连接")
        
        elif node_load < 0.3:  # 低负载
            new_max = min(2000, int(current_max_connections * 1.2))
            if new_max != current_max_connections:
                self.network.config.performance_params["max_connections"] = new_max
                actions.append(f"节点低负载，最大连接数从{current_max_connections}调整为{new_max}")
        
        # 根据网络稳定性调整心跳间隔
        stability = stats.get("stability_score", 0.5)
        current_heartbeat = self.network.config.heartbeat_interval
        if stability < 0.5:  # 低稳定性
            new_interval = max(10, current_heartbeat // 2)
            if new_interval != current_heartbeat:
                self.network.config.heartbeat_interval = new_interval
                actions.append(f"网络稳定性低，心跳间隔从{current_heartbeat}调整为{new_interval}秒")
        elif stability > 0.8:  # 高稳定性
            new_interval = min(120, current_heartbeat * 2)
            if new_interval != current_heartbeat:
                self.network.config.heartbeat_interval = new_interval
                actions.append(f"网络稳定性高，心跳间隔从{current_heartbeat}调整为{new_interval}秒")
        
        return actions

    def _optimize_crypto_strategy(self, stats: Dict[str, Any]) -> List[str]:
        """优化加密策略"""
        actions = []
        current_level = self.network.config.performance_params.get("encryption_level", "high")
        
        # 根据性能和安全性需求平衡加密级别
        if stats["avg_latency"] > self.thresholds["latency"]["high"] and current_level == "high":
            # 高延迟且当前为高加密级别，降级以提高性能
            self.network.config.performance_params["encryption_level"] = "medium"
            actions.append("高延迟网络，加密级别从high降为medium")
        
        elif stats["error_rate"] < self.thresholds["error_rate"]["low"] and current_level != "high":
            # 低错误率且网络稳定，提高加密级别
            self.network.config.performance_params["encryption_level"] = "high"
            actions.append("网络稳定，加密级别提升至high")
        
        # 根据节点类型调整混淆级别
        node_type = self.network.identity.node_type
        current_obfuscation = self.network.config.performance_params.get("obfuscation_level", "medium")
        
        if node_type == NodeType.D_NODE and current_obfuscation != "high":
            self.network.config.performance_params["obfuscation_level"] = "high"
            actions.append("D节点提升混淆级别至high")
        elif node_type == NodeType.U_NODE and current_obfuscation == "high":
            self.network.config.performance_params["obfuscation_level"] = "medium"
            actions.append("U节点降低混淆级别至medium")
        
        return actions

    def get_optimization_report(self, last_n: int = 10) -> List[Dict[str, Any]]:
        """获取最近的优化报告"""
        return list(self.optimization_history)[-last_n:]

    def get_recommendation(self) -> Dict[str, str]:
        """基于历史优化给出系统改进建议"""
        if not self.optimization_history:
            return {"建议": "暂无足够数据生成建议"}
        
        # 分析高频优化动作
        action_counts = defaultdict(int)
        for record in self.optimization_history:
            for action in record["actions"]:
                action_counts[action.split("，")[0]] += 1
        
        # 生成建议
        recommendations = []
        if len(action_counts) > 0:
            most_common = max(action_counts.items(), key=lambda x: x[1])
            if most_common[1] > len(self.optimization_history) * 0.7:
                recommendations.append(f"系统频繁{most_common[0]}，建议检查相关网络环境")
        
        # 基于当前状态给出建议
        current_stats = self.network.performance_monitor.get_performance_stats()
        if current_stats.get("avg_latency", 0) > self.thresholds["latency"]["high"]:
            recommendations.append("当前网络延迟较高，建议优化节点地理位置分布")
        if current_stats.get("packet_loss", 0) > self.thresholds["packet_loss"]["high"]:
            recommendations.append("当前网络丢包率较高，建议增加冗余节点")
        
        return {"建议": recommendations}

class FaultRecovery:
    """故障恢复"""
    
    def __init__(self, network: DistributedAnonymousNetwork):
        self.network = network
    
    async def handle_failure(self, failure_type: str, details: Dict[str, Any]):
        """处理故障"""
        if failure_type == "node_failure":
            await self._handle_node_failure(details)
        elif failure_type == "network_failure":
            await self._handle_network_failure(details)
        elif failure_type == "service_failure":
            await self._handle_service_failure(details)
    
    async def _handle_node_failure(self, details: Dict[str, Any]):
        """处理节点故障"""
        node_id = details.get("node_id")
        if node_id in self.network.node_list:
            self.network.node_list[node_id]["active"] = False
            logger.warning(f"标记节点 {node_id} 为失效")

async def main():
    """主函数"""
    network = DistributedAnonymousNetwork()
    
    try:
        # 启动系统
        await network.start()
        
        # 模拟处理一些请求
        for i in range(3):
            request = {
                "url": f"https://example.com/test{i}",
                "method": "GET",
                "headers": {"User-Agent": "DistributedNetwork/1.0"},
                "body": b""
            }
            result = await network.handle_client_request(request)
            logger.info(f"请求处理结果: {result}")
            
            await asyncio.sleep(10)
        
        # 运行一段时间
        await asyncio.sleep(300)  # 5分钟
        
    except KeyboardInterrupt:
        logger.info("收到中断信号，正在关闭...")
    finally:
        await network.stop()

if __name__ == "__main__":
    # 运行系统
    asyncio.run(main())
