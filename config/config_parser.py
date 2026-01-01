"""
配置解析器 - 解析.dpdsls配置文件
"""

import os
import re
import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger("ConfigParser")

class ConfigParser:
    """配置解析器"""
    
    @staticmethod
    def parse_dpdsls_file(file_path: str) -> Dict[str, Any]:
        """解析.dpdsls配置文件"""
        if not os.path.exists(file_path):
            logger.warning(f"配置文件不存在: {file_path}")
            return {}
        
        config = {}
        current_section = None
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # 跳过空行和注释
                    if not line or line.startswith('#'):
                        continue
                    
                    # 处理区块
                    if line.startswith('[') and line.endswith(']'):
                        current_section = line[1:-1]
                        config[current_section] = {}
                        continue
                    
                    # 处理键值对
                    if '=' in line and current_section:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        # 解析环境变量
                        value = ConfigParser._resolve_env_vars(value)
                        
                        # 解析值类型
                        parsed_value = ConfigParser._parse_value(value)
                        
                        # 处理嵌套键
                        if '.' in key:
                            ConfigParser._set_nested_value(config[current_section], key, parsed_value)
                        else:
                            config[current_section][key] = parsed_value
        
        except Exception as e:
            logger.error(f"解析配置文件失败: {e}")
        
        return config
    
    @staticmethod
    def _resolve_env_vars(value: str) -> str:
        """解析环境变量"""
        def replace_env(match):
            var_name = match.group(1)
            return os.getenv(var_name, '')
        
        return re.sub(r'\$\{([^}]+)\}', replace_env, value)
    
    @staticmethod
    def _parse_value(value: str) -> Any:
        """解析配置值"""
        # 布尔值
        if value.lower() in ('true', 'yes', 'on', '1'):
            return True
        if value.lower() in ('false', 'no', 'off', '0'):
            return False
        
        # 列表
        if ',' in value:
            return [ConfigParser._parse_value(v.strip()) for v in value.split(',')]
        
        # 整数
        if value.isdigit():
            return int(value)
        
        # 浮点数
        try:
            return float(value)
        except ValueError:
            pass
        
        # 字符串
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            return value[1:-1]
        
        return value
    
    @staticmethod
    def _set_nested_value(config_dict: Dict[str, Any], key: str, value: Any):
        """设置嵌套键值"""
        keys = key.split('.')
        current = config_dict
        
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        current[keys[-1]] = value

def load_config(file_path: str) -> Dict[str, Any]:
    """加载配置"""
    return ConfigParser.parse_dpdsls_file(file_path)
