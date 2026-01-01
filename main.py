#!/usr/bin/env python3
"""
分布式匿名网络系统 - 主程序入口
"""

import asyncio
import logging
from core.node import P2PNode
from config.config_parser import load_config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("P2PNetwork")

async def main():
    """主函数"""
    try:
        # 加载配置
        config = load_config("config.dpdsls")
        
        # 创建并启动节点
        node = P2PNode(
            node_id=config.get('node_id', 'default_node'),
            host=config.get('host', '0.0.0.0'),
            port=config.get('port', 8888),
            config=config
        )
        
        await node.start()
        
        # 保持运行
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("收到中断信号，正在关闭节点...")
    except Exception as e:
        logger.error(f"节点运行错误: {e}")
    finally:
        if 'node' in locals():
            await node.stop()

if __name__ == "__main__":
    asyncio.run(main())
    