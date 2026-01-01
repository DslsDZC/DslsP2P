"""
TCP时间戳选项构造器 - 使用32位编码
"""

import struct
import time

from https.encoder.compact32_encoder import Compact32Encoder

class TCPTimestampBuilder:
    """TCP时间戳选项构造器"""
    
    def __init__(self, encoder=None):
        self.encoder = encoder or Compact32Encoder()
    
    def build_timestamp_option(self, 
                              total_hops: int,
                              current_hop: int,
                              fragment_index: int,
                              use_real_time: bool = True) -> bytes:
        """
        构建TCP时间戳选项
        
        TCP时间戳选项格式:
        Kind=8 (1字节)
        Length=10 (1字节)  # 只有TSval
        TSval (4字节)      # 32位时间戳
        
        或者:
        Kind=8 (1字节)
        Length=18 (1字节)  # TSval + TSecr
        TSval (4字节)
        TSecr (4字节)      # 接收时间戳(这里可用于扩展信息)
        """
        # 获取当前时间戳
        if use_real_time:
            real_ts = int(time.time())
        else:
            real_ts = 0x5A5A5A5A  # 测试用固定值
        
        # 编码时间戳
        encoded_ts = self.encoder.encode(
            real_timestamp=real_ts,
            total_hops=total_hops,
            current_hop=current_hop,
            fragment_index=fragment_index
        )
        
        # 构建TCP选项 (只有TSval)
        option_data = struct.pack('BBII', 
                                8,          # Kind: Timestamp
                                10,         # Length: 10 bytes
                                encoded_ts, # TSval
                                0)          # TSecr (设为0，可用于扩展)
        
        return option_data
    
    def parse_timestamp_option(self, option_data: bytes):
        """
        解析TCP时间戳选项
        """
        if len(option_data) < 10:
            raise ValueError("无效的TCP时间戳选项长度")
        
        # 解析选项头
        kind, length = struct.unpack('BB', option_data[:2])
        
        if kind != 8:
            raise ValueError("不是时间戳选项")
        
        if length not in [10, 18]:
            raise ValueError("无效的时间戳选项长度")
        
        # 解析TSval (32位时间戳)
        if length == 10:
            tsval, = struct.unpack('I', option_data[2:6])
            tsecr = 0
        else:  # length == 18
            tsval, tsecr = struct.unpack('II', option_data[2:10])
        
        # 解码时间戳
        info = self.encoder.decode(tsval)
        
        return {
            'kind': kind,
            'length': length,
            'tsval': tsval,
            'tsecr': tsecr,
            'decoded_info': info
        }
    
    def create_extended_option(self,
                              total_hops: int,
                              current_hop: int,
                              fragment_index: int,
                              session_id: int = 0,
                              extra_data: int = 0) -> bytes:
        """
        创建扩展时间戳选项 (使用TSecr字段存储额外信息)
        
        在TSecr中存储:
        位31-24: 会话ID (8位)
        位23-16: 额外数据 (8位)
        位15-0: 校验和 (16位)
        """
        # 获取当前时间戳
        real_ts = int(time.time())
        
        # 编码TSval
        encoded_tsval = self.encoder.encode(
            real_timestamp=real_ts,
            total_hops=total_hops,
            current_hop=current_hop,
            fragment_index=fragment_index
        )
        
        # 构建TSecr (扩展信息)
        session_bits = session_id & 0xFF
        extra_bits = extra_data & 0xFF
        
        # 计算校验和 (简单校验)
        checksum = ((session_bits << 8) | extra_bits) ^ 0x55AA
        
        tsecr = (session_bits << 24) | (extra_bits << 16) | (checksum & 0xFFFF)
        
        # 构建TCP选项
        option_data = struct.pack('BBII',
                                8,          # Kind
                                18,         # Length: 18 bytes (TSval + TSecr)
                                encoded_tsval,
                                tsecr)
        
        return option_data
    