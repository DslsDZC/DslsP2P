"""
32位完整编码器 - 在32位内编码16跳+256分片
"""

import time

class Compact32Encoder:
    """紧凑32位编码器"""
    
    def __init__(self):
        # 校验掩码
        self.VERSION = 0b0001  # 4位版本号
        
    def encode(self, 
               real_timestamp: int,
               total_hops: int,      # 1-16
               current_hop: int,     # 0-15
               fragment_index: int): # 0-255
        """
        编码为32位时间戳
        
        参数验证:
        - total_hops: 1-16
        - current_hop: 0-15 且 < total_hops
        - fragment_index: 0-255
        """
        # 验证参数
        total_hops = max(1, min(total_hops, 16))
        current_hop = max(0, min(current_hop, 15))
        fragment_index = max(0, min(fragment_index, 255))
        
        # 提取时间戳位
        ts_high = (real_timestamp >> 28) & 0xF  # 位31-28
        ts_mid = (real_timestamp >> 16) & 0xFF  # 位23-16
        ts_low = real_timestamp & 0xFFFF        # 位15-0
        
        # 编码跳数 (6位: 总跳数4位 + 当前跳数4位)
        total_hops_bits = total_hops - 1  # 0-15
        current_hop_bits = current_hop
        
        # 总跳数分解: 高2位 + 低2位
        total_high = (total_hops_bits >> 2) & 0x3
        total_low = total_hops_bits & 0x3
        
        # 编码分片索引 (8位)
        frag_high = (fragment_index >> 4) & 0xF  # 高4位
        frag_low = fragment_index & 0xF          # 低4位
        
        # 构造混合编码位 (8位)
        mixed_bits = 0
        # 位7-6: 总跳数低2位
        mixed_bits |= (total_low & 0x3) << 6
        # 位5-2: 当前跳数4位
        mixed_bits |= (current_hop_bits & 0xF) << 2
        # 位1-0: 分片索引位2位
        mixed_bits |= (frag_low >> 2) & 0x3
        
        # 构造分片/校验位 (4位)
        frag_check_bits = 0
        # 位7-4: 分片索引高4位 (这里只取4位中的高位)
        frag_check_bits |= frag_high
        # 位3-0: 校验位 (版本+分片低2位)
        frag_check_bits |= self.VERSION
        # 将分片索引最低2位编码到校验位中
        frag_check_bits |= (frag_low & 0x3) << 2
        
        # 构造掩码/跳高位 (4位)
        mask_hop_bits = 0
        # 位3-2: 时间戳掩码 (取时间戳高4位中的2位)
        mask_hop_bits |= (ts_high >> 2) & 0x3
        # 位1-0: 总跳数高2位
        mask_hop_bits |= total_high & 0x3
        
        # 组合32位时间戳
        encoded_timestamp = 0
        encoded_timestamp |= (mask_hop_bits & 0xF) << 28
        encoded_timestamp |= (frag_check_bits & 0xF) << 24
        encoded_timestamp |= (mixed_bits & 0xFF) << 16
        encoded_timestamp |= ts_low & 0xFFFF
        
        return encoded_timestamp
    
    def decode(self, encoded_timestamp: int):
        """
        解码32位时间戳
        """
        # 提取各个字段
        mask_hop_bits = (encoded_timestamp >> 28) & 0xF
        frag_check_bits = (encoded_timestamp >> 24) & 0xF
        mixed_bits = (encoded_timestamp >> 16) & 0xFF
        ts_low = encoded_timestamp & 0xFFFF
        
        # 解码掩码/跳高位
        time_mask = (mask_hop_bits >> 2) & 0x3
        total_high = mask_hop_bits & 0x3
        
        # 解码分片/校验位
        frag_high = frag_check_bits & 0xF
        version = frag_check_bits & 0x1  # 版本在最低位
        frag_low_low = (frag_check_bits >> 2) & 0x3  # 分片索引最低2位
        
        # 解码混合编码位
        total_low = (mixed_bits >> 6) & 0x3
        current_hop = (mixed_bits >> 2) & 0xF
        frag_low_high = mixed_bits & 0x3  # 分片索引次低2位
        
        # 重组总跳数
        total_hops_bits = (total_high << 2) | total_low
        total_hops = total_hops_bits + 1
        
        # 重组分片索引
        frag_low = (frag_low_high << 2) | frag_low_low
        fragment_index = (frag_high << 4) | frag_low
        
        # 重建原始时间戳 (近似值)
        # 时间戳高16位: 使用掩码和混合位重建
        ts_high_reconstructed = (time_mask << 2) | ((mixed_bits >> 4) & 0x3)
        reconstructed_ts = (ts_high_reconstructed << 28) | ts_low
        
        return {
            'original_timestamp': reconstructed_ts,
            'total_hops': total_hops,
            'current_hop': current_hop,
            'fragment_index': fragment_index,
            'version': version,
            'raw_timestamp': encoded_timestamp
        }
    
    def validate(self, encoded_timestamp: int) -> bool:
        """验证编码时间戳的有效性"""
        try:
            info = self.decode(encoded_timestamp)
            
            # 检查版本
            if info['version'] != self.VERSION:
                return False
            
            # 检查跳数合理性
            if info['current_hop'] >= info['total_hops']:
                return False
            
            # 检查分片索引范围
            if info['fragment_index'] > 255:
                return False
            
            # 检查时间戳合理性 (粗略检查)
            current_time = int(time.time())
            decoded_time = info['original_timestamp']
            
            # 时间戳应该在合理范围内 (过去1年到现在+1小时)
            if decoded_time < current_time - 31536000 or decoded_time > current_time + 3600:
                return False
            
            return True
            
        except:
            return False
        