"""
时间戳验证器 - 验证伪装时间戳的真实性
"""

import time
import statistics

from https.encoder.compact32_encoder import Compact32Encoder

class TimestampValidator:
    """时间戳验证器"""
    
    def __init__(self, max_clock_skew: int = 60):
        self.max_clock_skew = max_clock_skew  # 最大时钟偏差(秒)
        self.recent_timestamps = []  # 最近的时间戳列表
        self.max_history = 1000
    
    def is_plausible_timestamp(self, encoded_timestamp: int, 
                              decoder: Compact32Encoder) -> bool:
        """检查时间戳是否合理"""
        try:
            info = decoder.decode(encoded_timestamp)
            
            # 1. 基本验证
            if not decoder.validate(encoded_timestamp):
                return False
            
            # 2. 时间合理性检查
            current_time = int(time.time())
            decoded_time = info['original_timestamp']
            
            # 允许一定的时间偏差
            time_diff = abs(current_time - decoded_time)
            if time_diff > self.max_clock_skew:
                # 可能是伪装时间戳，但编码合理
                # 检查是否在可能的范围内 (过去1年到未来1小时)
                if decoded_time < current_time - 31536000 or decoded_time > current_time + 3600:
                    return False
            
            # 3. 跳数合理性检查
            if info['current_hop'] >= info['total_hops']:
                return False
            
            # 4. 序列检查 (如果有多条记录)
            self.recent_timestamps.append({
                'timestamp': encoded_timestamp,
                'decoded_time': decoded_time,
                'current_hop': info['current_hop'],
                'fragment_index': info['fragment_index']
            })
            
            # 保持列表大小
            if len(self.recent_timestamps) > self.max_history:
                self.recent_timestamps.pop(0)
            
            # 检查时间戳序列是否单调递增
            if len(self.recent_timestamps) >= 2:
                last = self.recent_timestamps[-2]['decoded_time']
                current = self.recent_timestamps[-1]['decoded_time']
                
                # 允许小幅度回退 (由于网络延迟或时钟校正)
                if current < last - 1:  # 超过1秒的回退可疑
                    return False
            
            return True
            
        except Exception:
            return False
    
    def analyze_pattern(self, decoder: Compact32Encoder) -> dict:
        """分析时间戳模式"""
        if not self.recent_timestamps:
            return {'count': 0}
        
        # 统计信息
        timestamps = [t['timestamp'] for t in self.recent_timestamps]
        decoded_times = [t['decoded_time'] for t in self.recent_timestamps]
        
        # 检查可能的模式
        avg_interval = 0
        if len(decoded_times) >= 2:
            intervals = [decoded_times[i+1] - decoded_times[i] 
                        for i in range(len(decoded_times)-1)]
            if intervals:
                avg_interval = statistics.mean(intervals)
        
        # 检查跳数分布
        hop_counts = [t['current_hop'] for t in self.recent_timestamps]
        unique_hops = set(hop_counts)
        
        # 检查分片索引分布
        frag_indices = [t['fragment_index'] for t in self.recent_timestamps]
        unique_frags = set(frag_indices)
        
        return {
            'count': len(self.recent_timestamps),
            'avg_interval': avg_interval,
            'unique_hops': len(unique_hops),
            'unique_fragments': len(unique_frags),
            'time_range': max(decoded_times) - min(decoded_times) if decoded_times else 0,
            'suspicious': self.detect_suspicious_pattern()
        }
    
    def detect_suspicious_pattern(self) -> bool:
        """检测可疑模式"""
        if len(self.recent_timestamps) < 10:
            return False
        
        # 检查是否有固定的模式
        # 例如：时间戳低位总是相同的模式
        last_bits = [t['timestamp'] & 0xF for t in self.recent_timestamps[-10:]]
        
        # 如果最后4位总是相同，可疑
        if len(set(last_bits)) == 1:
            return True
        
        # 检查跳数是否总是相同
        hops = [t['current_hop'] for t in self.recent_timestamps[-10:]]
        if len(set(hops)) == 1:
            return True
        
        return False
    