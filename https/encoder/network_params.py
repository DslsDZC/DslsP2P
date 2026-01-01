"""
网络参数管理器 - 管理跳数和分片信息
"""

from https.encoder.compact32_encoder import Compact32Encoder


class NetworkParamsManager:
    """网络参数管理器"""
    
    def __init__(self, max_hops: int = 16, max_fragments: int = 256):
        self.max_hops = max_hops
        self.max_fragments = max_fragments
        self.current_session = None
    
    class NetworkSession:
        """网络会话"""
        
        def __init__(self, session_id: str, total_hops: int, total_fragments: int):
            self.session_id = session_id
            self.total_hops = total_hops
            self.total_fragments = total_fragments
            self.current_hop = 0
            self.sent_fragments = set()
            self.received_fragments = set()
            
        def increment_hop(self) -> bool:
            """增加跳数"""
            if self.current_hop < self.total_hops - 1:
                self.current_hop += 1
                return True
            return False
        
        def mark_fragment_sent(self, fragment_index: int):
            """标记分片已发送"""
            if 0 <= fragment_index < self.total_fragments:
                self.sent_fragments.add(fragment_index)
        
        def mark_fragment_received(self, fragment_index: int):
            """标记分片已接收"""
            if 0 <= fragment_index < self.total_fragments:
                self.received_fragments.add(fragment_index)
        
        def get_completion_rate(self) -> float:
            """获取完成率"""
            if self.total_fragments == 0:
                return 0.0
            return len(self.received_fragments) / self.total_fragments
    
    def create_session(self, session_id: str, 
                      total_hops: int, 
                      total_fragments: int) -> NetworkSession:
        """创建新会话"""
        total_hops = min(max(1, total_hops), self.max_hops)
        total_fragments = min(max(1, total_fragments), self.max_fragments)
        
        session = self.NetworkSession(session_id, total_hops, total_fragments)
        self.current_session = session
        return session
    
    def get_timestamp_params(self, fragment_index: int) -> tuple:
        """获取时间戳编码参数"""
        if not self.current_session:
            # 默认值
            return 4, 0, fragment_index % 256
        
        session = self.current_session
        
        # 确保分片索引在有效范围内
        frag_idx = fragment_index % session.total_fragments
        
        return (
            session.total_hops,
            session.current_hop,
            frag_idx
        )
    
    def process_incoming_timestamp(self, encoded_timestamp: int, 
                                 encoder: Compact32Encoder) -> dict:
        """处理接收到的时间戳"""
        try:
            info = encoder.decode(encoded_timestamp)
            
            # 更新会话状态
            if self.current_session:
                # 检查是否是同一会话的分片
                # 这里可以根据需要实现会话匹配逻辑
                pass
            
            return info
        except Exception as e:
            return {
                'error': str(e),
                'timestamp': encoded_timestamp
            }
        