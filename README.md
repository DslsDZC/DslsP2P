# Anonymous P2P Network with Browser Engine Support

## Project Overview

A decentralized, anonymous peer-to-peer network that enables secure web content fetching through relay nodes with optional browser engine support for JavaScript-heavy websites.

## Key Features

### 🛡️ Privacy Protection
- **Anonymous Request Routing**: Web requests are routed through multiple peer nodes
- **IP Address Masking**: Source IP addresses are hidden from target websites
- **No Central Server**: Fully decentralized architecture prevents single points of failure

### 🌐 Advanced Web Access
- **Dual Fetching Modes**: 
  - Standard HTTP requests for simple content
  - Headless browser engine for JavaScript-rendered pages
- **Automatic Fallback**: Seamless switching between fetching methods
- **Real Browser Simulation**: Chrome-based engine with realistic user agents

### 🔄 Network Protocol
- **Hybrid Communication**: UDP for node discovery + TCP for reliable data transfer
- **Custom Protocol**: Binary header format with message type differentiation
- **Automatic Node Discovery**: Periodic broadcasting and heartbeat mechanisms
- **Dynamic Network Topology**: Self-healing with expired node cleanup

## System Architecture

### Core Components

```
AnonymousP2PNode
├── Network Layer
│   ├── UDP Listener (Node Discovery)
│   ├── TCP Server (Data Relay)
│   └── Broadcast Service
├── Web Client
│   ├── HTTP Session Manager
│   └── Browser Engine (Selenium/Chrome)
├── Node Management
│   ├── Known Nodes Registry
│   └── Health Monitoring
└── Protocol Handler
    ├── Message Serialization
    └── Request Routing
```

### Message Types
- `NODE_REGISTER`: Node registration and capability announcement
- `ANON_REQUEST`: Anonymous web page request
- `ANON_RESPONSE`: Fetch results with content
- `DATA_RELAY`: Inter-node data forwarding
- `HEARTBEAT`: Node liveliness verification

## Installation

### Prerequisites
```bash
# Required packages
pip install requests selenium

# Chrome Driver (for browser engine)
# On Ubuntu: sudo apt-get install chromium-chromedriver
# On macOS: brew install chromedriver
```

### Quick Start
```bash
# Start a node with default settings
python p2p_node.py

# Start with specific ports and browser support
python p2p_node.py --port 9000 --udp-port 9001 --node-id "my_node"

# Disable browser engine
python p2p_node.py --no-browser
```

## Usage Examples

### Command Line Interface
```bash
# Fetch webpage through random peer (standard mode)
python p2p_node.py --fetch "https://example.com"

# Fetch with browser engine via specific node
python p2p_node.py --fetch "https://dynamic-site.com" --browser --via-node "node_123"

# Add node manually and test
python p2p_node.py --add-node "node_abc:192.168.1.100:8889" --test
```

### Interactive Mode
```python
# After starting the node, use the menu:
# 1. View node information and network status
# 2. List discovered peer nodes
# 3. Manually add trusted nodes
# 4. Request web pages (standard/HTTP mode)
# 5. Request web pages (browser engine mode)
# 6. Run network diagnostics
# 7. Exit gracefully
```

## Configuration Options

### Network Settings
- `--port`: TCP listening port (default: 8889)
- `--udp-port`: UDP broadcast port (default: 8888)
- `--node-id`: Custom node identifier

### Browser Engine
- `--browser`: Enable browser engine for requests
- `--no-browser`: Disable browser engine completely

### Operational Modes
- `--fetch URL`: Direct URL fetching
- `--via-node NODE_ID`: Specify relay node
- `--add-node NODE_INFO`: Manual node addition
- `--test`: Network connectivity test
- `--log-file PATH`: Log output file

## Protocol Specification

### Message Format
```
+--------------------------------+
| Header (9 bytes)              |
+--------------------------------+
| Total Length (4 bytes)        |
| Message Type (1 byte)         |
| Sequence Number (4 bytes)     |
+--------------------------------+
| Body (Variable Length)        |
| JSON-encoded data             |
+--------------------------------+
```

### Node Discovery
1. Nodes broadcast presence via UDP every 5 seconds
2. Receiving nodes update their known nodes registry
3. Heartbeat messages maintain node liveliness
4. Nodes expire after 60 seconds of inactivity

### Anonymous Request Flow
1. Client selects relay node from known peers
2. Request is serialized and sent via TCP
3. Relay node fetches content (HTTP or browser)
4. Response is returned through the same path
5. All intermediate nodes only see encrypted relay data

## Browser Engine Capabilities

### Supported Features
- **JavaScript Execution**: Full DOM manipulation support
- **Dynamic Content**: AJAX, WebSocket, and real-time updates
- **Session Management**: Cookies and local storage persistence
- **Resource Loading**: Images, CSS, and external assets
- **Mobile Emulation**: User agent spoofing

### Performance Considerations
- **Memory Usage**: ~100-200MB per browser instance
- **Load Time**: 2-5 seconds for page rendering
- **Fallback Strategy**: Automatic switch to HTTP on failure

## Network Security

### Privacy Guarantees
- **Source Obfuscation**: Target websites see relay node IP
- **Traffic Mixing**: Multiple request paths available
- **No Logging**: Ephemeral request handling

### Limitations
- **Not End-to-End Encrypted**: Content visible to relay nodes
- **Trust Requirements**: Relies on peer node honesty
- **Network Exposure**: IP addresses visible to direct peers

## Troubleshooting

### Common Issues

**Browser Engine Fails to Start**
```bash
# Check Chrome installation
which google-chrome
# Install missing dependencies
sudo apt-get install -y chromium-browser
```

**Node Discovery Problems**
```bash
# Verify UDP port accessibility
netstat -anu | grep 8888
# Check firewall settings
sudo ufw status
```

**Connection Timeouts**
- Ensure all nodes use consistent port configurations
- Verify network subnet compatibility
- Check for NAT traversal issues

### Diagnostics
Use the built-in network test:
```bash
python p2p_node.py --test
```

## Development

### Extending Functionality
```python
# Adding new message types
class ExtendedMessageType(MessageType):
    FILE_SHARE = 10
    STREAM_DATA = 11

# Custom message handlers
def _handle_file_share(self, data, sock, addr):
    # Implementation for new feature
    pass
```

### Testing
```bash
# Start multiple nodes for testing
python p2p_node.py --port 8890 --node-id "test_node_1"
python p2p_node.py --port 8891 --node-id "test_node_2"
```

## License & Contribution

This project is designed for educational and research purposes. Users are responsible for complying with local laws and website terms of service when using this software.
