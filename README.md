# Distributed Anonymous Network System (DSLSP2P)

## Project Overview

A Python-based distributed anonymous network system that enables decentralized secure communication and data transmission. The system employs multi-hop routing, data fragmentation, and dynamic DNS technologies to provide highly anonymous network communication capabilities.

## Core Features

### 🔒 Security & Anonymity
- **Multi-hop Routing**: Data is forwarded through multiple nodes to conceal the true source
- **Data Fragmentation**: Data is split into multiple fragments transmitted via different paths
- **Dynamic Encryption**: Uses ChaCha20 and RSA encryption algorithms to protect data
- **Parameter Obfuscation**: Adds random perturbations to prevent traffic analysis

### 🌐 Network Architecture
- **Three Node Types**:
  - **D-Node**: Full-function node supporting DNS registration and UPnP
  - **U-Node**: Limited-function node relying on D-nodes
  - **R-Node**: Relay-dependent node with basic forwarding capabilities
- **Intelligent Routing**: Multi-factor routing selection based on reputation, latency, and bandwidth
- **Dynamic Discovery**: P2P node discovery and network topology maintenance

### 🔄 Dynamic DNS Integration
- **Multi-provider Support**: Cloudflare, Alibaba Cloud, and other DNS providers
- **Dynamic Subdomains**: Automatic subdomain allocation and updates for nodes
- **Failover**: Automatic switching between primary and backup DNS providers
- **Lease Management**: Automatic renewal and cleanup of subdomain leases

### 📊 Performance Optimization
- **Adaptive Optimization**: Dynamic parameter adjustment based on network conditions
- **Smart Fragmentation**: Optimized fragmentation strategy based on content type and size
- **Load Balancing**: Traffic distribution with node load awareness
- **Health Monitoring**: Multi-dimensional node health checking

## Technical Architecture

### Core Components
- **Node Management**: Identity generation, type determination, capability assessment
- **Session Management**: Data fragmentation, reassembly, integrity verification
- **Routing Engine**: Multi-path calculation, performance optimization
- **DNS Manager**: Unified management of multiple providers
- **Performance Monitor**: Real-time metric collection and analysis

### Communication Protocols
- **TCP Extension Protocol**: Supports extended options and parameter obfuscation
- **Encrypted Communication**: End-to-end encryption and integrity protection
- **Heartbeat Mechanism**: Node liveliness detection and maintenance
- **Discovery Protocol**: P2P node information exchange

## Quick Start

### Environment Requirements
- Python 3.8+
- Dependencies: `aiohttp`, `pycryptodome`, `upnpclient`, `psutil`

### Basic Usage
```python
# Create network instance
network = DistributedAnonymousNetwork("config.dpdsls")

# Start the system
await network.start()

# Handle requests
request = {
    "url": "https://example.com",
    "method": "GET",
    "headers": {},
    "body": b""
}
result = await network.handle_client_request(request)
```

### Configuration File
The system uses `.dpdsls` format configuration files, supporting conditional expressions and environment variables:
```ini
[network]
scan_domain = dsls.top
exclude_subdomains = mail, www, ftp, admin

[dns]
primary_provider = cloudflare
backup_providers = aliyun

[security]
encryption_level = high
max_hops = 8
```

## Application Scenarios

### 🛡️ Privacy Protection
- Sensitive data transmission
- Anonymous network access
- Traffic analysis prevention

### 🔗 Decentralized Applications
- Distributed storage
- P2P communication
- Censorship-resistant networks

### 🌍 Network Penetration
- NAT traversal
- Firewall bypassing
- Hybrid network deployment

## System Advantages

1. **High Anonymity**: Strong anonymity through multi-hop routing and data fragmentation
2. **Resilient Architecture**: Supports different node types for various network environments
3. **Easy Expansion**: Modular design supporting functional extensions
4. **Flexible Configuration**: Supports dynamic configuration and environment adaptation
5. **Performance Adaptation**: Automatic parameter optimization based on network conditions

## Development Status

Current version is a complete implementation including all core features:
- ✅ Node management and discovery
- ✅ Secure communication protocols
- ✅ DNS integration and management
- ✅ Performance monitoring and optimization
- ✅ Fault recovery mechanisms

This is a fully functional distributed anonymous network system implementation suitable for various application scenarios requiring high anonymity and decentralized communication.