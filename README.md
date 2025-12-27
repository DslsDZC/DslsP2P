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




##Disclaimer Against Illegal Use

Project Name: DslsP2P ("the Project")
Platform: GitHub
Nature: Anonymous networking tools / software / source code

##IMPORTANT NOTICE:

Before accessing, copying, using, modifying, or distributing this Project (including but not limited to source code, binaries, documentation, and related materials), please read, understand, and agree to all terms of this Agreement. If you do not agree to any term herein, please cease use of the Project immediately. Any use of the Project constitutes your acknowledgment that you have read, understood, and fully accepted the entirety of this Agreement.

#1. Project Purpose and Ownership
#1.1 This Project is intended solely for legitimate technical research, academic exchange, privacy protection testing, network communication theory studies, and other lawful purposes within all applicable jurisdictions.
#1.2 The developers, contributors, and owners (collectively, "the Developers") provide the technical implementation only and assume no responsibility for the actions or consequences of any user.
#1.3 All intellectual property and related rights of this Project belong to the Developers or respective rightsholders unless explicitly stated otherwise.
#2. Primary Obligation: Global Legal Compliance
#You explicitly represent and warrant that you have the primary obligation to conduct your own legal review. You must ensure your use of the Project strictly adheres to all laws, regulations, and policies applicable to you, including but not limited to:
#2.1 Laws of the jurisdiction where you or your organization are located, reside, or operate.
#2.2 Laws of the physical location where the Project is being used.
#2.3 Laws of the jurisdictions where servers, networks, services, or data accessed or influenced by this Project are situated.
#2.4 Laws of any other jurisdiction with a legal nexus to your actions.
#3. Prohibited Illegal Activities
#Based on the aforementioned compliance obligations, you are strictly prohibited from using the Project for any illicit purposes, including:
#3.1 Unauthorized access, disruption, interference, or tampering with any computer system, network, or data.
#3.2 Theft, leakage, or misuse of PII (Personally Identifiable Information), financial data, trade secrets, or sensitive state information.
#3.3 Production or distribution of malware (viruses, ransomware, botnets), phishing, or launching Denial-of-Service (DoS) attacks.
#3.4 Facilitating fraud, extortion, espionage, terrorism, or any act recognized as criminal by the international community.
#3.5 Disseminating illegal content (e.g., child exploitation material, incitement of violence/hatred) or infringing upon intellectual property.
#3.6 Circumventing technical measures designed to protect copyright or network security.
#3.7 Any action that exposes the Developers to legal risk, litigation, or causes the Project to be sanctioned.
#4. Comprehensive Disclaimer of Liability
#4.1 The Project is provided "AS IS" without warranties of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement.
#4.2 The Developers shall not be liable for any damages arising from the use or inability to use the Project, including direct, indirect, incidental, special, or consequential damages (such as data loss, loss of profit, or legal penalties), regardless of the cause of action.
#4.3 You are solely responsible for your actions. You agree to indemnify and hold the Developers harmless from any third-party claims, lawsuits, or losses resulting from your breach of this Agreement or applicable laws.
#4.4 The publication of this Project does not constitute an endorsement or encouragement of any specific use case. The Developers explicitly condemn all illegal utilization.
#5. Modification and Termination
#5.1 The Developers reserve the right to unilaterally update this Agreement. Continued use of the Project following such updates constitutes acceptance of the revised terms.
#5.2 The Developers reserve the right to suspend or terminate access to the Project at any time without prior notice or liability.
#6. Miscellaneous
#6.1 Governing Law: This Agreement shall be governed by and construed in accordance with the laws of [Your Jurisdiction]. Any disputes shall be submitted to the [Designated Arbitration Center/Court] for final resolution.
#6.2 Severability: If any provision is found to be invalid, it shall be modified to the minimum extent necessary to make it valid, without affecting the remaining provisions.
#FINAL WARNING:
Technology is borderless, but law has boundaries. While the source code is globally accessible, this does not grant permission to use it for illegal purposes in any jurisdiction. This Project is designed for research and legitimate privacy protection, not to facilitate crime.
#By clicking "Agree," cloning the repository, or downloading the code, you confirm that you have read and unconditionally agreed to this Agreement and assume full legal responsibility for your actions.

