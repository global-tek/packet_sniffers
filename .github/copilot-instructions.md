<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# Network Packet Monitoring Toolkit - Copilot Instructions

This workspace contains a comprehensive Python toolkit for network packet monitoring, analysis, and security assessment. The toolkit is designed for educational purposes and authorized network monitoring.

## Project Structure and Guidelines

### Core Modules
- **capture/**: Packet capture functionality using Scapy and raw sockets
- **analysis/**: Deep packet inspection and protocol analysis
- **scanning/**: Network discovery and port scanning tools
- **decryption/**: Encrypted traffic analysis (metadata extraction only)
- **visualization/**: Data visualization and reporting
- **utils/**: Common utilities and configuration management

### Coding Standards
- Follow PEP 8 Python style guidelines
- Use type hints for function parameters and return values
- Include comprehensive docstrings for all classes and functions
- Handle exceptions gracefully with appropriate error messages
- Use logging instead of print statements for debugging

### Security Considerations
- Always check for administrative privileges before packet capture
- Implement proper input validation for network addresses and ports
- Never store or log sensitive data in plain text
- Include legal disclaimers and usage warnings
- Respect network privacy and local regulations

### Dependencies
- **Core**: scapy, pyshark, cryptography, requests
- **Analysis**: pandas, numpy, matplotlib, seaborn
- **Utilities**: pyyaml, click, rich, colorama
- **Optional**: python-nmap, psutil, paramiko

### Error Handling
- Gracefully handle missing dependencies with fallback options
- Provide clear error messages for common issues
- Use try-catch blocks for network operations and file I/O
- Implement timeout mechanisms for network operations

### Performance
- Use threading for concurrent network operations
- Implement proper memory management for large packet captures
- Include performance monitoring and statistics
- Optimize data structures for large-scale analysis

### Configuration
- Use YAML configuration files for flexibility
- Support both file-based and programmatic configuration
- Validate configuration parameters before use
- Provide sensible defaults for all settings

When generating code for this project:
1. Prioritize security and ethical usage
2. Include proper error handling and logging
3. Use type hints and comprehensive documentation
4. Follow the established module structure
5. Consider performance implications for network operations
6. Include appropriate legal and ethical disclaimers
