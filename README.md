# Net-Watcher

A powerful Python-based network connection monitor and DNS sniffer that provides real-time monitoring of TCP, UDP, and ICMP connections with DNS resolution capabilities.

## Features

### 🔍 **Real-time Network Monitoring**

- **TCP Connection Tracking**: Monitor all outgoing TCP connections
- **UDP Packet Analysis**: Capture and analyze UDP traffic (excluding DNS)
- **ICMP Monitoring**: Track ping requests and other ICMP traffic
- **Process Association**: Link network connections to specific processes

### 🌐 **DNS Sniffing & Caching**

- **DNS Query Resolution**: Capture DNS queries and responses in real-time
- **Smart Caching**: Automatic DNS-to-IP mapping with configurable timeout
- **Domain Resolution**: Display domain names instead of IP addresses when available

### 📊 **Advanced Features**

- **Five-tuple Deduplication**: Prevent duplicate connection logging (configurable timeout)
- **Color-coded Output**: Easy-to-read terminal output with protocol-specific colors
- **Multiple Log Formats**: Full logs, IP-only logs, and DNS-specific logs
- **Configurable Settings**: Extensive configuration options via JSON files
- **Thread-safe Design**: Multi-threaded architecture for concurrent monitoring

## Installation

### Prerequisites

- **Python 3.7+**
- **Administrator/root privileges** (required for packet sniffing)
- **Npcap/WinPcap** (Windows users) or **libpcap** (Linux/macOS)

### Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- `psutil` - Process and system utilities
- `scapy` - Packet manipulation and sniffing
- `colorama` - Cross-platform colored terminal text

## Quick Start

### Basic Usage

```bash
# Run with default settings
python net-watcher.py

# Run with custom configuration
python net-watcher.py --config custom_config.json
```

### Configuration

Create a configuration file (`network_monitor_config.json`) to customize behavior:

```json
{
  "check_interval": 1.0,
  "enable_file_output": true,
  "enable_dns_sniff": true,
  "enable_udp_sniff": true,
  "dns_cache_timeout": 36000,
  "max_dns_cache_size": 10000,
  "capture_ipv4": true,
  "capture_ipv6": false,
  "capture_tcp": true,
  "capture_udp": true,
  "capture_icmp": true,
  "interface": "auto",
  "packet_filter": "",
  "duplicate_suppress_time": 300,
  "output_dir": "network_logs"
}
```

## Output Format

### Terminal Display
```
[11-01 14:30:25] [TCP] chrome.exe (PID: 1234) google.com (172.217.14.206):443 🔗 192.168.1.100:54321
[11-01 14:30:26] [DNS] google.com 🌐 172.217.14.206
[11-01 14:30:27] [ICMP] 192.168.1.100 🏓 8.8.8.8 Echo Request (Ping请求) 0
```

### Log Files

- **Full Logs**: Complete connection information with timestamps
- **IP-only Logs**: Clean list of IP addresses for analysis
- **DNS Logs**: DNS resolution history with timestamps

## Protocol Support

| Protocol | Status | Features |
|----------|--------|----------|
| **TCP** | ✅ Full Support | Connection tracking, process association |
| **UDP** | ✅ Full Support | Packet analysis, connection discovery |
| **DNS** | ✅ Full Support | Query/response capture, caching |
| **ICMP** | ✅ Full Support | Ping monitoring, type/code analysis |

## Advanced Usage

### Custom Packet Filtering

Use BPF (Berkeley Packet Filter) syntax for custom filtering:

```python
# Example: Monitor only HTTP/HTTPS traffic
config.packet_filter = "tcp port 80 or tcp port 443"
```

### Programmatic Usage

```python
from net_watcher import NetworkConnectionMonitor, MonitorConfig

# Create custom configuration
config = MonitorConfig(
    check_interval=0.5,
    enable_dns_sniff=True,
    capture_icmp=False
)

# Initialize monitor
monitor = NetworkConnectionMonitor(config)

# Start monitoring
monitor.monitor()
```

## Troubleshooting

### Common Issues

**Permission Errors:**

```bash
# Linux/macOS
sudo python net-watcher.py

# Windows - Run as Administrator
```

**Missing Dependencies:**

```bash
# Install Npcap (Windows)
# Download from: https://npcap.com/

# Install libpcap (Linux)
sudo apt-get install libpcap-dev  # Ubuntu/Debian
sudo yum install libpcap-devel    # CentOS/RHEL
```

**Scapy Installation Issues:**

```bash
# If scapy fails to install
pip install --upgrade pip
pip install scapy[basic]
```

## File Structure

```
net-watcher/
├── net-watcher.py          # Main application
├── requirements.txt         # Python dependencies
├── network_monitor_config.json  # Configuration file
├── dns_cache.json          # DNS cache (auto-generated)
└── network_logs/           # Log directory (auto-generated)
    ├── full_log_*.txt      # Complete connection logs
    ├── ip_only_*.txt       # IP address lists
    └── dns_log_*.txt       # DNS resolution logs
```

## Security Considerations

- Requires elevated privileges for packet sniffing
- Only monitors outgoing connections by default
- DNS caching respects privacy with configurable timeouts
- No sensitive data is stored in logs

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is open source and available under the [MIT License](LICENSE).

## Acknowledgments

- Built with [Scapy](https://scapy.net/) for packet manipulation
- Uses [psutil](https://github.com/giampaolo/psutil) for process information
- Terminal colors provided by [colorama](https://github.com/tartley/colorama)
