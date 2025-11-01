#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import signal
import psutil
import socket
import threading
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from colorama import init, Fore, Back, Style
from typing import Set, List, Tuple, Optional, Dict
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP, TCP, ICMP
init(autoreset=True)  # 自动重置颜色


@dataclass
class MonitorConfig:
    """网络监控配置数据类"""
    # 基本监控配置
    check_interval: float = 1.0
    enable_file_output: bool = True
    enable_dns_sniff: bool = True
    enable_udp_sniff: bool = True
    
    # DNS配置
    dns_cache_timeout: int = 36000  # DNS缓存超时时间（秒）
    max_dns_cache_size: int = 10000  # DNS缓存最大条目数
    
    # 协议捕获配置
    capture_ipv4: bool = True
    capture_ipv6: bool = False
    capture_tcp: bool = True
    capture_udp: bool = True
    capture_icmp: bool = True
    
    # 网络接口配置
    interface: str = 'auto'
    packet_filter: str = ''
    
    # 去重配置
    duplicate_suppress_time: int = 300  # 五元组去重时间（秒）
    
    # 输出目录配置
    output_dir: str = "network_logs"

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            'check_interval': self.check_interval,
            'enable_file_output': self.enable_file_output,
            'enable_dns_sniff': self.enable_dns_sniff,
            'enable_udp_sniff': self.enable_udp_sniff,
            'dns_cache_timeout': self.dns_cache_timeout,
            'max_dns_cache_size': self.max_dns_cache_size,
            'capture_ipv4': self.capture_ipv4,
            'capture_ipv6': self.capture_ipv6,
            'capture_tcp': self.capture_tcp,
            'capture_udp': self.capture_udp,
            'capture_icmp': self.capture_icmp,
            'interface': self.interface,
            'packet_filter': self.packet_filter,
            'duplicate_suppress_time': self.duplicate_suppress_time,
            'output_dir': self.output_dir
        }
    
    @classmethod
    def from_dict(cls, config_dict: dict) -> 'MonitorConfig':
        """从字典创建配置对象"""
        return cls(**{k: v for k, v in config_dict.items() if hasattr(cls, k)})
    
    def save_to_file(self, filename: str = "network_monitor_config.json"):
        """保存配置到文件"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
            print(f"配置已保存到 {filename}")
        except Exception as e:
            print(f"保存配置失败: {e}")
    
    @classmethod
    def load_from_file(cls, filename: str = "network_monitor_config.json") -> 'MonitorConfig':
        """从文件加载配置"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                config_dict = json.load(f)
            print(f"配置已从 {filename} 加载")
            return cls.from_dict(config_dict)
        except FileNotFoundError:
            print(f"配置文件 {filename} 不存在，使用默认配置")
            return cls()
        except Exception as e:
            print(f"加载配置失败: {e}，使用默认配置")
            return cls()


class NetworkConnectionMonitor:

    def __init__(self, config: Optional[MonitorConfig] = None):
        """
        初始化网络连接监控器（TCP和UDP）
        
        Args:
            config: 监控配置对象，如果为None则使用默认配置
        """
        # 使用传入的配置或创建默认配置
        self.config = config if config is not None else MonitorConfig()
        
        # 从配置中提取常用属性
        self.check_interval = self.config.check_interval
        self.enable_file_output = self.config.enable_file_output
        self.enable_dns_sniff = self.config.enable_dns_sniff
        self.enable_udp_sniff = self.config.enable_udp_sniff
        
        self.known_connections: Set[str] = set()
        self.dns_cache_timestamps: Dict[str, float] = {}  # DNS缓存时间戳

        # 创建输出目录
        if self.enable_file_output:
            self.output_dir = self.config.output_dir
            os.makedirs(self.output_dir, exist_ok=True)
            
            # 生成带时间戳的文件名
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.full_log_file = os.path.join(self.output_dir, f"full_log_{timestamp}.txt")
            self.ip_only_file = os.path.join(self.output_dir, f"ip_only_{timestamp}.txt")
            self.dns_log_file = os.path.join(self.output_dir, f"dns_log_{timestamp}.txt")
            
            # 初始化文件
            self._init_log_files()

        # DNS相关
        self.dns_cache: Dict[str, Dict[str, any]] = {}  # IP -> {domain: 域名, timestamp: 时间戳}
        self.dns_lock = threading.Lock()
        self.dns_running = False
        self.dns_thread = None
        self.dns_packet_count = 0
        
        # 监控控制
        self.network_running = False
        
        # UDP嗅探相关
        self.udp_running = False
        self.udp_thread = None
        self.udp_packet_count = 0
        self.udp_connections: Set[str] = set()  # 存储发现的UDP连接
        
        # TCP嗅探相关
        self.tcp_running = False
        self.tcp_thread = None
        self.tcp_packet_count = 0
        self.tcp_connections: Set[str] = set()  # 存储发现的TCP连接
        
        # ICMP嗅探相关
        self.icmp_running = False
        self.icmp_thread = None
        self.icmp_packet_count = 0
        self.icmp_connections: Set[str] = set()  # 存储发现的ICMP连接
        
        # 五元组去重控制
        self.five_tuple_timestamps: Dict[str, float] = {}  # 存储五元组的最后输出时间
        self.five_tuple_lock = threading.Lock()
        
        # DNS缓存文件路径
        self.dns_cache_file = "dns_cache.json"
        
        # 设置信号处理
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # 启动时加载DNS缓存
        self.load_dns_cache()

    def _signal_handler(self, signum, frame):
        """处理退出信号"""
        print(f"\n收到退出信号，正在停止监控...")
        self.stop()
        sys.exit(0)

    def get_outbound_ipv4_connections(self) -> List[Tuple[str, int, str, int, dict, str]]:
        """
        获取本机向外的IPv4连接（仅TCP，UDP通过scapy嗅探）
        
        Returns:
            连接列表，格式为 [(本地IP, 本地端口, 远程IP, 远程端口, 进程信息, 协议类型), ...]
        """
        connections = []

        # TCP和UDP连接现在都通过scapy嗅探获取
        # 这个方法主要用于兼容性，实际的连接发现在数据包处理方法中进行
            
        return connections
    
    def _is_ipv4(self, ip: str) -> bool:
        """检查是否为IPv4地址"""
        try:
            socket.inet_aton(ip)
            return '.' in ip  # 简单检查IPv4格式
        except socket.error:
            return False
    
    def _is_loopback(self, ip: str) -> bool:
        """检查是否为回环地址"""
        return ip.startswith('127.') or ip == 'localhost'
    
    def _is_private_ip(self, ip: str) -> bool:
        """检查是否为私有IP地址"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
            
        try:
            first = int(parts[0])
            second = int(parts[1])
            
            # 10.0.0.0/8
            if first == 10:
                return True
            # 172.16.0.0/12
            elif first == 172 and 16 <= second <= 31:
                return True
            # 192.168.0.0/16
            elif first == 192 and second == 168:
                return True
                
        except ValueError:
            pass
            
        return False
    
    def _get_process_info(self, pid: Optional[int]) -> dict:
        """获取进程信息"""
        if pid is None:
            return {"name": "未知", "pid": "N/A", "exe": "N/A"}
        
        try:
            process = psutil.Process(pid)
            return {
                "name": process.name(),
                "pid": pid,
                "exe": process.exe() if hasattr(process, 'exe') else "N/A"
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return {"name": "无法访问", "pid": pid, "exe": "N/A"}
    
    def _init_log_files(self):
        """初始化日志文件"""
        header_time = datetime.now().strftime("%m-%d %H:%M:%S")
        
        # 完整日志文件头部
        with open(self.full_log_file, 'w', encoding='utf-8') as f:
            f.write(f"网络连接监控日志 - 完整记录（TCP和UDP）\n")
            f.write(f"开始时间: {header_time}\n")
            f.write("=" * 80 + "\n")
        
        # IP地址文件头部
        with open(self.ip_only_file, 'w', encoding='utf-8') as f:
            f.write(f"# 网络连接监控 - 仅IP地址（TCP和UDP）\n")
            f.write(f"# 开始时间: {header_time}\n")
        
        # DNS日志文件头部
        with open(self.dns_log_file, 'w', encoding='utf-8') as f:
            f.write(f"DNS解析日志\n")
            f.write(f"开始时间: {header_time}\n")
            f.write("格式: [时间] 域名 -> IP地址\n")
            f.write("=" * 80 + "\n")
    
    def _get_display_address(self, ip: str) -> str:
        """
        获取显示用的地址（优先显示域名）
        """
        with self.dns_lock:
            cache_entry = self.dns_cache.get(ip)
            if cache_entry and not self._is_dns_cache_expired(cache_entry):
                domain = cache_entry['domain']
                return f"{domain} ({ip})"
            return ip
    
    def _is_dns_cache_expired(self, cache_entry: Dict[str, any]) -> bool:
        """检查DNS缓存条目是否过期"""
        current_time = time.time()
        return (current_time - cache_entry['timestamp']) > self.config.dns_cache_timeout
    
    def clean_expired_dns_cache(self):
        """清理过期的DNS缓存"""
        with self.dns_lock:
            expired_ips = []
            for ip, cache_entry in self.dns_cache.items():
                if self._is_dns_cache_expired(cache_entry):
                    expired_ips.append(ip)
            
            for ip in expired_ips:
                del self.dns_cache[ip]
            
            if expired_ips:
                print(f"[DNS] 清理了 {len(expired_ips)} 个过期的DNS缓存条目")
    
    def _load_cache_from_file(self, cache_file, cache_dict, cache_lock, cache_name, validator_func=None):
        """通用缓存加载方法"""
        try:
            if os.path.exists(cache_file):
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                
                loaded_count = 0
                expired_count = 0
                
                with cache_lock:
                    for key, cache_entry in cache_data.items():
                        if validator_func:
                            if validator_func(cache_entry):
                                cache_dict[key] = cache_entry
                                loaded_count += 1
                            else:
                                expired_count += 1
                        else:
                            cache_dict[key] = cache_entry
                            loaded_count += 1
                
                print(f"[{cache_name}] 从缓存文件加载了 {loaded_count} 个记录")
                if expired_count > 0:
                    print(f"[{cache_name}] 跳过了 {expired_count} 个过期的记录")
            else:
                print(f"[{cache_name}] 缓存文件不存在，将创建新的缓存")
                
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            print(f"[{cache_name}] 缓存文件格式错误，将重新开始: {e}")
            with cache_lock:
                cache_dict.clear()
        except Exception as e:
            print(f"[{cache_name}] 加载缓存文件时发生错误: {e}")
            with cache_lock:
                cache_dict.clear()
    
    def _save_cache_to_file(self, cache_file, cache_dict, cache_lock, cache_name, cleanup_func=None):
        """通用缓存保存方法"""
        try:
            # 先清理过期的缓存（如果提供了清理函数）
            if cleanup_func:
                cleanup_func()
            
            with cache_lock:
                cache_data = dict(cache_dict)
            
            # 保存到文件
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, ensure_ascii=False, indent=2)
            
            print(f"[{cache_name}] 已保存 {len(cache_data)} 个缓存记录到文件")
            
        except Exception as e:
            print(f"[{cache_name}] 保存缓存文件时发生错误: {e}")
    
    def _dns_cache_validator(self, cache_entry):
        """DNS缓存验证器"""
        return (isinstance(cache_entry, dict) and 
                'domain' in cache_entry and 
                'timestamp' in cache_entry and 
                not self._is_dns_cache_expired(cache_entry))
    
    def load_dns_cache(self):
        """从文件加载DNS缓存"""
        self._load_cache_from_file(
            self.dns_cache_file, 
            self.dns_cache, 
            self.dns_lock, 
            "DNS", 
            self._dns_cache_validator
        )
    
    def save_dns_cache(self):
        """保存DNS缓存到文件"""
        self._save_cache_to_file(
            self.dns_cache_file, 
            self.dns_cache, 
            self.dns_lock, 
            "DNS", 
            self.clean_expired_dns_cache
        )
    
    def _write_to_files(self, full_info: str, ip_address: str, dns_info: Optional[str] = None):
        """写入到各个日志文件"""
        if not self.enable_file_output:
            return
            
        try:
            # 写入完整日志
            with open(self.full_log_file, 'a', encoding='utf-8') as f:
                f.write(full_info + "\n")
            
            # 写入IP地址文件
            with open(self.ip_only_file, 'a', encoding='utf-8') as f:
                f.write(ip_address + "\n")
            
            # 写入DNS日志（如果有DNS信息）
            if dns_info:
                with open(self.dns_log_file, 'a', encoding='utf-8') as f:
                    f.write(dns_info + "\n")
                    
        except Exception as e:
            print(f"写入文件时发生错误: {e}")
    
    def format_connection_info(self, local_ip: str, local_port: int, 
                             remote_ip: str, remote_port: int, process_info: dict, protocol: str) -> str:
        """格式化连接信息"""
        timestamp = datetime.now().strftime("%m-%d %H:%M:%S")
        
        process_name = process_info.get("name", "未知")
        process_pid = process_info.get("pid", "N/A")
        
        # 使用域名显示（如果有的话）
        if remote_ip == "LISTENING":
            display_address = "LISTENING"
        else:
            display_address = self._get_display_address(remote_ip)
        
        # 彩色格式化
        # 时间戳 - 灰色
        time_str = f"{Fore.WHITE}[{timestamp}]{Style.RESET_ALL}"

        # 协议标识
        if protocol == 'TCP':
            protocol_str = f"{Fore.GREEN}[TCP]{Style.RESET_ALL}"
        elif protocol == 'UDP':
            protocol_str = f"{Fore.BLUE}[UDP]{Style.RESET_ALL}"
        elif protocol == 'UDP-LISTEN':
            protocol_str = f"{Fore.YELLOW}[UDP-LISTEN]{Style.RESET_ALL}"
        elif protocol == 'ICMP':
            protocol_str = f"{Fore.RED}[ICMP]{Style.RESET_ALL}"
        else:
            protocol_str = f"{Fore.WHITE}[{protocol}]{Style.RESET_ALL}"
        
        # 远程地址 - 青色
        if remote_port == 0:
            remote_str = f"{Fore.CYAN}{display_address}{Style.RESET_ALL}"
        else:
            remote_str = f"{Fore.CYAN}{display_address}{Style.RESET_ALL}:{Fore.MAGENTA}{remote_port}{Style.RESET_ALL}"
        
        # 本地地址 - 蓝色
        local_str = f"{Fore.BLUE}{local_ip}{Style.RESET_ALL}:{Fore.MAGENTA}{local_port}{Style.RESET_ALL}"
        
        # 进程名 - 绿色
        process_str = f"{Fore.GREEN}{process_name}{Style.RESET_ALL} (PID: {Fore.YELLOW}{process_pid}{Style.RESET_ALL})"
        
        return f"{time_str} {protocol_str}{Fore.WHITE}{Style.RESET_ALL} {process_str} {remote_str} 🔗 {local_str}"
    
    def _should_output_connection(self, local_ip: str, local_port: int, 
                                remote_ip: str, remote_port: int, protocol: str) -> bool:
        """检查是否应该输出连接信息（五元组去重检查）"""
        # 创建五元组标识符
        five_tuple = f"{protocol}:{local_ip}:{local_port}:{remote_ip}:{remote_port}"
        
        current_time = time.time()
        
        with self.five_tuple_lock:
            last_output_time = self.five_tuple_timestamps.get(five_tuple)
            
            # 如果从未输出过，或者距离上次输出已超过配置的时间
            if last_output_time is None or (current_time - last_output_time) >= self.config.duplicate_suppress_time:
                # 更新时间戳
                self.five_tuple_timestamps[five_tuple] = current_time
                return True
            else:
                return False
    
    def _process_new_connection(self, local_ip: str, local_port: int, 
                              remote_ip: str, remote_port: int, process_info: dict, protocol: str):
        """处理新连接，包括DNS解析和文件写入"""
        # 跳过内网地址（除了UDP监听）
        if protocol != 'UDP-LISTEN' and remote_ip != "LISTENING" and self._is_private_ip(remote_ip):
            return
        
        # 检查是否应该输出（五元组去重）
        if not self._should_output_connection(local_ip, local_port, remote_ip, remote_port, protocol):
            return
            
        # 格式化连接信息
        full_info = self.format_connection_info(local_ip, local_port, remote_ip, remote_port, process_info, protocol)
        print(full_info)
        
        if self.enable_file_output:
            ip_to_log = remote_ip if remote_ip != "LISTENING" else local_ip
            self._write_to_files(full_info, ip_to_log)

    # 通用数据包处理方法
    def _process_packet(self, packet, protocol_type):
        """通用数据包处理方法"""
        protocol_config = {
            'TCP': {
                'running_flag': 'tcp_running',
                'config_key': 'capture_tcp',
                'layer_class': TCP,
                'packet_count_attr': 'tcp_packet_count',
                'connections_attr': 'tcp_connections',
                'protocol_name': 'tcp'
            },
            'UDP': {
                'running_flag': 'udp_running',
                'config_key': 'capture_udp',
                'layer_class': UDP,
                'packet_count_attr': 'udp_packet_count',
                'connections_attr': 'udp_connections',
                'protocol_name': 'udp'
            },
            'ICMP': {
                'running_flag': 'icmp_running',
                'config_key': 'capture_icmp',
                'layer_class': ICMP,
                'packet_count_attr': 'icmp_packet_count',
                'connections_attr': 'icmp_connections',
                'protocol_name': None
            }
        }

        config = protocol_config.get(protocol_type)
        if not config:
            return
            
        # 检查运行状态
        if not getattr(self, config['running_flag']):
            return
        
        try:
            # 检查是否启用该协议捕获
            if not getattr(self.config, config['config_key']):
                return
                
            if not packet.haslayer(config['layer_class']) or not packet.haslayer(IP):
                return
            
            # 增加数据包计数
            current_count = getattr(self, config['packet_count_attr'])
            setattr(self, config['packet_count_attr'], current_count + 1)
            
            ip_layer = packet[IP]
            protocol_layer = packet[config['layer_class']]
            
            local_ip = ip_layer.src
            remote_ip = ip_layer.dst
            
            # 跳过回环地址
            if self._is_loopback(local_ip) or self._is_loopback(remote_ip):
                return
            
            # 协议特定处理
            if protocol_type == 'TCP':
                self._handle_tcp_specific(packet, ip_layer, protocol_layer, config)
            elif protocol_type == 'UDP':
                self._handle_udp_specific(packet, ip_layer, protocol_layer, config)
            elif protocol_type == 'ICMP':
                self._handle_icmp_specific(packet, ip_layer, protocol_layer, config)
                
        except Exception as e:
            pass  # 忽略数据包处理错误
    
    def _handle_tcp_specific(self, packet, ip_layer, tcp_layer, config):
        """处理TCP特定逻辑"""
        local_ip = ip_layer.src
        remote_ip = ip_layer.dst
        local_port = tcp_layer.sport
        remote_port = tcp_layer.dport
        
        # 只处理已建立的连接（有 ACK 标志且不是 SYN）
        if not (tcp_layer.flags & 0x10):  # 没有 ACK 标志
            return
        
        connection_key = f"TCP:{remote_ip}:{remote_port}:{local_port}"
        connections_set = getattr(self, config['connections_attr'])
        
        if connection_key not in connections_set:
            connections_set.add(connection_key)
            process_info = self._get_process_info_by_port(local_port, config['protocol_name'])
            self._process_new_connection(local_ip, local_port, remote_ip, remote_port, process_info, 'TCP')
    
    def _handle_udp_specific(self, packet, ip_layer, udp_layer, config):
        """处理UDP特定逻辑"""
        local_ip = ip_layer.src
        remote_ip = ip_layer.dst
        local_port = udp_layer.sport
        remote_port = udp_layer.dport
        
        # 跳过DNS数据包（由DNS嗅探处理）
        if local_port == 53 or remote_port == 53:
            return
        
        connection_key = f"UDP:{remote_ip}:{remote_port}:{local_port}"
        connections_set = getattr(self, config['connections_attr'])
        
        if connection_key not in connections_set:
            connections_set.add(connection_key)
            process_info = self._get_process_info_by_port(local_port, config['protocol_name'])
            self._process_new_connection(local_ip, local_port, remote_ip, remote_port, process_info, 'UDP')
    
    def _handle_icmp_specific(self, packet, ip_layer, icmp_layer, config):
        """处理ICMP特定逻辑"""
        local_ip = ip_layer.src
        remote_ip = ip_layer.dst
        
        # ICMP类型映射
        icmp_types = {
            0: "Echo Reply (Ping回复)",
            3: "Destination Unreachable (目标不可达)",
            4: "Source Quench (源端抑制)",
            5: "Redirect (重定向)",
            8: "Echo Request (Ping请求)",
            11: "Time Exceeded (超时)",
            12: "Parameter Problem (参数问题)",
            13: "Timestamp Request (时间戳请求)",
            14: "Timestamp Reply (时间戳回复)",
            15: "Information Request (信息请求)",
            16: "Information Reply (信息回复)"
        }
        
        icmp_type = icmp_layer.type
        icmp_code = icmp_layer.code
        icmp_type_name = icmp_types.get(icmp_type, f"未知类型({icmp_type})")
        
        connection_key = f"ICMP:{remote_ip}:{icmp_type}:{icmp_code}"
        connections_set = getattr(self, config['connections_attr'])
        
        if connection_key not in connections_set:
            connections_set.add(connection_key)
            process_info = {"name": "系统", "pid": "N/A", "exe": "N/A"}
            
            # 格式化ICMP信息显示
            timestamp = datetime.now().strftime("%m-%d %H:%M:%S")
            local_display = self._get_display_address(local_ip)
            remote_display = self._get_display_address(remote_ip)
            time_str = f"{Fore.WHITE}[{timestamp}]{Style.RESET_ALL}"
            print(f"{time_str} {Fore.RED}[ICMP]{Style.RESET_ALL} {Fore.CYAN}{local_display}{Style.RESET_ALL} 🏓 {Fore.CYAN}{remote_display}{Style.RESET_ALL} {Fore.YELLOW}{icmp_type_name}{Style.RESET_ALL} {Fore.MAGENTA}{icmp_code}{Style.RESET_ALL}")

            if self.enable_file_output:
                full_info = f"[{time_str}] [ICMP] {local_display} -> {remote_display} {icmp_type_name}"
                self._write_to_files(full_info, remote_ip)

    # 协议特定的包装方法
    def _process_tcp_packet(self, packet):
        """处理TCP数据包"""
        self._process_packet(packet, 'TCP')

    def _process_udp_packet(self, packet):
        """处理UDP数据包"""
        self._process_packet(packet, 'UDP')
    
    def _process_icmp_packet(self, packet):
        """处理ICMP数据包"""
        self._process_packet(packet, 'ICMP')
    
    def _get_process_info_by_port(self, port: int, protocol: str) -> dict:
        """通过端口号获取进程信息"""
        try:
            for conn in psutil.net_connections(kind=protocol):
                if conn.laddr and conn.laddr[1] == port:
                    return self._get_process_info(conn.pid)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        
        return {"name": "未知", "pid": "N/A", "exe": "N/A"}
    
    def _start_protocol_sniffer(self, protocol_type):
        """通用协议嗅探器启动方法"""
        sniffer_config = {
            'TCP': {
                'check_condition': True,
                'running_flag': 'tcp_running',
                'filter': "tcp",
                'process_func': self._process_tcp_packet,
                'name': 'TCP'
            },
            'UDP': {
                'check_condition': self.enable_udp_sniff,
                'running_flag': 'udp_running',
                'filter': "udp and not port 53",
                'process_func': self._process_udp_packet,
                'name': 'UDP'
            },
            'ICMP': {
                'check_condition': True,
                'running_flag': 'icmp_running',
                'filter': "icmp",
                'process_func': self._process_icmp_packet,
                'name': 'ICMP'
            },
            'DNS': {
                'check_condition': self.enable_dns_sniff,
                'running_flag': 'dns_running',
                'filter': "udp port 53",
                'process_func': self._process_dns_packet,
                'name': 'DNS'
            }
        }
        
        config = sniffer_config.get(protocol_type)
        if not config:
            return
            
        if not config['check_condition']:
            return
            
        print(f"[{config['name']}] 启动{config['name']}数据包嗅探...")
        setattr(self, config['running_flag'], True)
        
        try:
            sniff(
                filter=config['filter'],
                prn=config['process_func'],
                stop_filter=lambda x: not getattr(self, config['running_flag']),
                store=0  # 不存储数据包，节省内存
            )
        except PermissionError:
            print(f"[{config['name']}] 错误: 需要管理员权限来嗅探网络数据包")
        except Exception as e:
            print(f"[{config['name']}] {config['name']}嗅探过程中发生错误: {e}")
        finally:
            setattr(self, config['running_flag'], False)
    
    def _start_tcp_sniffer(self):
        """启动TCP数据包嗅探（在单独线程中运行）"""
        self._start_protocol_sniffer('TCP')
    
    def _start_udp_sniffer(self):
        """启动UDP数据包嗅探（在单独线程中运行）"""
        self._start_protocol_sniffer('UDP')
    
    def _start_icmp_sniffer(self):
        """启动ICMP数据包嗅探（在单独线程中运行）"""
        self._start_protocol_sniffer('ICMP')

    # DNS嗅探相关方法
    def _process_dns_packet(self, packet):
        """处理DNS数据包"""
        if not self.dns_running:
            return
        
        try:
            if not packet.haslayer(DNS):
                return
            
            self.dns_packet_count += 1
            timestamp = datetime.now().strftime("%m-%d %H:%M:%S")

            ip_layer = packet[IP]
            dns_layer = packet[DNS]
            
            # 只处理DNS响应
            if dns_layer.qr != 1:  # 不是响应
                return

            # 处理查询部分获取域名
            domain = None
            if dns_layer.qd and hasattr(dns_layer.qd, 'qname'):
                domain = dns_layer.qd.qname.decode('utf-8').rstrip('.')
            
            # 处理响应部分获取IP地址
            if dns_layer.ancount > 0 and domain:
                try:
                    # 解析答案记录
                    if hasattr(dns_layer, 'an') and dns_layer.an:
                        answer = dns_layer.an
                        # 检查是否是A记录（IPv4地址）
                        if hasattr(answer, 'type') and answer.type == 1:  # A记录
                            if hasattr(answer, 'rdata'):
                                ip_address = str(answer.rdata)
                                
                                # 更新DNS缓存（包含时间戳）
                                with self.dns_lock:
                                    # 检查缓存大小限制
                                    if len(self.dns_cache) >= self.config.max_dns_cache_size:
                                        # 删除最旧的缓存条目
                                        oldest_ip = min(self.dns_cache.keys(), 
                                                       key=lambda k: self.dns_cache[k]['timestamp'])
                                        del self.dns_cache[oldest_ip]
                                    
                                    self.dns_cache[ip_address] = {
                                        'domain': domain,
                                        'timestamp': time.time()
                                    }
                                
                                # 记录DNS解析
                                dns_info = f"[{timestamp}] DNS解析: {domain} -> {ip_address}"
                                time_str = f"{Fore.WHITE}[{timestamp}]{Style.RESET_ALL}"
                                print(f"{time_str} {Fore.LIGHTBLUE_EX}[DNS]{Style.RESET_ALL} {Fore.CYAN}{domain}{Style.RESET_ALL} 🌐 {Fore.CYAN}{ip_address}{Style.RESET_ALL}")

                                if self.enable_file_output:
                                    self._write_to_files("", "", dns_info)
                                
                except Exception as e:
                    pass  # 忽略解析错误
                    
        except Exception as e:
            pass  # 忽略数据包处理错误
    
    def _get_dns_type_name(self, qtype):
        """获取DNS查询类型名称"""
        dns_types = {
            1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
            15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY'
        }
        return dns_types.get(qtype, f'TYPE{qtype}')
    
    def _start_dns_sniffer(self):
        """启动DNS嗅探（在单独线程中运行）"""
        self._start_protocol_sniffer('DNS')
    
    def _start_sniffers(self, sniffers):
        """通用嗅探器启动方法"""
        for sniffer in sniffers:
            if sniffer['condition']:
                print(f"{sniffer['color']}{sniffer['icon']} 启动{sniffer['name']}数据包嗅探功能...{Style.RESET_ALL}")
                thread = threading.Thread(target=sniffer['start_func'], daemon=True)
                setattr(self, sniffer['thread_attr'], thread)
                thread.start()
                time.sleep(0.5)  # 等待嗅探启动
            else:
                print(f"{Fore.RED}⚠️  {sniffer['disabled_msg']}{Style.RESET_ALL}")
    
    def monitor(self):
        """开始监控连接"""
        print(f"{Style.BRIGHT}{Fore.GREEN}🚀 网络连接监控器 + DNS嗅探器（TCP和UDP）{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
        
        # 定义嗅探器配置
        sniffers = [
            {
                'name': 'TCP',
                'condition': True,
                'thread_attr': 'tcp_thread',
                'start_func': self._start_tcp_sniffer,
                'color': Fore.GREEN,
                'icon': '📡',
                'disabled_msg': 'TCP嗅探功能已禁用'
            },
            {
                'name': 'UDP',
                'condition': self.enable_udp_sniff,
                'thread_attr': 'udp_thread',
                'start_func': self._start_udp_sniffer,
                'color': Fore.BLUE,
                'icon': '📡',
                'disabled_msg': 'UDP嗅探功能已禁用'
            },
            {
                'name': 'DNS',
                'condition': self.enable_dns_sniff,
                'thread_attr': 'dns_thread',
                'start_func': self._start_dns_sniffer,
                'color': Fore.YELLOW,
                'icon': '🔍',
                'disabled_msg': 'DNS嗅探功能已禁用'
            },
            {
                'name': 'ICMP',
                'condition': self.config.capture_icmp,
                'thread_attr': 'icmp_thread',
                'start_func': self._start_icmp_sniffer,
                'color': Fore.RED,
                'icon': '🔍',
                'disabled_msg': 'ICMP嗅探功能已禁用'
            }
        ]
        
        # 启动所有嗅探器
        self._start_sniffers(sniffers)
        
        # 启动定期清理过期DNS缓存的线程
        cleanup_thread = threading.Thread(target=self._periodic_dns_cleanup, daemon=True)
        cleanup_thread.start()
        
        print(f"{Fore.GREEN}📡 开始监控网络连接（TCP和UDP）...{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}🔄 五元组去重: 同一连接5分钟内不重复输出{Style.RESET_ALL}")
        if self.enable_file_output:
            print(f"{Fore.BLUE}📁 日志文件保存在: {Fore.YELLOW}{self.output_dir}/{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}• 完整日志: {Fore.CYAN}{os.path.basename(self.full_log_file)}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}• IP地址: {Fore.CYAN}{os.path.basename(self.ip_only_file)}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}• DNS日志: {Fore.CYAN}{os.path.basename(self.dns_log_file)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⌨️  按 Ctrl+C 停止监控{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'-' * 80}{Style.RESET_ALL}")
        
        self.network_running = True
        
        try:
            while self.network_running:
                current_connections = self.get_outbound_ipv4_connections()
                
                # 检查新增的连接
                for local_ip, local_port, remote_ip, remote_port, process_info, protocol in current_connections:
                    connection_key = f"{protocol}:{remote_ip}:{remote_port}:{local_port}"
                    
                    if connection_key not in self.known_connections:
                        # 发现新连接
                        self.known_connections.add(connection_key)
                        self._process_new_connection(local_ip, local_port, remote_ip, remote_port, process_info, protocol)
                
                # 清理已断开的连接
                current_connection_keys = {f"{protocol}:{remote_ip}:{remote_port}:{local_port}" 
                                         for _, local_port, remote_ip, remote_port, _, protocol in current_connections}
                self.known_connections &= current_connection_keys
                
                time.sleep(self.check_interval)
                
        except KeyboardInterrupt:
            print("\n正在停止监控...")
        except Exception as e:
            print(f"监控过程中发生错误: {e}")
        finally:
            self.stop()
    
    def _periodic_dns_cleanup(self):
        """定期清理过期的DNS缓存和五元组时间戳"""
        while self.network_running:
            time.sleep(3600)  # 每小时检查一次
            self.clean_expired_dns_cache()
            self._clean_expired_five_tuples()
    
    def _clean_expired_five_tuples(self):
        """清理过期的五元组时间戳记录"""
        current_time = time.time()
        expired_tuples = []
        
        with self.five_tuple_lock:
            for five_tuple, timestamp in self.five_tuple_timestamps.items():
                # 如果超过1小时未使用，则清理（避免内存泄漏）
                if (current_time - timestamp) > 3600:
                    expired_tuples.append(five_tuple)
            
            for five_tuple in expired_tuples:
                del self.five_tuple_timestamps[five_tuple]
        
        if expired_tuples:
            print(f"[清理] 清理了 {len(expired_tuples)} 个过期的五元组记录")
    
    def _stop_threads(self):
        """通用线程停止方法"""
        threads_to_stop = [
            {'name': 'TCP', 'thread_attr': 'tcp_thread', 'running_flag': 'tcp_running'},
            {'name': 'UDP', 'thread_attr': 'udp_thread', 'running_flag': 'udp_running'},
            {'name': 'DNS', 'thread_attr': 'dns_thread', 'running_flag': 'dns_running'},
            {'name': 'ICMP', 'thread_attr': 'icmp_thread', 'running_flag': 'icmp_running'}
        ]
        
        # 设置所有运行标志为False
        for thread_info in threads_to_stop:
            setattr(self, thread_info['running_flag'], False)
        
        # 等待所有线程结束
        for thread_info in threads_to_stop:
            thread = getattr(self, thread_info['thread_attr'], None)
            if thread and thread.is_alive():
                print(f"正在停止{thread_info['name']}嗅探...")
                thread.join(timeout=2)

    def stop(self):
        """停止监控"""
        self.network_running = False
        self._stop_threads()
        
        # 保存DNS缓存到文件
        self.save_dns_cache()
        
        print("监控已停止")
        if self.enable_file_output:
            print(f"日志文件已保存在: {self.output_dir}/")
        
        # 显示统计信息
        self._print_statistics()
    
    def _print_statistics(self):
        """显示统计信息"""
        stats = [
            {'name': 'TCP', 'condition': True, 'packet_count': self.tcp_packet_count, 'connections': len(self.tcp_connections)},
            {'name': 'UDP', 'condition': self.enable_udp_sniff, 'packet_count': self.udp_packet_count, 'connections': len(self.udp_connections)},
            {'name': 'DNS', 'condition': self.enable_dns_sniff, 'packet_count': self.dns_packet_count, 'connections': len(self.dns_cache)},
            {'name': 'ICMP', 'condition': self.config.capture_icmp, 'packet_count': self.icmp_packet_count, 'connections': len(self.icmp_connections)}
        ]
        
        for stat in stats:
            if stat['condition']:
                if stat['name'] == 'DNS':
                    print(f"{stat['name']}数据包处理总数: {stat['packet_count']}")
                    print(f"{stat['name']}缓存记录数: {stat['connections']}")
                else:
                    print(f"{stat['name']}数据包处理总数: {stat['packet_count']}")
                    print(f"{stat['name']}连接发现数: {stat['connections']}")
        
        print(f"五元组去重记录数: {len(self.five_tuple_timestamps)}")
    
    def update_config(self, new_config: dict):
        """更新配置"""
        for key, value in new_config.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
        print("配置已更新")
    
    def get_config(self) -> dict:
        """获取当前配置"""
        return self.config.to_dict()
    
    def save_config_to_file(self, filename: str = "network_monitor_config.json"):
        """保存配置到文件"""
        self.config.save_to_file(filename)
    
    def load_config_from_file(self, filename: str = "network_monitor_config.json"):
        """从文件加载配置"""
        self.config = MonitorConfig.load_from_file(filename)
        # 更新相关属性
        self.check_interval = self.config.check_interval
        self.enable_file_output = self.config.enable_file_output
        self.enable_dns_sniff = self.config.enable_dns_sniff
        self.enable_udp_sniff = self.config.enable_udp_sniff
    
    def clear_dns_cache(self):
        """清空DNS缓存"""
        with self.dns_lock:
            self.dns_cache.clear()
            self.dns_cache_timestamps.clear()
        print("DNS缓存已清空")
    
    def get_dns_cache_stats(self) -> dict:
        """获取DNS缓存统计信息"""
        with self.dns_lock:
            return {
                'total_entries': len(self.dns_cache),
                'max_size': self.config.max_dns_cache_size,
                'timeout': self.config.dns_cache_timeout
            }


def main():
    """主函数"""
    print("网络连接监控器 + DNS嗅探器（TCP和UDP）")
    print("=" * 60)
    
    print("注意: DNS嗅探和UDP监控功能需要管理员权限")
    print("Windows用户需要安装Npcap驱动程序")
    print()
    
    config = MonitorConfig.load_from_file()
    config.check_interval = 0.5  # 0.5秒检查一次
    monitor = NetworkConnectionMonitor(config)
    
    config_dict = monitor.get_config()
    print("当前配置:")
    for key, value in config_dict.items():
        print(f"  {key}: {value}")
    print()
    # 开始监控
    monitor.monitor()


if __name__ == "__main__":
    main()