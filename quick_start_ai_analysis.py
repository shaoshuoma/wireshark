#!/usr/bin/env python3
"""
Wireshark + Python AI 快速开始脚本
立即测试Python与Wireshark的集成
"""

import subprocess
import sys
import os
import json
from pathlib import Path

def check_dependencies():
    """检查必要的依赖"""
    print("🔍 检查环境依赖...")
    
    # 检查TShark
    tshark_path = "./build-msys2/run/tshark.exe"
    if not os.path.exists(tshark_path):
        print(f"❌ 找不到TShark: {tshark_path}")
        print("   请确保Wireshark已成功编译")
        return False
    else:
        print(f"✅ TShark找到: {tshark_path}")
    
    # 检查Python包
    required_packages = ['pandas', 'numpy']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package} 已安装")
        except ImportError:
            missing_packages.append(package)
            print(f"❌ {package} 未安装")
    
    if missing_packages:
        print(f"\n请安装缺失的包: pip install {' '.join(missing_packages)}")
        return False
    
    return True

def test_tshark_integration():
    """测试TShark基本功能"""
    print("\n🧪 测试TShark集成...")
    
    tshark_path = "./build-msys2/run/tshark.exe"
    
    # 测试版本信息
    try:
        result = subprocess.run([tshark_path, "--version"], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            version_info = result.stdout.split('\n')[0]
            print(f"✅ TShark版本: {version_info}")
            return True
        else:
            print(f"❌ TShark执行失败: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("❌ TShark响应超时")
        return False
    except Exception as e:
        print(f"❌ TShark测试出错: {e}")
        return False

def list_network_interfaces():
    """列出可用的网络接口"""
    print("\n🌐 获取网络接口列表...")
    
    tshark_path = "./build-msys2/run/tshark.exe"
    
    try:
        result = subprocess.run([tshark_path, "-D"], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            interfaces = result.stdout.strip().split('\n')
            print("📡 可用网络接口:")
            for interface in interfaces:
                print(f"   {interface}")
            return interfaces
        else:
            print(f"❌ 获取接口失败: {result.stderr}")
            return []
    except Exception as e:
        print(f"❌ 获取接口出错: {e}")
        return []

def create_sample_pcap():
    """创建一个样本pcap文件用于测试"""
    print("\n📦 创建测试数据...")
    
    # 使用dumpcap创建一个小的测试文件
    dumpcap_path = "./build-msys2/run/dumpcap.exe"
    test_file = "test_sample.pcap"
    
    if os.path.exists(dumpcap_path):
        try:
            print("🎯 捕获5秒钟的测试数据...")
            cmd = [
                dumpcap_path,
                "-i", "1",  # 使用第一个接口
                "-a", "duration:5",  # 5秒
                "-w", test_file
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if os.path.exists(test_file) and os.path.getsize(test_file) > 0:
                print(f"✅ 测试文件创建成功: {test_file}")
                return test_file
            else:
                print("❌ 测试文件创建失败或为空")
                return None
                
        except subprocess.TimeoutExpired:
            print("❌ 数据捕获超时")
            return None
        except Exception as e:
            print(f"❌ 捕获数据出错: {e}")
            return None
    else:
        print(f"❌ 找不到dumpcap: {dumpcap_path}")
        return None

def analyze_sample_data(pcap_file):
    """分析样本数据并展示Python集成"""
    print(f"\n🤖 分析数据文件: {pcap_file}")
    
    import pandas as pd
    import numpy as np
    
    tshark_path = "./build-msys2/run/tshark.exe"
    
    # 使用TShark提取基本统计信息
    try:
        # 获取包的基本信息
        cmd = [
            tshark_path,
            "-r", pcap_file,
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "frame.len", 
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "_ws.col.Protocol"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            print(f"❌ TShark分析失败: {result.stderr}")
            return
        
        # 解析数据
        lines = result.stdout.strip().split('\n')
        data = []
        
        for line in lines:
            if line.strip():
                fields = line.split('\t')
                if len(fields) >= 7:
                    try:
                        record = {
                            'timestamp': float(fields[0]) if fields[0] else 0,
                            'length': int(fields[1]) if fields[1] else 0,
                            'src_ip': fields[2] if fields[2] else 'Unknown',
                            'dst_ip': fields[3] if fields[3] else 'Unknown', 
                            'src_port': int(fields[4]) if fields[4] else 0,
                            'dst_port': int(fields[5]) if fields[5] else 0,
                            'protocol': fields[6] if fields[6] else 'Unknown'
                        }
                        data.append(record)
                    except (ValueError, IndexError):
                        continue
        
        if not data:
            print("❌ 没有有效的数据包被解析")
            return
        
        # 转换为DataFrame进行分析
        df = pd.DataFrame(data)
        
        print(f"📊 数据分析结果:")
        print(f"   总数据包数: {len(df)}")
        print(f"   数据包大小范围: {df['length'].min()} - {df['length'].max()} 字节")
        print(f"   平均包大小: {df['length'].mean():.2f} 字节")
        
        # 协议分布
        protocol_counts = df['protocol'].value_counts()
        print(f"   协议分布:")
        for protocol, count in protocol_counts.head(5).items():
            print(f"     {protocol}: {count} 包 ({count/len(df)*100:.1f}%)")
        
        # 流量最多的连接
        if 'src_ip' in df.columns and 'dst_ip' in df.columns:
            connections = df.groupby(['src_ip', 'dst_ip']).size()
            if len(connections) > 0:
                print(f"   主要连接:")
                for (src, dst), count in connections.head(3).items():
                    print(f"     {src} → {dst}: {count} 包")
        
        # 简单的AI分析示例
        print(f"\n🧠 AI分析示例:")
        
        # 异常大小检测
        mean_size = df['length'].mean()
        std_size = df['length'].std()
        threshold = mean_size + 2 * std_size
        large_packets = df[df['length'] > threshold]
        
        if len(large_packets) > 0:
            print(f"   🚨 检测到 {len(large_packets)} 个异常大包 (>{threshold:.0f} 字节)")
        else:
            print(f"   ✅ 未检测到异常大包")
        
        # 端口活动分析
        if 'dst_port' in df.columns:
            port_activity = df['dst_port'].value_counts()
            active_ports = port_activity[port_activity > 1]
            if len(active_ports) > 0:
                print(f"   📡 活跃端口 (>1个连接): {len(active_ports)} 个")
                for port, count in active_ports.head(3).items():
                    service = get_port_service(port)
                    print(f"     端口 {port} ({service}): {count} 连接")
        
        print(f"\n✅ Python + TShark 集成测试成功！")
        
    except subprocess.TimeoutExpired:
        print("❌ 数据分析超时")
    except Exception as e:
        print(f"❌ 分析出错: {e}")

def get_port_service(port):
    """根据端口号返回常见服务名"""
    services = {
        22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        993: "IMAPS", 995: "POP3S", 8080: "HTTP-Alt"
    }
    return services.get(port, "Unknown")

def demonstrate_real_time_analysis():
    """演示实时分析功能"""
    print("\n⚡ 实时分析演示 (10秒)...")
    print("这将展示如何实时处理网络流量...")
    
    tshark_path = "./build-msys2/run/tshark.exe"
    
    # 实时捕获10秒
    cmd = [
        tshark_path,
        "-i", "1",  # 第一个接口
        "-a", "duration:10",  # 10秒
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "_ws.col.Protocol"
    ]
    
    try:
        print("🎯 开始实时捕获...")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                 stderr=subprocess.PIPE, text=True)
        
        packet_count = 0
        total_bytes = 0
        protocols = {}
        
        for line in process.stdout:
            if line.strip():
                fields = line.strip().split('\t')
                if len(fields) >= 3:
                    try:
                        length = int(fields[1]) if fields[1] else 0
                        protocol = fields[2] if fields[2] else 'Unknown'
                        
                        packet_count += 1
                        total_bytes += length
                        protocols[protocol] = protocols.get(protocol, 0) + 1
                        
                        # 每100包输出一次状态
                        if packet_count % 100 == 0:
                            print(f"   📈 已处理: {packet_count} 包, {total_bytes} 字节")
                        
                    except (ValueError, IndexError):
                        continue
        
        process.wait()
        
        print(f"\n📊 实时分析结果:")
        print(f"   总包数: {packet_count}")
        print(f"   总流量: {total_bytes} 字节")
        print(f"   平均速率: {total_bytes/10:.1f} 字节/秒")
        
        if protocols:
            print(f"   协议分布:")
            for protocol, count in sorted(protocols.items(), 
                                        key=lambda x: x[1], reverse=True)[:5]:
                print(f"     {protocol}: {count} 包")
        
        print("✅ 实时分析演示完成！")
        
    except Exception as e:
        print(f"❌ 实时分析出错: {e}")

def main():
    """主函数"""
    print("🚀 Wireshark + Python AI 集成快速测试")
    print("=" * 50)
    
    # 1. 检查依赖
    if not check_dependencies():
        print("\n❌ 环境检查失败，请解决依赖问题后重试")
        return
    
    # 2. 测试TShark
    if not test_tshark_integration():
        print("\n❌ TShark集成测试失败")
        return
    
    # 3. 列出网络接口
    interfaces = list_network_interfaces()
    if not interfaces:
        print("\n⚠️  无法获取网络接口，跳过实时测试")
    
    # 4. 选择测试模式
    print("\n🎯 请选择测试模式:")
    print("1. 创建测试数据并分析")
    print("2. 分析现有pcap文件")
    print("3. 实时流量分析演示")
    print("4. 全部测试")
    
    try:
        choice = input("\n请输入选择 (1-4): ").strip()
        
        if choice == "1":
            # 创建并分析测试数据
            pcap_file = create_sample_pcap()
            if pcap_file:
                analyze_sample_data(pcap_file)
            
        elif choice == "2":
            # 分析用户指定的文件
            pcap_file = input("请输入pcap文件路径: ").strip()
            if os.path.exists(pcap_file):
                analyze_sample_data(pcap_file)
            else:
                print(f"❌ 文件不存在: {pcap_file}")
        
        elif choice == "3":
            # 实时分析
            if interfaces:
                demonstrate_real_time_analysis()
            else:
                print("❌ 没有可用的网络接口")
        
        elif choice == "4":
            # 全部测试
            print("\n🧪 执行完整测试...")
            
            # 测试1: 样本数据分析
            pcap_file = create_sample_pcap()
            if pcap_file:
                analyze_sample_data(pcap_file)
            
            # 测试2: 实时分析
            if interfaces:
                demonstrate_real_time_analysis()
            
        else:
            print("❌ 无效选择")
            
    except KeyboardInterrupt:
        print("\n\n👋 用户中断测试")
    except Exception as e:
        print(f"\n❌ 测试出错: {e}")
    
    print("\n" + "=" * 50)
    print("🎉 测试完成！")
    print("\n💡 下一步:")
    print("   1. 查看 PYTHON_AI_INTEGRATION_GUIDE.md 了解详细集成方案")
    print("   2. 运行 python_integration_examples.py 查看更多示例")
    print("   3. 开始开发您的AI数据包分析应用!")

if __name__ == "__main__":
    main() 