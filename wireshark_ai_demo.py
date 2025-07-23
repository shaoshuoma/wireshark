#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wireshark AI分析演示脚本
使用自编译的TShark和AI技术分析网络流量
"""

import os
import sys
import subprocess
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

# 配置matplotlib中文显示
plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

class WiresharkAI:
    def __init__(self, tshark_path=None):
        """初始化Wireshark AI分析器"""
        if tshark_path is None:
            # 自动检测TShark路径
            possible_paths = [
                Path("build-msys2/run/tshark.exe"),
                Path("build/run/tshark.exe"),
                Path("C:/Program Files/Wireshark/tshark.exe")
            ]
            
            for path in possible_paths:
                if path.exists():
                    self.tshark_path = str(path.absolute())
                    break
            else:
                raise FileNotFoundError("未找到TShark可执行文件")
        else:
            self.tshark_path = tshark_path
            
        print(f"🔧 使用TShark路径: {self.tshark_path}")
        
    def extract_packet_features(self, pcap_file, max_packets=1000):
        """使用TShark提取数据包特征"""
        print(f"📊 从 {pcap_file} 提取数据包特征...")
        
        # 确保使用绝对路径
        pcap_file_abs = Path(pcap_file).resolve()
        
        # TShark命令：提取关键字段为JSON格式
        cmd = [
            self.tshark_path,
            "-r", str(pcap_file_abs),  # 使用绝对路径
            "-T", "json",
            "-c", str(max_packets),  # 限制包数量
            "-e", "frame.number",
            "-e", "frame.time_epoch", 
            "-e", "frame.len",
            "-e", "ip.src",
            "-e", "ip.dst", 
            "-e", "ip.proto",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.flags",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
            "-e", "icmp.type",
            "-e", "http.request.method",
            "-e", "dns.qry.name"
        ]
        
        try:
            # 设置环境变量，确保依赖库能被找到
            env = os.environ.copy()
            
            # 重要：添加MSYS2路径到环境变量前面
            msys2_bin_path = "C:\\msys64\\ucrt64\\bin"
            tshark_dir = str(Path(self.tshark_path).parent)
            
            # 构建新的PATH：MSYS2路径 + TShark目录 + 原有PATH
            new_path = msys2_bin_path + os.pathsep + tshark_dir + os.pathsep + env.get('PATH', '')
            env['PATH'] = new_path
            
            print(f"🔧 设置环境PATH: {new_path[:100]}...")
            
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=60, env=env, cwd=Path(self.tshark_path).parent)
            
            if result.returncode != 0:
                print(f"❌ TShark执行失败: {result.stderr}")
                return None
                
            if not result.stdout.strip():
                print("❌ TShark未返回数据")
                return None
                
            # 解析JSON输出
            packets_data = json.loads(result.stdout)
            print(f"✅ 成功提取 {len(packets_data)} 个数据包")
            
            return self._process_packets(packets_data)
            
        except subprocess.TimeoutExpired:
            print("❌ TShark执行超时")
            return None
        except json.JSONDecodeError as e:
            print(f"❌ JSON解析失败: {e}")
            print("TShark输出:", result.stdout[:500])
            return None
        except Exception as e:
            print(f"❌ 数据提取失败: {e}")
            return None
    
    def _process_packets(self, packets_data):
        """处理原始数据包数据"""
        from datetime import datetime
        
        processed_packets = []
        
        for packet in packets_data:
            layers = packet.get('_source', {}).get('layers', {})
            
            # 提取基本信息
            frame = layers.get('frame', {})
            
            # 解析时间戳（从ISO 8601格式转换为epoch）
            timestamp = 0
            time_str = frame.get('frame.time_epoch', '')
            if time_str and isinstance(time_str, str):
                try:
                    # TShark的time_epoch实际上是ISO 8601格式
                    dt = datetime.fromisoformat(time_str.replace('Z', '+00:00'))
                    timestamp = dt.timestamp()
                except:
                    # 如果解析失败，尝试相对时间
                    try:
                        timestamp = float(frame.get('frame.time_relative', '0'))
                    except:
                        timestamp = 0
            
            # 使用-e参数时，字段值是数组格式，需要提取第一个元素
            def get_field_value(layer_dict, field_name, default=''):
                """从TShark字段中提取值（处理数组格式）"""
                value = layer_dict.get(field_name, [default])
                if isinstance(value, list) and len(value) > 0:
                    return value[0]
                return value if value else default
            
            packet_info = {
                'frame_number': int(get_field_value(layers, 'frame.number', '0')),
                'timestamp': timestamp,
                'length': int(get_field_value(layers, 'frame.len', '0')),
                'protocol': 'Unknown',
                'src_ip': get_field_value(layers, 'ip.src', ''),
                'dst_ip': get_field_value(layers, 'ip.dst', ''),
                'src_port': 0,
                'dst_port': 0,
                'tcp_flags': '',
                'http_method': '',
                'dns_query': ''
            }
            
            # 解析时间戳字段（数组格式）
            time_epoch_value = get_field_value(layers, 'frame.time_epoch', '0')
            if time_epoch_value and time_epoch_value != '0':
                try:
                    # TShark的time_epoch是Unix时间戳（浮点数）
                    packet_info['timestamp'] = float(time_epoch_value)
                except:
                    packet_info['timestamp'] = 0
            
            # 协议判断
            proto_num = get_field_value(layers, 'ip.proto', '0')
            if proto_num and proto_num != '0':
                packet_info['protocol'] = self._get_protocol_name(proto_num)
            
            # TCP信息
            tcp_src = get_field_value(layers, 'tcp.srcport', '0')
            tcp_dst = get_field_value(layers, 'tcp.dstport', '0')
            if tcp_src != '0' or tcp_dst != '0':
                packet_info['src_port'] = int(tcp_src) if tcp_src != '0' else 0
                packet_info['dst_port'] = int(tcp_dst) if tcp_dst != '0' else 0
                packet_info['tcp_flags'] = get_field_value(layers, 'tcp.flags', '')
                packet_info['protocol'] = 'TCP'
            
            # UDP信息
            udp_src = get_field_value(layers, 'udp.srcport', '0')
            udp_dst = get_field_value(layers, 'udp.dstport', '0')
            if udp_src != '0' or udp_dst != '0':
                packet_info['src_port'] = int(udp_src) if udp_src != '0' else 0
                packet_info['dst_port'] = int(udp_dst) if udp_dst != '0' else 0
                packet_info['protocol'] = 'UDP'
            
            # HTTP信息
            http_method = get_field_value(layers, 'http.request.method', '')
            if http_method:
                packet_info['http_method'] = http_method
            
            # DNS信息
            dns_query = get_field_value(layers, 'dns.qry.name', '')
            if dns_query:
                packet_info['dns_query'] = dns_query
            
            # ICMP信息
            icmp_type = get_field_value(layers, 'icmp.type', '')
            if icmp_type:
                packet_info['protocol'] = 'ICMP'
            
            processed_packets.append(packet_info)
        
        return pd.DataFrame(processed_packets)
    
    def _get_protocol_name(self, proto_num):
        """根据协议号获取协议名称"""
        protocol_map = {
            1: 'ICMP',
            6: 'TCP', 
            17: 'UDP',
            2: 'IGMP',
            89: 'OSPF'
        }
        return protocol_map.get(int(proto_num) if proto_num else 0, f'Protocol_{proto_num}')
    
    def analyze_traffic_patterns(self, df):
        """分析流量模式"""
        print("\n🔍 流量模式分析:")
        
        # 基本统计
        total_packets = len(df)
        total_bytes = df['length'].sum()
        time_span = df['timestamp'].max() - df['timestamp'].min()
        
        print(f"📈 总包数: {total_packets}")
        print(f"📊 总字节数: {total_bytes:,.0f} bytes ({total_bytes/1024/1024:.2f} MB)")
        print(f"⏱️ 时间跨度: {time_span:.2f} 秒")
        print(f"📉 平均包速率: {total_packets/time_span:.2f} packets/sec")
        
        # 协议分布
        protocol_counts = df['protocol'].value_counts()
        print(f"\n📋 协议分布:")
        for protocol, count in protocol_counts.head(10).items():
            percentage = (count / total_packets) * 100
            print(f"  {protocol}: {count} ({percentage:.1f}%)")
        
        # 端口分析
        port_analysis = self._analyze_ports(df)
        
        # 流量热点分析
        ip_analysis = self._analyze_ips(df)
        
        return {
            'basic_stats': {
                'total_packets': total_packets,
                'total_bytes': total_bytes,
                'time_span': time_span,
                'packet_rate': total_packets/time_span if time_span > 0 else 0
            },
            'protocol_distribution': protocol_counts.to_dict(),
            'port_analysis': port_analysis,
            'ip_analysis': ip_analysis
        }
    
    def _analyze_ports(self, df):
        """分析端口使用情况"""
        # 合并源端口和目标端口
        all_ports = pd.concat([
            df[df['src_port'] > 0]['src_port'],
            df[df['dst_port'] > 0]['dst_port']
        ])
        
        if len(all_ports) == 0:
            return {}
            
        port_counts = all_ports.value_counts()
        
        # 识别知名端口
        well_known_ports = {
            80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP',
            25: 'SMTP', 53: 'DNS', 110: 'POP3', 143: 'IMAP',
            993: 'IMAPS', 995: 'POP3S', 587: 'SMTP-TLS'
        }
        
        print(f"\n🔌 端口使用分析 (前10个):")
        for port, count in port_counts.head(10).items():
            service = well_known_ports.get(port, 'Unknown')
            percentage = (count / len(all_ports)) * 100
            print(f"  端口 {port} ({service}): {count} ({percentage:.1f}%)")
        
        return port_counts.head(20).to_dict()
    
    def _analyze_ips(self, df):
        """分析IP地址通信模式"""
        # 源IP分析
        src_ips = df[df['src_ip'] != '']['src_ip'].value_counts()
        dst_ips = df[df['dst_ip'] != '']['dst_ip'].value_counts()
        
        print(f"\n🌐 IP地址分析:")
        print("活跃源IP (前5个):")
        for ip, count in src_ips.head(5).items():
            print(f"  {ip}: {count} 个包")
        
        print("热门目标IP (前5个):")
        for ip, count in dst_ips.head(5).items():
            print(f"  {ip}: {count} 个包")
        
        return {
            'top_src_ips': src_ips.head(10).to_dict(),
            'top_dst_ips': dst_ips.head(10).to_dict()
        }
    
    def ai_anomaly_detection(self, df):
        """AI异常检测"""
        print("\n🤖 AI异常检测分析:")
        
        if len(df) < 10:
            print("❌ 数据包数量不足，无法进行异常检测")
            return None
        
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
            
            # 准备特征
            features = []
            
            # 数值特征
            numeric_features = ['length', 'src_port', 'dst_port']
            for feature in numeric_features:
                if feature in df.columns:
                    features.append(df[feature].fillna(0))
            
            # 时间间隔特征
            if 'timestamp' in df.columns and len(df) > 1:
                time_diffs = df['timestamp'].diff().fillna(0)
                features.append(time_diffs)
            
            if len(features) == 0:
                print("❌ 无可用特征进行异常检测")
                return None
            
            # 组合特征矩阵
            feature_matrix = np.column_stack(features)
            
            # 标准化
            scaler = StandardScaler()
            feature_matrix_scaled = scaler.fit_transform(feature_matrix)
            
            # 异常检测
            iso_forest = IsolationForest(contamination=0.1, random_state=42)
            anomaly_labels = iso_forest.fit_predict(feature_matrix_scaled)
            
            # 分析结果
            anomaly_count = np.sum(anomaly_labels == -1)
            normal_count = np.sum(anomaly_labels == 1)
            
            print(f"✅ 异常检测完成:")
            print(f"  正常包: {normal_count}")
            print(f"  异常包: {anomaly_count}")
            print(f"  异常率: {(anomaly_count/len(df)*100):.2f}%")
            
            # 分析异常包特征
            if anomaly_count > 0:
                anomaly_indices = np.where(anomaly_labels == -1)[0]
                anomaly_packets = df.iloc[anomaly_indices]
                
                print("\n🚨 异常包特征分析:")
                print(f"异常包大小统计: {anomaly_packets['length'].describe()}")
                
                if len(anomaly_packets['protocol'].value_counts()) > 0:
                    print("异常包协议分布:")
                    for protocol, count in anomaly_packets['protocol'].value_counts().head(5).items():
                        print(f"  {protocol}: {count}")
            
            return {
                'total_packets': len(df),
                'normal_count': normal_count,
                'anomaly_count': anomaly_count,
                'anomaly_rate': anomaly_count/len(df),
                'anomaly_indices': anomaly_indices.tolist() if anomaly_count > 0 else []
            }
            
        except Exception as e:
            print(f"❌ 异常检测失败: {e}")
            return None
    
    def create_visualizations(self, df, analysis_results):
        """创建数据可视化"""
        print("\n📊 生成数据可视化图表...")
        
        try:
            # 创建子图
            fig, axes = plt.subplots(2, 2, figsize=(15, 12))
            fig.suptitle('Wireshark 网络流量 AI 分析报告', fontsize=16, fontweight='bold')
            
            # 1. 协议分布饼图
            protocol_dist = analysis_results['protocol_distribution']
            if protocol_dist:
                protocols = list(protocol_dist.keys())[:6]  # 前6个协议
                counts = [protocol_dist[p] for p in protocols]
                
                axes[0, 0].pie(counts, labels=protocols, autopct='%1.1f%%', startangle=90)
                axes[0, 0].set_title('协议分布')
            
            # 2. 包大小分布直方图
            if 'length' in df.columns and df['length'].sum() > 0:
                axes[0, 1].hist(df['length'], bins=30, alpha=0.7, color='skyblue', edgecolor='black')
                axes[0, 1].set_title('数据包大小分布')
                axes[0, 1].set_xlabel('包大小 (bytes)')
                axes[0, 1].set_ylabel('频次')
            
            # 3. 时间序列流量图
            if 'timestamp' in df.columns and df['timestamp'].var() > 0:
                df_sorted = df.sort_values('timestamp')
                time_bins = pd.cut(df_sorted['timestamp'], bins=20)
                traffic_over_time = df_sorted.groupby(time_bins)['length'].sum()
                
                axes[1, 0].plot(range(len(traffic_over_time)), traffic_over_time.values, 
                               marker='o', linewidth=2, markersize=4)
                axes[1, 0].set_title('时间序列流量')
                axes[1, 0].set_xlabel('时间片段')
                axes[1, 0].set_ylabel('流量 (bytes)')
                axes[1, 0].grid(True, alpha=0.3)
            
            # 4. 端口使用热力图
            port_data = analysis_results.get('port_analysis', {})
            if port_data:
                top_ports = list(port_data.keys())[:10]
                port_counts = [port_data[p] for p in top_ports]
                
                y_pos = np.arange(len(top_ports))
                bars = axes[1, 1].barh(y_pos, port_counts, color='lightcoral')
                axes[1, 1].set_yticks(y_pos)
                axes[1, 1].set_yticklabels([f'Port {p}' for p in top_ports])
                axes[1, 1].set_title('热门端口使用')
                axes[1, 1].set_xlabel('使用次数')
                
                # 添加数值标签
                for i, bar in enumerate(bars):
                    width = bar.get_width()
                    axes[1, 1].text(width + max(port_counts)*0.01, bar.get_y() + bar.get_height()/2,
                                   f'{int(width)}', ha='left', va='center', fontsize=8)
            
            plt.tight_layout()
            
            # 保存图表
            output_file = 'wireshark_ai_analysis.png'
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            print(f"✅ 可视化图表已保存: {output_file}")
            
            # 显示图表（如果在交互环境中）
            try:
                plt.show()
            except:
                pass
                
        except Exception as e:
            print(f"❌ 可视化生成失败: {e}")

def main():
    """主函数"""
    print("=" * 60)
    print("🚀 Wireshark AI 网络流量分析演示")
    print("=" * 60)
    
    try:
        # 初始化分析器
        analyzer = WiresharkAI()
        
        # 查找demo数据文件
        demo_data_path = Path('demo_data')
        pcap_files = []
        
        if demo_data_path.exists():
            pcap_files = list(demo_data_path.glob('*.pcap')) + list(demo_data_path.glob('*.pcapng'))
            # 过滤掉空文件
            pcap_files = [f for f in pcap_files if f.stat().st_size > 0]
        
        if not pcap_files:
            print("❌ 未在demo_data文件夹中找到有效的pcap文件")
            return
        
        # 选择第一个有效文件进行分析
        pcap_file = pcap_files[0]
        print(f"📁 分析文件: {pcap_file} ({pcap_file.stat().st_size} bytes)")
        
        # 提取数据包特征
        df = analyzer.extract_packet_features(pcap_file, max_packets=500)
        
        if df is None or len(df) == 0:
            print("❌ 数据提取失败")
            return
        
        print(f"\n📋 数据框概览:")
        print(f"数据形状: {df.shape}")
        print(f"列名: {list(df.columns)}")
        print(f"前5行预览:")
        print(df.head())
        
        # 流量模式分析
        analysis_results = analyzer.analyze_traffic_patterns(df)
        
        # AI异常检测
        anomaly_results = analyzer.ai_anomaly_detection(df)
        if anomaly_results:
            analysis_results['anomaly_detection'] = anomaly_results
        
        # 生成可视化
        analyzer.create_visualizations(df, analysis_results)
        
        # 保存分析结果
        results_file = 'analysis_results.json'
        with open(results_file, 'w', encoding='utf-8') as f:
            # 转换numpy类型为Python基本类型以便JSON序列化
            def convert_numpy(obj):
                if isinstance(obj, np.integer):
                    return int(obj)
                elif isinstance(obj, np.floating):
                    return float(obj)
                elif isinstance(obj, np.ndarray):
                    return obj.tolist()
                return obj
            
            # 递归转换字典中的numpy类型
            def clean_for_json(data):
                if isinstance(data, dict):
                    return {k: clean_for_json(v) for k, v in data.items()}
                elif isinstance(data, list):
                    return [clean_for_json(item) for item in data]
                else:
                    return convert_numpy(data)
            
            clean_results = clean_for_json(analysis_results)
            json.dump(clean_results, f, ensure_ascii=False, indent=2)
        
        print(f"\n✅ 分析完成！结果已保存到 {results_file}")
        print("\n🎉 Wireshark AI分析演示成功完成！")
        print("📊 您可以查看生成的图表和分析结果文件")
        
    except Exception as e:
        print(f"❌ 分析过程出错: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 