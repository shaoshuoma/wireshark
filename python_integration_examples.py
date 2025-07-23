#!/usr/bin/env python3
"""
Wireshark + Python AI分析集成示例
"""

import subprocess
import json
import pandas as pd
import numpy as np
from datetime import datetime
import socket
import struct

# =============================================================================
# 方案1：TShark JSON导出 + Python分析
# =============================================================================

def extract_packets_with_tshark(pcap_file, output_format="json"):
    """
    使用TShark提取数据包信息
    
    Args:
        pcap_file: pcap文件路径
        output_format: 输出格式 ("json", "csv", "fields")
    
    Returns:
        解析后的数据包信息
    """
    
    if output_format == "json":
        # 导出为JSON格式，包含完整的协议解析信息
        cmd = [
            "./build-msys2/run/tshark.exe",  # 你编译的tshark路径
            "-r", pcap_file,
            "-T", "json",
            "-e", "frame.time_epoch",
            "-e", "ip.src", 
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport", 
            "-e", "frame.len",
            "-e", "tcp.flags",
            "-e", "http.request.method",
            "-e", "dns.qry.name"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            raise Exception(f"TShark执行失败: {result.stderr}")
    
    elif output_format == "csv":
        # 导出为CSV格式，适合大数据集分析
        cmd = [
            "./build-msys2/run/tshark.exe",
            "-r", pcap_file,
            "-T", "fields",
            "-E", "header=y",
            "-E", "separator=,",
            "-e", "frame.time_epoch",
            "-e", "ip.src", 
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "frame.len",
            "-e", "tcp.flags.syn",
            "-e", "tcp.flags.ack",
            "-e", "tcp.flags.fin"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            # 转换为pandas DataFrame
            from io import StringIO
            return pd.read_csv(StringIO(result.stdout))
        else:
            raise Exception(f"TShark执行失败: {result.stderr}")

def ai_traffic_analysis(packet_data):
    """
    使用AI技术分析网络流量
    """
    # 转换为DataFrame便于分析
    if isinstance(packet_data, list):
        # JSON格式数据转换
        records = []
        for packet in packet_data:
            layers = packet.get("_source", {}).get("layers", {})
            record = {
                'timestamp': layers.get("frame.time_epoch", [None])[0],
                'src_ip': layers.get("ip.src", [None])[0],
                'dst_ip': layers.get("ip.dst", [None])[0],
                'src_port': layers.get("tcp.srcport", [None])[0],
                'dst_port': layers.get("tcp.dstport", [None])[0],
                'length': layers.get("frame.len", [None])[0],
                'tcp_flags': layers.get("tcp.flags", [None])[0]
            }
            records.append(record)
        df = pd.DataFrame(records)
    else:
        # 已经是DataFrame
        df = packet_data
    
    # AI分析示例
    analysis_results = {}
    
    # 1. 流量模式分析
    if 'length' in df.columns:
        df['length'] = pd.to_numeric(df['length'], errors='coerce')
        analysis_results['avg_packet_size'] = df['length'].mean()
        analysis_results['traffic_volume'] = df['length'].sum()
    
    # 2. 异常检测 (使用统计方法，可替换为ML模型)
    if 'length' in df.columns:
        mean_size = df['length'].mean()
        std_size = df['length'].std()
        threshold = mean_size + 3 * std_size
        anomalies = df[df['length'] > threshold]
        analysis_results['anomalous_packets'] = len(anomalies)
    
    # 3. 连接模式分析
    if 'src_ip' in df.columns and 'dst_ip' in df.columns:
        connections = df.groupby(['src_ip', 'dst_ip']).size()
        analysis_results['top_connections'] = connections.nlargest(10).to_dict()
    
    # 4. 端口扫描检测
    if 'src_ip' in df.columns and 'dst_port' in df.columns:
        port_attempts = df.groupby('src_ip')['dst_port'].nunique()
        scan_threshold = 10  # 访问超过10个不同端口视为扫描
        potential_scanners = port_attempts[port_attempts > scan_threshold]
        analysis_results['potential_port_scanners'] = potential_scanners.to_dict()
    
    return analysis_results

# =============================================================================
# 方案2：实时数据捕获 + Python分析
# =============================================================================

def real_time_capture_analysis(interface="1", duration=60):
    """
    实时捕获并分析网络流量
    
    Args:
        interface: 网络接口编号
        duration: 捕获时长(秒)
    """
    print(f"开始实时捕获网络流量，持续{duration}秒...")
    
    # 使用TShark进行实时捕获
    cmd = [
        "./build-msys2/run/tshark.exe",
        "-i", interface,
        "-a", f"duration:{duration}",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst", 
        "-e", "frame.len",
        "-e", "tcp.dstport"
    ]
    
    packet_count = 0
    suspicious_ips = set()
    
    # 实时处理数据流
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE, text=True)
    
    try:
        for line in process.stdout:
            if line.strip():
                fields = line.strip().split('\t')
                if len(fields) >= 4:
                    timestamp, src_ip, dst_ip, length = fields[:4]
                    packet_count += 1
                    
                    # 实时AI分析逻辑
                    if length and int(length) > 1500:  # 大包检测
                        print(f"检测到大包: {src_ip} -> {dst_ip}, 大小: {length}")
                    
                    # 每1000个包输出一次统计
                    if packet_count % 1000 == 0:
                        print(f"已处理 {packet_count} 个数据包")
                        
    except KeyboardInterrupt:
        print("用户中断捕获")
    finally:
        process.terminate()
        
    return {"total_packets": packet_count, "suspicious_ips": list(suspicious_ips)}

# =============================================================================
# 方案3：自定义Lua脚本 + Python后处理  
# =============================================================================

def generate_lua_extractor_script():
    """
    生成Lua脚本，用于从Wireshark中提取特定数据
    """
    lua_script = '''
-- custom_extractor.lua
-- 自定义数据提取脚本

-- 创建一个tap
local tap = Listener.new()

-- 输出文件
local output_file = io.open("extracted_data.json", "w")
local packet_count = 0

function tap.packet(pinfo, tvb)
    packet_count = packet_count + 1
    
    -- 提取需要的字段
    local packet_info = {
        number = pinfo.number,
        timestamp = tostring(pinfo.abs_ts),
        src = tostring(pinfo.src),
        dst = tostring(pinfo.dst),
        protocol = pinfo.cols.protocol,
        length = pinfo.len
    }
    
    -- 如果是TCP包，提取额外信息
    local tcp_info = pinfo.cols.info
    if tcp_info then
        packet_info.info = tcp_info
    end
    
    -- 写入JSON格式
    output_file:write(table.concat({
        '{"packet":', packet_count, 
        ',"data":', json_encode(packet_info), '}\\n'
    }))
    
    -- 每1000包刷新一次
    if packet_count % 1000 == 0 then
        output_file:flush()
        print("已处理", packet_count, "个数据包")
    end
end

function tap.draw()
    print("数据提取完成，共处理", packet_count, "个数据包")
    output_file:close()
end

-- 简单的JSON编码函数
function json_encode(obj)
    local json_str = "{"
    for k, v in pairs(obj) do
        json_str = json_str .. '"' .. k .. '":"' .. tostring(v) .. '",'
    end
    return json_str:sub(1, -2) .. "}"
end
'''
    
    with open("custom_extractor.lua", "w") as f:
        f.write(lua_script)
    
    print("Lua脚本已生成: custom_extractor.lua")
    print("使用方法: tshark -X lua_script:custom_extractor.lua -r your_file.pcap")

# =============================================================================
# 机器学习示例：流量分类
# =============================================================================

def ml_traffic_classification(packet_data):
    """
    使用机器学习进行流量分类示例
    """
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import LabelEncoder
    except ImportError:
        print("需要安装scikit-learn: pip install scikit-learn")
        return None
    
    # 特征工程
    df = pd.DataFrame(packet_data)
    
    # 构造特征
    features = []
    if 'length' in df.columns:
        features.append('length')
    if 'src_port' in df.columns:
        features.append('src_port') 
    if 'dst_port' in df.columns:
        features.append('dst_port')
    
    if len(features) < 2:
        print("特征不足，无法进行机器学习分析")
        return None
    
    # 创建标签（示例：基于端口分类）
    def classify_traffic(row):
        dst_port = row.get('dst_port', 0)
        if dst_port in [80, 8080, 443]:
            return 'web'
        elif dst_port in [22, 23]:
            return 'ssh_telnet'
        elif dst_port in [53]:
            return 'dns'
        else:
            return 'other'
    
    df['traffic_type'] = df.apply(classify_traffic, axis=1)
    
    # 准备训练数据
    X = df[features].fillna(0)
    y = df['traffic_type']
    
    # 训练模型
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2)
    
    clf = RandomForestClassifier(n_estimators=100)
    clf.fit(X_train, y_train)
    
    # 预测准确率
    accuracy = clf.score(X_test, y_test)
    
    return {
        'model': clf,
        'label_encoder': le,
        'accuracy': accuracy,
        'feature_importance': dict(zip(features, clf.feature_importances_))
    }

# =============================================================================
# 主函数示例
# =============================================================================

def main():
    """主函数示例"""
    print("=== Wireshark + Python AI分析示例 ===")
    
    # 示例1：分析pcap文件
    # packet_data = extract_packets_with_tshark("sample.pcap", "json")
    # analysis = ai_traffic_analysis(packet_data)
    # print("流量分析结果:", analysis)
    
    # 示例2：生成Lua提取脚本
    generate_lua_extractor_script()
    
    # 示例3：实时分析
    # real_time_capture_analysis(interface="1", duration=30)
    
    print("\n集成方案已准备就绪！")
    print("请根据你的需求选择合适的方案进行开发。")

if __name__ == "__main__":
    main() 