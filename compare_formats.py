#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
对比TShark的两种JSON输出格式
"""

import os
import subprocess
import json
from pathlib import Path

def compare_tshark_formats():
    """对比TShark的JSON输出格式"""
    tshark_path = "build-msys2/run/tshark.exe"
    pcap_file = "demo_data/0718.pcapng"
    
    # 设置环境变量
    env = os.environ.copy()
    msys2_bin_path = "C:\\msys64\\ucrt64\\bin"
    tshark_dir = str(Path(tshark_path).parent)
    new_path = msys2_bin_path + os.pathsep + tshark_dir + os.pathsep + env.get('PATH', '')
    env['PATH'] = new_path
    
    pcap_file_abs = Path(pcap_file).resolve()
    
    print("=" * 60)
    print("🔍 对比TShark JSON输出格式")
    print("=" * 60)
    
    # 格式1：完整JSON（不使用-e参数）
    print("\n📋 格式1：完整JSON (无-e参数)")
    print("-" * 40)
    
    cmd1 = [
        tshark_path,
        "-r", str(pcap_file_abs),
        "-T", "json",
        "-c", "1"  # 只读1个包
    ]
    
    try:
        result1 = subprocess.run(cmd1, capture_output=True, text=True, 
                              timeout=30, env=env, cwd=Path(tshark_path).parent)
        
        if result1.returncode == 0:
            data1 = json.loads(result1.stdout)
            print(f"✅ 成功提取，数据类型: {type(data1)}")
            if isinstance(data1, list) and len(data1) > 0:
                packet = data1[0]
                print(f"第一层键: {list(packet.keys())}")
                if '_source' in packet:
                    source = packet['_source']
                    print(f"_source键: {list(source.keys())}")
                    if 'layers' in source:
                        layers = source['layers']
                        print(f"layers键: {list(layers.keys())}")
                        
                        # 显示frame层的详细信息
                        if 'frame' in layers:
                            frame = layers['frame']
                            print(f"frame字段示例: frame.number={frame.get('frame.number')}, frame.len={frame.get('frame.len')}")
        else:
            print(f"❌ 执行失败: {result1.stderr}")
            
    except Exception as e:
        print(f"❌ 格式1测试失败: {e}")
    
    # 格式2：字段JSON（使用-e参数）
    print("\n📋 格式2：字段JSON (使用-e参数)")
    print("-" * 40)
    
    cmd2 = [
        tshark_path,
        "-r", str(pcap_file_abs),
        "-T", "json",
        "-c", "1",  # 只读1个包
        "-e", "frame.number",
        "-e", "frame.time_epoch", 
        "-e", "frame.len",
        "-e", "ip.src",
        "-e", "ip.dst", 
        "-e", "tcp.srcport",
        "-e", "tcp.dstport"
    ]
    
    try:
        result2 = subprocess.run(cmd2, capture_output=True, text=True, 
                              timeout=30, env=env, cwd=Path(tshark_path).parent)
        
        if result2.returncode == 0:
            print("原始输出:")
            print(result2.stdout[:500])
            print("\n尝试解析JSON:")
            
            data2 = json.loads(result2.stdout)
            print(f"✅ 成功提取，数据类型: {type(data2)}")
            if isinstance(data2, list) and len(data2) > 0:
                packet = data2[0]
                print(f"数据包结构:")
                print(json.dumps(packet, indent=2, ensure_ascii=False))
        else:
            print(f"❌ 执行失败: {result2.stderr}")
            
    except Exception as e:
        print(f"❌ 格式2测试失败: {e}")
        
    print("\n" + "=" * 60)
    print("分析完成！")

if __name__ == "__main__":
    compare_tshark_formats() 