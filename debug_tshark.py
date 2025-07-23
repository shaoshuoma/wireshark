#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
调试TShark输出格式
"""

import os
import subprocess
import json
from pathlib import Path

def debug_tshark_output():
    """调试TShark的JSON输出"""
    tshark_path = "build-msys2/run/tshark.exe"
    pcap_file = "demo_data/0718.pcapng"
    
    # 设置环境变量
    env = os.environ.copy()
    msys2_bin_path = "C:\\msys64\\ucrt64\\bin"
    tshark_dir = str(Path(tshark_path).parent)
    new_path = msys2_bin_path + os.pathsep + tshark_dir + os.pathsep + env.get('PATH', '')
    env['PATH'] = new_path
    
    pcap_file_abs = Path(pcap_file).resolve()
    
    # 简化的TShark命令，只读取前3个包
    cmd = [
        tshark_path,
        "-r", str(pcap_file_abs),
        "-T", "json",
        "-c", "3"  # 只读3个包用于调试
    ]
    
    print(f"🔍 调试TShark输出...")
    print(f"命令: {' '.join(cmd)}")
    print(f"文件: {pcap_file_abs}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, 
                              timeout=30, env=env, cwd=Path(tshark_path).parent)
        
        if result.returncode != 0:
            print(f"❌ TShark执行失败: {result.stderr}")
            return
        
        print(f"✅ TShark执行成功")
        print(f"📊 输出长度: {len(result.stdout)} 字符")
        
        # 保存原始输出
        with open('tshark_raw_output.json', 'w', encoding='utf-8') as f:
            f.write(result.stdout)
        
        # 显示前1000个字符
        print(f"\n📋 原始输出预览 (前1000字符):")
        print("=" * 50)
        print(result.stdout[:1000])
        print("=" * 50)
        
        # 尝试解析JSON
        try:
            data = json.loads(result.stdout)
            print(f"\n✅ JSON解析成功")
            print(f"📊 数据类型: {type(data)}")
            print(f"📊 数据长度: {len(data) if isinstance(data, list) else 'N/A'}")
            
            if isinstance(data, list) and len(data) > 0:
                first_packet = data[0]
                print(f"\n📋 第一个数据包结构:")
                print(json.dumps(first_packet, indent=2, ensure_ascii=False)[:2000])
                
                # 分析层次结构
                if '_source' in first_packet:
                    source = first_packet['_source']
                    print(f"\n📊 _source 键: {source.keys()}")
                    
                    if 'layers' in source:
                        layers = source['layers']
                        print(f"📊 layers 键: {layers.keys()}")
                        
                        # 检查每一层
                        for layer_name, layer_data in layers.items():
                            print(f"  层 {layer_name}: {type(layer_data)}")
                            if isinstance(layer_data, dict):
                                sample_keys = list(layer_data.keys())[:5]
                                print(f"    样本键: {sample_keys}")
                
        except json.JSONDecodeError as e:
            print(f"❌ JSON解析失败: {e}")
            print("可能不是有效的JSON格式")
            
    except Exception as e:
        print(f"❌ 调试失败: {e}")

if __name__ == "__main__":
    debug_tshark_output() 