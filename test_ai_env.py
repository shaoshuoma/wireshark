#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wireshark AI环境测试脚本
测试Python虚拟环境与TShark的集成以及AI分析功能
"""

import os
import sys
import subprocess
import json
from pathlib import Path

def test_environment():
    """测试Python环境和依赖库"""
    print("🔍 测试Python环境...")
    print(f"Python版本: {sys.version}")
    print(f"虚拟环境: {sys.prefix}")
    
    try:
        import pandas as pd
        import numpy as np
        import sklearn
        import matplotlib.pyplot as plt
        import seaborn as sns
        import pyshark
        
        print("✅ 所有AI分析库可用:")
        print(f"  - pandas: {pd.__version__}")
        print(f"  - numpy: {np.__version__}")
        print(f"  - scikit-learn: {sklearn.__version__}")
        print(f"  - matplotlib: {plt.matplotlib.__version__}")
        print(f"  - seaborn: {sns.__version__}")
        try:
            print(f"  - pyshark: {pyshark.__version__}")
        except AttributeError:
            print(f"  - pyshark: 已安装 (版本号不可用)")
        
        return True
    except ImportError as e:
        print(f"❌ 库导入失败: {e}")
        return False

def test_tshark_integration():
    """测试TShark集成"""
    print("\n🔍 测试TShark集成...")
    
    # 可能的TShark路径
    possible_paths = [
        Path("build-msys2/run/tshark.exe"),
        Path("build/run/tshark.exe"), 
        Path("tshark.exe"),
        Path("C:/Program Files/Wireshark/tshark.exe")
    ]
    
    tshark_path = None
    for path in possible_paths:
        if path.exists():
            tshark_path = path
            break
    
    if not tshark_path:
        print("❌ TShark未找到，尝试的路径:")
        for path in possible_paths:
            print(f"  - {path}")
        print("请确保Wireshark编译成功或已安装")
        return False
    
    print(f"✅ 找到TShark: {tshark_path}")
    
    try:
        # 测试TShark版本
        result = subprocess.run([str(tshark_path), "--version"], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0]
            print(f"✅ TShark可用: {version_line}")
            
            # 测试接口列表
            result = subprocess.run([str(tshark_path), "-D"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                interfaces = result.stdout.strip().split('\n')
                print(f"✅ 检测到 {len(interfaces)} 个网络接口")
                for interface in interfaces[:3]:  # 显示前3个接口
                    print(f"  - {interface}")
                if len(interfaces) > 3:
                    print(f"  - ... 共{len(interfaces)}个接口")
                return True
            else:
                print(f"❌ 接口检测失败: {result.stderr}")
                return False
        else:
            print(f"❌ TShark版本检测失败: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ TShark调用超时")
        return False
    except Exception as e:
        print(f"❌ TShark测试异常: {e}")
        return False

def test_ai_analysis():
    """测试AI分析功能"""
    print("\n🔍 测试AI分析功能...")
    
    try:
        import pandas as pd
        import numpy as np
        from sklearn.cluster import KMeans
        import matplotlib.pyplot as plt
        
        # 生成模拟网络流量数据
        print("📊 生成模拟网络流量数据...")
        np.random.seed(42)
        n_packets = 1000
        
        # 模拟数据包特征
        data = {
            'packet_size': np.random.lognormal(6, 1, n_packets),
            'inter_arrival_time': np.random.exponential(0.1, n_packets),
            'port': np.random.choice([80, 443, 22, 53, 25], n_packets),
            'protocol': np.random.choice(['TCP', 'UDP', 'ICMP'], n_packets)
        }
        
        df = pd.DataFrame(data)
        print(f"✅ 生成 {len(df)} 个数据包记录")
        print(f"数据概览:")
        print(df.describe())
        
        # 简单的流量分类分析
        print("\n🤖 执行AI流量分类...")
        features = df[['packet_size', 'inter_arrival_time']].values
        
        # K-means聚类
        kmeans = KMeans(n_clusters=3, random_state=42, n_init=10)
        clusters = kmeans.fit_predict(features)
        
        df['cluster'] = clusters
        
        # 分析结果
        cluster_summary = df.groupby('cluster').agg({
            'packet_size': ['mean', 'std'],
            'inter_arrival_time': ['mean', 'std'],
            'port': lambda x: x.mode().iloc[0] if not x.mode().empty else 'N/A'
        }).round(3)
        
        print("✅ 流量聚类分析完成:")
        print(cluster_summary)
        
        return True
        
    except Exception as e:
        print(f"❌ AI分析测试失败: {e}")
        return False

def test_pyshark_integration():
    """测试PyShark集成（使用demo_data文件夹中的样本文件）"""
    print("\n🔍 测试PyShark集成...")
    
    try:
        import pyshark
        
        # 检查demo_data文件夹中的样本pcap文件
        demo_data_path = Path('demo_data')
        sample_files = []
        
        if demo_data_path.exists():
            sample_files = list(demo_data_path.glob('*.pcap')) + list(demo_data_path.glob('*.pcapng'))
        
        # 也检查当前目录
        sample_files.extend(list(Path('.').glob('*.pcap')) + list(Path('.').glob('*.pcapng')))
        
        # 过滤掉空文件
        valid_files = [f for f in sample_files if f.stat().st_size > 0]
        
        if valid_files:
            sample_file = valid_files[0]
            print(f"📁 发现样本文件: {sample_file} ({sample_file.stat().st_size} 字节)")
            
            try:
                # 使用PyShark读取文件
                cap = pyshark.FileCapture(str(sample_file))
                
                packet_count = 0
                protocols = set()
                
                for packet in cap:
                    packet_count += 1
                    # 收集协议信息
                    if hasattr(packet, 'highest_layer'):
                        protocols.add(packet.highest_layer)
                    
                    if packet_count >= 10:  # 处理前10个包
                        break
                
                cap.close()
                print(f"✅ PyShark成功读取 {packet_count} 个数据包")
                if protocols:
                    print(f"📊 检测到的协议: {', '.join(sorted(protocols))}")
                
                return True
                
            except Exception as e:
                print(f"⚠️  PyShark读取失败: {e}")
                # 尝试使用TShark作为备选
                print("📋 尝试获取文件基本信息...")
                try:
                    result = subprocess.run(['file', str(sample_file)], capture_output=True, text=True)
                    if result.returncode == 0:
                        print(f"文件类型: {result.stdout.strip()}")
                except:
                    pass
                return False
        else:
            print("⚠️  未发现有效的样本pcap文件")
            print(f"检查路径: {demo_data_path}")
            if demo_data_path.exists():
                files = list(demo_data_path.glob('*'))
                print(f"demo_data文件夹内容: {[f.name for f in files]}")
            print("✅ PyShark库导入正常")
            return True
            
    except Exception as e:
        print(f"❌ PyShark测试失败: {e}")
        return False

def main():
    """主测试函数"""
    print("=" * 60)
    print("🚀 Wireshark AI环境集成测试")
    print("=" * 60)
    
    tests = [
        ("Python环境", test_environment),
        ("TShark集成", test_tshark_integration),
        ("AI分析功能", test_ai_analysis),
        ("PyShark集成", test_pyshark_integration)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name}测试异常: {e}")
            results.append((test_name, False))
    
    # 总结
    print("\n" + "=" * 60)
    print("📋 测试结果总结:")
    print("=" * 60)
    
    passed = 0
    for test_name, result in results:
        status = "✅ 通过" if result else "❌ 失败"
        print(f"{test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\n总体结果: {passed}/{len(results)} 项测试通过")
    
    if passed == len(results):
        print("\n🎉 恭喜！Wireshark AI环境配置完成，可以开始二次开发！")
        print("\n🔧 后续开发建议:")
        print("1. 使用TShark导出数据为JSON/CSV格式进行Python分析")
        print("2. 利用PyShark进行实时数据包捕获和分析")
        print("3. 结合pandas和scikit-learn构建AI分析模型")
        print("4. 使用matplotlib/seaborn进行数据可视化")
    else:
        print(f"\n⚠️  还有 {len(results) - passed} 项测试需要解决")
        print("请检查相关配置和依赖")

if __name__ == "__main__":
    main() 