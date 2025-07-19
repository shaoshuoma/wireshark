# Wireshark 自编译构建指南

## 🎉 构建成功！

恭喜！您已成功从源代码编译了Wireshark 4.5.0版本，可以进行二次开发了。

## 📁 项目结构

```
D:\mss\wireshark\
├── epan/                    # 核心包分析引擎
│   ├── dissectors/          # 协议解析器 (1800+协议)
│   ├── dfilter/            # 显示过滤器引擎
│   └── wslua/              # Lua脚本支持
├── ui/qt/                  # Qt图形界面
├── tools/                  # 开发工具
├── build-msys2/            # 编译构建目录
│   └── run/                # 可执行文件目录
└── 启动脚本/
    ├── run-wireshark.bat   # GUI版本启动
    ├── run-tshark.bat      # 命令行版本启动
    └── dev-setup.bat       # 开发环境设置
```

## 🚀 快速启动

### 启动图形界面版本
```bash
# 双击运行
run-wireshark.bat

# 或者手动启动
cd D:\mss\wireshark\build-msys2\run
wireshark.exe
```

### 启动命令行版本
```bash
# 双击运行
run-tshark.bat

# 或者手动启动
cd D:\mss\wireshark\build-msys2\run
tshark.exe --version
```

### 进入开发环境
```bash
# 双击运行
dev-setup.bat
```

## 🛠️ 编译环境信息

- **编译器**: GCC 15.1.0 (MSYS2/MinGW-w64)
- **构建系统**: CMake + Ninja
- **GUI框架**: Qt 6.9.1
- **操作系统**: Windows 11 64位
- **编译时间**: 约15-20分钟 (首次编译)

## 📦 编译生成的程序

| 程序 | 大小 | 描述 |
|------|------|------|
| `wireshark.exe` | ~303MB | 主要的图形界面程序 |
| `tshark.exe` | ~2.6MB | 命令行版本 |
| `dumpcap.exe` | ~2.1MB | 包捕获工具 |
| `capinfos.exe` | ~695KB | 捕获文件信息工具 |
| `editcap.exe` | ~920KB | 捕获文件编辑工具 |
| `mergecap.exe` | ~621KB | 捕获文件合并工具 |

## 🔧 二次开发指南

### 重新编译
```bash
cd D:\mss\wireshark\build-msys2
ninja                    # 增量编译
ninja clean && ninja     # 完全重新编译
```

### 修改源代码后编译
1. 修改源代码文件 (如 `epan/dissectors/packet-*.c`)
2. 运行 `cd build-msys2 && ninja`
3. 测试新编译的程序

### 添加新的协议解析器
1. 在 `epan/dissectors/` 目录创建新的 `packet-yourprotocol.c`
2. 参考现有解析器的模式
3. 重新编译并测试

### 修改UI界面
1. 修改 `ui/qt/` 目录下的文件
2. `.ui` 文件：界面布局
3. `.cpp/.h` 文件：逻辑代码
4. 重新编译

## 🧪 测试和调试

### 基本测试
```bash
# 检查程序版本
wireshark.exe --version
tshark.exe --version

# 列出网络接口
tshark.exe -D

# 捕获少量包进行测试
tshark.exe -i 1 -c 5
```

### 调试
- 使用 `gdb` 调试: `gdb wireshark.exe`
- 启用调试符号 (已配置 RelWithDebInfo)
- 查看日志输出

## 📚 有用的开发资源

### Wireshark官方文档
- [开发者指南](https://www.wireshark.org/docs/wsdg_html_chunked/)
- [用户指南](https://www.wireshark.org/docs/wsug_html_chunked/)
- [协议解析器开发](https://wiki.wireshark.org/Development/DissectorDevelopment)

### 源代码关键目录
- `epan/dissectors/` - 协议解析器
- `ui/qt/` - Qt图形界面
- `tools/` - 开发工具和脚本
- `doc/` - 文档源文件

## ⚠️ 注意事项

1. **依赖环境**: 需要MSYS2环境，确保 `C:\msys64\ucrt64\bin` 在PATH中
2. **增量编译**: 只修改少量文件时使用 `ninja` 即可，无需完全重新编译
3. **内存需求**: 编译过程可能需要8GB+内存
4. **磁盘空间**: 完整编译需要约2GB磁盘空间

## 🆘 常见问题

### Q: 编译失败怎么办？
A: 检查依赖是否完整安装，清理构建目录后重试：
```bash
cd build-msys2
rm -rf *
cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
ninja
```

### Q: 程序启动失败？
A: 确保MSYS2路径在环境变量中，或使用提供的启动脚本。

### Q: 如何更新源代码？
A: 使用git拉取最新代码后重新编译：
```bash
git pull origin master
cd build-msys2
ninja
```

---

**祝您开发愉快！** 🎉

如有问题，可参考 [Wireshark开发者邮件列表](https://www.wireshark.org/lists/) 或官方文档。 