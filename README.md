# mDNS监控工具

这是一个使用Python和Flask框架开发的mDNS监控工具，主要用于发现和跟踪本地网络中的mDNS服务。

## 功能特性
- 实时监控网络中的mDNS服务
- 发现新加入的服务并显示详细信息
- 跟踪服务状态变化
- 简洁直观的Web界面展示

## 技术栈
- Python 3.x
- Flask web框架
- 标准库中的socket模块处理网络通信
- 使用内置的wsgiref.simple_server作为WSGI服务器

## 安装依赖
```bash
pip install -r requirements.txt
```

## 使用说明
1. 克隆仓库
2. 进入项目目录
3. 安装依赖
4. 运行`mdns_monitor.py`
5. 打开浏览器访问`http://localhost:5000`

## 目录结构
- `templates/` - HTML模板文件
- `mdns_monitor.py` - 主程序
- `README.md` - 本文件