#!/bin/bash

# 生成证书和密钥的脚本
# 用于go-mitmproxy的HTTPS拦截

echo "正在生成证书和密钥..."

# 生成私钥 (key.pem)
openssl genrsa -out key.pem 2048

# 生成自签名证书 (cert.pem)
openssl req -new -x509 -key key.pem -out cert.pem -days 3650 -subj "/CN=go-mitmproxy CA"

# 设置适当的权限
chmod 600 key.pem
chmod 644 cert.pem

echo "证书和密钥生成完成！"
echo "文件位置:"
echo "  私钥: $(pwd)/key.pem"
echo "  证书: $(pwd)/cert.pem"
echo ""
echo "使用说明:"
echo "1. 将 cert.pem 安装到您的浏览器或系统的受信任根证书颁发机构中"
echo "2. 确保 go-mitmproxy 配置使用这些证书"
