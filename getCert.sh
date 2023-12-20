#!/bin/bash
# windows 环境下无法运行sh文件，linux和mac使用sh指令就可
# 生成根证书私钥
openssl genrsa -out ./communication/config/ca.key 2048
# 生成根证书请求文件
openssl req -new -x509 -days 3650 -key ca.key -subj "/C=CN/ST=GD/L=SZ/O=Acme, Inc./CN=Acme Root CA" -out ./communication/config/ca.crt

openssl req -newkey rsa:2048 -sha256 -nodes -keyout server.key -subj "/C=CN/ST=GD/L=SZ/O=Acme, Inc./CN=Acme Root CA" -out ./communication/config/server.csr
openssl x509 -req  -sha256 -extfile <(printf "subjectAltName=DNS:example.com,DNS:localhost,IP:127.0.0.1") -days 3650  -in server.csr   -CA ca.crt -CAkey ca.key -CAcreateserial -out ./communication/config/server.crt

openssl req -newkey rsa:2048 -sha256 -nodes -keyout client.key -subj "/C=CN/ST=GD/L=SZ/O=Acme, Inc./CN=Acme Root CA" -out ./communication/config/client.csr
openssl x509 -req  -sha256 -extfile <(printf "subjectAltName=DNS:example.com,DNS:localhost,IP:127.0.0.1") -days 3650  -in client.csr   -CA ca.crt -CAkey ca.key -CAcreateserial -out ./communication/config/client.crt
