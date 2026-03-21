#!/bin/bash

if [ -z "$1" ]; then
  echo "用法: $0 <IP_ADDRESS>"
  exit 1
fi

IP=$1

if ! [[ $IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  echo "错误: $IP 不是一个有效的 IP 地址"
  exit 1
fi

echo "正在封禁 IP: $IP"
/sbin/iptables -A INPUT -s $IP -j DROP

if [ $? -eq 0 ]; then
  echo "IP $IP 封禁成功"
else
  echo "错误: 封禁 IP $IP 失败"
  exit 1
fi
