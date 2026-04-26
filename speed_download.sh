#!/bin/bash

URL="https://r2.wuxie.de/hello100.png"

echo "开始测速（精确限制100MB流量）..."

START=$(date +%s)

# 只下载前100MB
curl -r 0-104857599 -o /dev/null -s -w "%{speed_download}\n" $URL > /tmp/speed.txt

END=$(date +%s)
TIME=$((END - START))

SPEED=$(cat /tmp/speed.txt)

echo "---------------------------------"
echo "耗时: ${TIME} 秒"
echo "平均速度: $(echo "$SPEED / 1024 / 1024" | bc -l) MB/s"

rm -f /tmp/speed.txt
