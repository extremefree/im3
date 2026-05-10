#!/bin/bash
cd ~/im3
pkill -f './client' 2>/dev/null
sleep 0.3

# bob 先登录，保持 stdin 5 秒
(printf "LOGIN bob:bob456\n"; sleep 5) | ./client ::1 > /tmp/bob.txt 2>&1 &

sleep 1

# alice 登录并发消息，保持 stdin 3 秒
(printf "LOGIN alice:alice123\nhello from alice\n"; sleep 3) | ./client ::1 > /tmp/alice.txt 2>&1 &

sleep 4

echo "=== ALICE ==="
cat /tmp/alice.txt
echo "=== BOB ==="
cat /tmp/bob.txt
