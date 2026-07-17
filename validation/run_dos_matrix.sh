#!/bin/bash
for i in $(seq 1 10); do
    echo "=== DOS-01 rep $i/10 ==="
    timeout 60 python3 06_run_logger.py \
        --scenario DOS-01 \
        --class alert_storm \
        --cmd "timeout 30 nmap -sS -T5 --min-rate 1000 -p 1-2000 192.168.10.104" \
        --target 192.168.10.104 \
        --note "rep $i/10, fast repeated scan to trigger volume threshold"
    sleep 10
done

echo "DOS DONE"