#!/bin/bash
TIMINGS=(-T2 -T4)

for i in $(seq 1 15); do
    timing=${TIMINGS[$((RANDOM % 2))]}
    echo "=== RECON-01 rep $i/15 -- timing=$timing ==="
    timeout 90 python3 06_run_logger.py \
        --scenario RECON-01 \
        --class reconnaissance \
        --cmd "timeout 75 nmap -sV $timing -p- 192.168.10.104" \
        --target 192.168.10.104 \
        --note "rep $i/15, timing=$timing"
    sleep 10
done

for i in $(seq 1 10); do
    echo "=== RECON-02 rep $i/10 ==="
    timeout 60 python3 06_run_logger.py \
        --scenario RECON-02 \
        --class reconnaissance \
        --cmd "timeout 45 nmap -sS -p 1-1000 192.168.10.104" \
        --target 192.168.10.104 \
        --note "rep $i/10"
    sleep 10
done

echo "RECON DONE"