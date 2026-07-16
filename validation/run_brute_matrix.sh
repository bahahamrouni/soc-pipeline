#!/bin/bash
WORDLISTS=(/tmp/wl_small.txt /tmp/wl_medium.txt /tmp/wl_large.txt)
THREADS=(2 4)

for i in 2 3 4 5 6 7 8 9 10 12 13 15; do
    wl=${WORDLISTS[$((RANDOM % 3))]}
    t=${THREADS[$((RANDOM % 2))]}
    echo "=== Retry rep $i/15 -- wordlist=$wl threads=$t ==="
    python3 06_run_logger.py \
        --scenario BRUTE-01 \
        --class brute_force \
        --cmd "hydra -l root -P $wl -t $t ssh://192.168.10.104" \
        --target 192.168.10.104 \
        --note "retry rep $i/15, wordlist=$wl, threads=$t"
    sleep 20
done

echo "RETRY DONE"