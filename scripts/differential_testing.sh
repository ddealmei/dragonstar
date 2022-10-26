#!/bin/bash
set -e

LOG_DIR=results/functional

n_passwords=100
mkdir -p $LOG_DIR
# Following tests need password as input, we will test a bunch
passwords=$(shuf -n $n_passwords "data/1000_passwords.txt" | tr '/' '_')

echo "Comparing outputs of $n_passwords passwords for OpenSSL and HaCl*"

echo -en "\tTesting SAE (legacy): "
./hostap/dragonstar/debug/dragonstar_openssl $passwords &> "$LOG_DIR/legacy-openssl.log"
./hostap/dragonstar/debug/dragonstar_hacl $passwords &> "$LOG_DIR/legacy-hacl.log"
diff_file="$LOG_DIR/legacy.diff"
diff -W 150 "$LOG_DIR/legacy-openssl.log" "$LOG_DIR/legacy-hacl.log" > $diff_file || true
[ -s $diff_file ] && echo "[-] Outputs not matching. Run \"cat $diff_file\" to get more details" || echo "[+] PASSED"

echo -en "\tTesting SAE-PT: "
./hostap/dragonstar/debug/dragonstar_openssl -i testid $passwords &> "$LOG_DIR/sswu-openssl.log"
./hostap/dragonstar/debug/dragonstar_hacl      -i testid $passwords &> "$LOG_DIR/sswu-hacl.log"
diff_file="$LOG_DIR/sswu.diff"
diff -W 150 "$LOG_DIR/sswu-openssl.log" "$LOG_DIR/sswu-hacl.log" > $diff_file || true
[ -s $diff_file ] && echo -e "[-] Outputs not matching. Run \"cat $diff_file\" to get more details" || echo -e "[+] PASSED"