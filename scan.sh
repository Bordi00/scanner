#!/usr/bin/env bash

TARGETS=("172.16.199.0/24" "172.16.4.0/22" "172.16.15.0/24")
t=$((RANDOM % ${#TARGETS[@]}))
python3 main.py -t ${t} -r -p MSWKP -m sneaky -o scans.json