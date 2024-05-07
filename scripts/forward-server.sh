#!/bin/bash
ROOT_DIR=`realpath $(dirname $0)`
cd $ROOT_DIR

python3 ../forward.py --is-tunnel-server --server-key=test --status-period=300