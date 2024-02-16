#!/bin/bash
ROOT_DIR=`realpath $(dirname $0)`
cd $ROOT_DIR

python3 ../forward.py --is-tunnel-server --status-period=300