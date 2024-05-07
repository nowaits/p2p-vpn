#!/bin/bash
ROOT_DIR=`realpath $(dirname $0)`
cd $ROOT_DIR

python3 ../vpn.py -s=www.botnn.com --server-key=test --user=test --passwd=123456 --vip=10.0.0.1 --verbose=INFO