#!/bin/bash
ROOT_DIR=`realpath $(dirname $0)`
cd $ROOT_DIR

python3 ../forward.py --ip=www.botnn.com --verbose=INFO --status-period=300 --remote-port-map=tcp:4510:22,tcp:4511:80,tcp:4512:8080
