#!/bin/bash
ROOT_DIR=`realpath $(dirname $0)`
cd $ROOT_DIR

python3 ../forward.py \
	--ip=www.botnn.com --server-key=test --verbose=INFO \
	--status-period=300 \
	--remote-port-map=tcp:4510:22 \
	--remote-port-map=tcp:4511:80 \
	--remote-port-map=tcp:4512:8080 \
	--remote-port-map=tcp:4513:8081 \
	--remote-port-map=tcp:4514:7890 \
	--remote-port-map=tcp:4515:4312 \
	--remote-port-map=tcp:4516:5244 \
