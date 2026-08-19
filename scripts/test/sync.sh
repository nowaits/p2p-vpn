#!/bin/bash

ROOT_DIR=`realpath $(dirname $0)`
cd $ROOT_DIR

SOURCE_DIR=$ROOT_DIR/../..
REMOTE_DIR=/root/nas/code/p2p-vpn

SHOULD_DEL=

PORT=4510
HOST=z.botnn.com

PORT=22
HOST=20.0.0.2

#
# 1. 如果目的目录不存在，会自动创建
#
SYNC="rsync -q -avz --exclude=**/.git"

if [ -n "$SHOULD_DEL" ]; then
    SYNC="$SYNC --delete"
fi

$SYNC -e "ssh -p $PORT" \
    $SOURCE_DIR/ root@$HOST:$REMOTE_DIR/

while inotifywait -q -r -e modify,create,delete,move "$SOURCE_DIR" || true; do
    $SYNC -e "ssh -p $PORT" \
        $SOURCE_DIR/ root@$HOST:$REMOTE_DIR/
done