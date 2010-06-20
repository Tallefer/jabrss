#!/bin/sh
export MOZILLA_FIVE_HOME=/home/cmeerw/jabrss

cd "`dirname $0`"
exec python jabrss.py \
    --server=cmeerw.net \
    --username=jabrss \
    --connect-host=c2s.swissjabber.ch:5239 \
    --password-file=/home/cmeerw/jabrss/jabrss-passwd
