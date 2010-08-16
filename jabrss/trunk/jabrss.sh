#!/bin/sh
cd "`dirname $0`"
exec python jabrssng.py \
    --server=cmeerw.net \
    --username=jabrss \
    --connect-host=c2s.swissjabber.ch \
    --password-file=/home/cmeerw/jabrss/jabrss-passwd
