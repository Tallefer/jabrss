#!/bin/sh
cd "`dirname $0`"
exec python jabrssng.py \
    --jid=JabRSS@cmeerw.net/JabRSS --connect-host=swissjabber.ch \
    --password-file=/home/cmeerw/jabrss/jabrss-passwd
