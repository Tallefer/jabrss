#!/usr/bin/python
# Copyright (C) 2001-2005, Christof Meerwald
# http://jabrss.cmeerw.org

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 dated June, 1991.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA

import cgi, fcntl, os, signal, string, struct, sys, time

import parserss
from parserss import RSS_Resource, RSS_Resource_id2url, RSS_Resource_simplify
from parserss import RSS_Resource_db, RSS_Resource_Cursor
from parserss import UrlError


script_dir = os.path.split(os.getenv('SCRIPT_FILENAME'))[0]
stylesheet = 'http://cmeerw.org/style/webrss.css'

if os.getenv('SERVER_NAME').find('beta.cmeerw.org') != -1:
    db_fname = os.path.join(script_dir, '../../files/db/webrss-beta.db')
elif os.getenv('SERVER_NAME').find('cmeerw.org') != -1:
    db_fname = os.path.join(script_dir, '../../files/db/webrss.db')
else:
    stylesheet = 'http://cmeerw.hacking.cmeerw.net/style/webrss.css'
    db_fname = os.path.join(script_dir, '../db/webrss.db')

interval_div = 5
min_interval = 45*60
max_interval = 12*60*60


class TimedOutException(Exception):
    def __init__(self, value = 'Timed Out'):
        self.value = value

    def __str__(self):
        return repr(self.value)


def timed_out_func(timeout, func, *args, **kwargs):
    def alarm_handler(signum, frame):
        raise TimedOutException()

    signal.alarm(timeout)
    old = signal.signal(signal.SIGALRM, alarm_handler)
    try:
        result = func(*args, **kwargs)
    finally:
        signal.signal(signal.SIGALRM, old)
        signal.alarm(0)

    return result


class File_Lock_Synchronizer:
    def __init__(self, fname):
        self._fd = open(fname, 'r+')

        self._lockdata = struct.pack('hhqqhh', fcntl.F_WRLCK,
                                     0, 0L, 0L, 0, 0)
        self._unlockdata = struct.pack('hhqqhh', fcntl.F_UNLCK,
                                       0, 0L, 0L, 0, 0)

    def acquire(self):
        timed_out_func(10, fcntl.fcntl, self._fd, fcntl.F_SETLKW,
                       self._lockdata)

    def release(self):
        fcntl.fcntl(self._fd, fcntl.F_SETLK, self._unlockdata)


parserss.init(db_fname = db_fname,
              min_interval = 45*60, max_interval = 12*60*60,
              interval_div = 5,
              dbsync_obj = File_Lock_Synchronizer(db_fname))


def html_encode(s):
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

def process_id(id, db):
    url = RSS_Resource_id2url(id, db.cursor())

    resource = RSS_Resource(url, db)
    next_update = resource.next_update(False)

    if next_update <= now:
        new_items, next_item_id, redirect_resource, redirect_seq, redirects = resource.update()

        if redirect_resource != None:
            resource = redirect_resource

    channel_info = resource.channel_info()
    channel_title = channel_info.title
    if not channel_title.strip():
        channel_title = channel_info.link
    if not channel_title.strip():
        channel_title = url

    sys.stdout.write('<div class="resheader"><h2><a href="%s">%s</a></h2>\n' % (html_encode(channel_info.link.encode('ascii' ,'replace')), html_encode(channel_title).encode('utf-8')))

    last_updated, last_modified, invalid_since = resource.times()

    sys.stdout.write('<span class="resinfo">Resource <a href="%s">id %d</a>, feed penalty: %d %%<br />\n' % (html_encode(resource.url()), resource.id(), 100*resource.penalty() / 1024))
    if last_modified:
        sys.stdout.write('updated: %s, ' % (time.asctime(time.gmtime(last_modified)),))
    sys.stdout.write('polled: %s' % (time.asctime(time.gmtime(last_updated)),))

    if invalid_since:
        sys.stdout.write('<br /><span class="error">Error: %s</span>' % (resource.error_info(),))

    sys.stdout.write('</span></div>\n<ul class="headlines">\n')
    items, last_id = resource.get_headlines(None)
    items = items[-15:]
    items.reverse()
    for item in items:
        title = item.title
        if title == '':
            title = item.link
            pos = title.find('?')
            if pos != -1:
                title = title[pos + 1:]

        sys.stdout.write('<li><a href="%s">%s</a></li>\n' % (html_encode(item.link.encode('ascii', 'replace')), html_encode(title).encode('utf-8')))

    sys.stdout.write('</ul>\n')

    return resource.id()


db = RSS_Resource_db()
now = int(time.time())

ids = []

form = cgi.FieldStorage()
if form.has_key('id'):
    ids = map(string.atoi, form['id'].value.split(','))

if form.has_key('url'):
    url = form['url'].value
    resource = RSS_Resource(url, db)
    if resource != None:
        new_ids = ids + [resource.id()]
        query = ','.join(map(lambda x: str(x), new_ids))

        sys.stdout.write('Status: 301\r\n')
        sys.stdout.write('Location: http://%s%s?id=%s\r\n' % (html_encode(os.getenv('SERVER_NAME')), html_encode(os.getenv('SCRIPT_NAME')), query))
        sys.stdout.write('\r\n')
        sys.exit(0)

sys.stdout.write('Content-Type: text/html;charset=utf-8\r\n')
sys.stdout.write('\r\n')
sys.stdout.write('''<html><head>
<link type="text/css" rel="stylesheet" href="%s" />
<title>WebRSS (built on JabRSS technology)</title>
</head><body bgcolor="#ffffff">
<h1>WebRSS (built on JabRSS technology)</h1>
''' % (html_encode(stylesheet),))

new_ids = []
for id in ids:
    new_ids.append(process_id(id, db))

query = ','.join(map(lambda x: str(x), new_ids))
sys.stdout.write('<hr /><h1>Control</h1>\n')
sys.stdout.write('<p><ul>\n')
sys.stdout.write('<li><a href="http://%s%s?id=%s">Bookmark URL</a></li>\n' % (html_encode(os.getenv('SERVER_NAME')), html_encode(os.getenv('SCRIPT_NAME')), query))
sys.stdout.write('<li><form action="http://%s%s"><input type="hidden" name="id" value="%s" />URL: <input type="text" name="url" /> <input type="submit" value="Add" /></form></li>\n' % (html_encode(os.getenv('SERVER_NAME')), html_encode(os.getenv('SCRIPT_NAME')), query))
sys.stdout.write('</ul></p>\n')

sys.stdout.write('</p>\n')
sys.stdout.write('</body></html>\n')
