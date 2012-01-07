#!/usr/bin/python
# Copyright (C) 2011, Christof Meerwald
# http://webrss.cmeerw.org

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

import fcntl, itertools, os, re, string, struct, time

from array import array
from urlparse import urlparse

from flask import Flask, current_app, render_template, url_for
from flask.globals import request
from werkzeug.routing import RequestRedirect
from werkzeug.exceptions import NotFound

from parserss import RSS_Resource, RSS_Resource_id2url, RSS_Resource_simplify
from parserss import RSS_Resource_db, RSS_Resource_Cursor
from parserss import UrlError, init_parserss

app = Flask(__name__)
#app.debug = True

base_dir = os.path.abspath(os.path.dirname(__file__))
DB_FNAME = os.path.join(base_dir, 'webrss.db')
init_parserss(db_fname = DB_FNAME,
              min_interval = 45*60, max_interval = 12*60*60,
              interval_div = 5)


def format_timestamp(ts):
    now = int(time.time())
    diff = now - ts

    if diff < 0:
        return None
    elif diff < 10:
        return 'just now'
    elif diff < 70:
        return '%d seconds ago' % (diff,)
    elif diff < 70*60:
        return '%d minutes ago' % (diff // 60,)
    elif diff < 30*60*60:
        return '%d hours ago' % (diff // 3600,)

    return '%d days ago' % (diff // 86400,)


def feed(url, translate_urls=False, reqprefix='', db=None,
         templ=app.jinja_env.get_template('feed.html')):
    now = int(time.time())
    if db == None:
        db = RSS_Resource_db()

    while url != None:
        resource = RSS_Resource(url, db)
        url, seq = resource.redirect_info(db)

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
        channel_title = resource.url()

    last_updated, last_modified, invalid_since = resource.times()
    last_updated = time.asctime(time.gmtime(last_updated))
    if last_modified:
        last_modified = time.asctime(time.gmtime(last_modified))

    if invalid_since:
        error_info = resource.error_info()
    else:
        error_info = ''

    items, last_id = resource.get_headlines(None)
    items = items[-15:]
    items.reverse()

    for item in items:
        item.published = format_timestamp(item.published)

    if translate_urls:
        cursor = db.cursor()

        for item in items:
            keep_going = True
            lnk = item.link

            while keep_going:
                keep_going = False
                hostname = urlparse(lnk).hostname

                for pattern, replacement in cursor.execute('SELECT pattern, replacement FROM translate WHERE host=?', (hostname,)):
                    mo = re.match(pattern, lnk)
                    if mo:
                        buf = []
                        begpos = 0
                        pos = replacement.find('%')
                        while pos != -1:
                            buf.append(replacement[begpos:pos])
                            c = replacement[pos + 1]
                            if c.isdigit():
                                buf.append(mo.group(ord(c) - ord('0')))
                            else:
                                buf.append(c)

                            begpos = pos + 2
                            pos = replacement.find('%', begpos)

                        buf.append(replacement[begpos:])
                        buf = (''.join(buf)).encode('us-ascii')
                        if lnk != buf:
                            lnk = buf
                            keep_going = True

            item.link = lnk

    return (resource.id(), templ.render(rid=resource.id(), url=resource.url(),
                                        reqprefix=reqprefix,
                                        link=channel_info.link,
                                        title=channel_title,
                                        penalty=100*resource.penalty() / 1024,
                                        updated=last_modified,
                                        polled=last_updated,
                                        error_info=error_info,
                                        items=items))


class ResourceIterator:
    def __init__(self, urls, db, translate_urls, reqprefix):
        self.__urls = urls[:]
        self.__iter = 0
        self.__now = int(time.time())
        self.__templ = app.jinja_env.get_template('feed.html')

        if db == None:
            self.__db = RSS_Resource_db()
        else:
            self.__db = db

        self.__translate_urls = translate_urls
        self.__reqprefix = reqprefix

    def __iter__(self):
        return self

    def next(self):
        if self.__iter >= len(self.__urls):
            raise StopIteration()
        else:
            url = self.__urls[self.__iter]
            self.__iter += 1

            rid, response = feed(url, self.__translate_urls,
                                 self.__reqprefix, self.__db, self.__templ)
            return '<span style="display: block; overflow: hidden;" id="feed-%d">%s</span>' % (rid, response)


@app.route('/url', methods=('POST',))
def get_url():
    url = request.form['url']
    reqprefix = request.form['reqprefix']
    translate_urls = ('m' in request.query_string)
    user_agent = request.headers.get('HTTP_USER_AGENT', None)
    if user_agent and not translate_urls:
        translate_urls = (user_agent.find(' NF-Browser/') != -1)

    try:
        id, content = feed(url, translate_urls, reqprefix)
        response = current_app.response_class(content)
        response.headers['X-Feed-Id'] = '%d' % (id,)
    except UrlError, ue:
        response = current_app.response_class(str(ue))
        response.headers['X-Feed-Error'] = str(ue)

    return response

@app.route('/r/<ids>', methods=('GET', 'POST'))
def page(ids, reqprefix=''):
    baseurl = request.url_root
    db = RSS_Resource_db()
    if ids:
        rids = map(lambda x: string.atoi(x), ids.split(','))
    else:
        rids = []
    resources = []

    if request.method == 'POST':
        url = request.form['url']
        if not url:
            raise NotFound()

        while url != None:
            resource = RSS_Resource(url, db)
            url, seq = resource.redirect_info(db)

        if resource.id() not in rids:
            rids.append(resource.id())

        rids = map(lambda x: '%d' % (x,), rids)
        raise RequestRedirect('%s%s%s' % (baseurl, 'r/', ','.join(rids)))

    translate_urls = ('m' in request.query_string)
    user_agent = request.headers.get('HTTP_USER_AGENT', None)
    if user_agent and not translate_urls:
        translate_urls = (user_agent.find(' NF-Browser/') != -1)

    db_rids = []
    urls = []
    for rid in rids:
        try:
            if rid not in db_rids:
                url = RSS_Resource_id2url(rid, db.cursor())
                db_rids.append(rid)
                urls.append(url)
        except KeyError:
            pass

    ridlist = ','.join(map(lambda x: '%d' % (x,), db_rids))

    content_top = render_template('top.html', baseurl=baseurl,
                                  rids=db_rids, ridlist=ridlist)
    content_bottom = render_template('bottom.html', baseurl=baseurl,
                                     reqprefix=reqprefix,
                                     rids=db_rids, ridlist=ridlist)

    content_iter = itertools.chain(iter((content_top,)),
                                   ResourceIterator(urls, db, translate_urls,
                                                    reqprefix),
                                   iter((content_bottom,)))

    response = current_app.response_class(content_iter)
    return response

@app.route('/', methods=('GET', 'POST'))
def index():
    return page('', 'r/')
