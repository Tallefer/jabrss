#!/usr/bin/python
# Copyright (C) 2011-2013, Christof Meerwald
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

import itertools, os, random, time

from flask import Flask, current_app, render_template, url_for
from flask.globals import request
from werkzeug.routing import RequestRedirect
from werkzeug.exceptions import NotFound

from parserss import RSS_Resource, RSS_Resource_id2url, RSS_Resource_simplify
from parserss import RSS_Resource_db, RSS_Resource_Cursor
from parserss import UrlError, init_parserss

from urlrewriter import NullRewriter, UrlRewriter

app = Flask(__name__)
app.debug = False

base_dir = os.path.abspath(os.path.dirname(__file__))
DB_FNAME = os.path.join(base_dir, 'webrss.db')
init_parserss(db_fname = DB_FNAME,
              min_interval = 45*60, max_interval = 12*60*60,
              interval_div = 5)

CHARSET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-*'


def format_rid(rid):
    s = ''
    while rid:
        s += CHARSET[rid % 64]
        rid /= 64
    return s

def parse_rid(s):
    rid, mult = 0, 1

    for c in s:
        val = 0
        if c >= '0' and c <= '9':
            val = ord(c) - ord('0')
        elif c >= 'A' and c <= 'Z':
            val = ord(c) - ord('A') + 10
        elif c >= 'a' and c <= 'z':
            val = ord(c) - ord('a') + 36
        elif c == '-':
            val = 62
        elif c == '*':
            val = 63

        rid += val * mult
        mult *= 64

    return rid

def get_generate_id():
    random_id = random.SystemRandom()
    return lambda: random_id.randint(0, 64**5)

generate_id = get_generate_id()

def get_rewriter(rewrite = False):
    if rewrite:
        return UrlRewriter(os.path.join(base_dir, 'rewrite.db'))
    else:
        return NullRewriter()


def format_timestamp(ts):
    if ts == None:
        return None

    now = int(time.time())
    diff = now - ts

    if diff < 0:
        return None
    elif diff < 10:
        return 'just now'
    elif diff < 70:
        return '%d seconds ago' % (diff,)
    elif diff < 90*60:
        return '%d minutes ago' % (diff // 60,)
    elif diff < 2*60*60:
        return '1 hour ago'
    elif diff < 30*60*60:
        return '%d hours ago' % (diff // 3600,)
    elif diff < 48*60*60:
        return '1 day ago'

    return '%d days ago' % (diff // 86400,)


def feed(url, rewriter, db=None, templ=app.jinja_env.get_template('feed.html')):
    now = int(time.time())
    if db == None:
        db = RSS_Resource_db()

    while url != None:
        resource = RSS_Resource(url, db, generate_id=generate_id)
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
        item.link = rewriter.rewrite(item.link)

    return (resource.id(), templ.render(rid=format_rid(resource.id()),
                                        url=resource.url(),
                                        link=channel_info.link,
                                        title=channel_title,
                                        penalty=100*resource.penalty() / 1024,
                                        updated=last_modified,
                                        polled=last_updated,
                                        error_info=error_info,
                                        items=items))


class ResourceIterator:
    def __init__(self, rids, db, rewrite=False):
        self.__rids = rids
        self.__iter = 0
        self.__now = int(time.time())
        self.__templ = app.jinja_env.get_template('feed.html')

        if db == None:
            self.__db = RSS_Resource_db()
        else:
            self.__db = db

        self.__rewriter = get_rewriter(rewrite)

    def __iter__(self):
        return self

    def next(self):
        while True:
            if self.__iter >= len(self.__rids):
                raise StopIteration()
            else:
                rid = self.__rids[self.__iter]
                self.__iter += 1

                try:
                    url = RSS_Resource_id2url(rid, self.__db.cursor())
                    rid, response = feed(url, self.__rewriter, self.__db,
                                         self.__templ)
                    self.__rids[self.__iter - 1] = rid
                    return '<span style="display: block; overflow: hidden;" class="rssfeed" id="feed-%s">%s</span>' % (format_rid(rid), response)
                except KeyError:
                    self.__rids[self.__iter - 1] = None


class BottomIterator:
    def __init__(self, rids):
        self.__rids = rids
        self.__iter = 0

    def __iter__(self):
        return self

    def next(self):
        if self.__iter:
            raise StopIteration()
        else:
            self.__iter += 1
            ridlist = map(format_rid, filter(lambda x: x != None, self.__rids))
            return app.jinja_env.get_template('bottom.html').render(ridlist=ridlist)


@app.route('/url', methods=('POST',))
def get_url():
    url = request.form['url']
    rewrite = request.form.get('rewrite', 'false') == 'true'

    try:
        id, content = feed(url, get_rewriter(rewrite))
        response = current_app.response_class(content)
        response.headers['X-Feed-Id'] = format_rid(id)
    except UrlError, ue:
        response = current_app.response_class(str(ue))
        response.headers['X-Feed-Error'] = str(ue)

    return response

@app.route('/r/<ids>', methods=('GET', 'POST'))
@app.route('/r/', methods=('GET', 'POST'))
def page(ids='', rewrite=False):
    db = RSS_Resource_db()
    if ids:
        rids = map(parse_rid, ids.split(','))
    else:
        rids = []
    resources = []

    content_top = render_template('top.html')
    content_iter = itertools.chain(iter((content_top,)),
                                   ResourceIterator(rids, db, rewrite),
                                   BottomIterator(rids))

    response = current_app.response_class(content_iter)
    return response

@app.route('/R/<ids>', methods=('GET', 'POST'))
@app.route('/R/', methods=('GET', 'POST'))
def page_rewrite(ids=''):
    return page(ids, True)

@app.route('/p/<ids>', methods=('POST',))
@app.route('/p/', methods=('POST',))
def addurl(ids=''):
    db = RSS_Resource_db()
    if ids:
        rids = map(parse_rid, ids.split(','))
    else:
        rids = []

    url = request.form['url']
    if not url:
        raise NotFound()

    while url != None:
        resource = RSS_Resource(url, db, generate_id)
        url, seq = resource.redirect_info(db)

    if resource.id() not in rids:
        rids.append(resource.id())

    ridlist = map(format_rid, rids)
    raise RequestRedirect(url_for('page', ids=','.join(ridlist)))

@app.route('/opml/<ids>/subscriptions.xml')
@app.route('/opml/subscriptions.xml')
def opml(ids=''):
    db = RSS_Resource_db()
    if ids:
        rids = map(parse_rid, ids.split(','))
    else:
        rids = []
    items = []

    for rid in rids:
        try:
            url = RSS_Resource_id2url(rid, db.cursor())
            while url != None:
                resource = RSS_Resource(url, db, generate_id=generate_id)
                url, seq = resource.redirect_info(db)

            items.append(resource)
        except KeyError:
            pass

    response = current_app.response_class(render_template('subscriptions.xml', items=items), mimetype='application/xml')
    return response

@app.route('/')
def index():
    raise RequestRedirect(url_for('page', ids=''))
