#!/usr/bin/python
# Copyright (C) 2001-2014, Christof Meerwald
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

from __future__ import with_statement

import codecs, functools, hashlib, logging, random, re, socket, struct
import sys, time, threading, traceback, zlib
import sqlite3
import requests

from email.utils import formatdate, mktime_tz, parsedate_tz

try:
    from lxml.etree import Element, XMLParser
except ImportError:
    try:
        from xml.etree.cElementTree import Element, XMLParser
    except ImportError:
        from xml.etree.ElementTree import Element, XMLParser

from contenttools import htmlelem2plain, html2plain, xml2plain

if sys.version_info[0] == 2:
    from HTMLParser import HTMLParser, HTMLParseError
    from StringIO import StringIO
    from urlparse import urlsplit, urljoin
else:
    from html.parser import HTMLParser, HTMLParseError
    from io import StringIO
    from urllib.parse import urlsplit, urljoin
    unichr = chr

logger = logging.getLogger('parserss')


__all__ = [
    'RSS_Resource', 'RSS_Resource_id2url', 'RSS_Resource_simplify'
    'RSS_Resource_db', 'RSS_Resource_Cursor',
    'UrlError', 'init_parserss',
]

if sys.version_info[0] == 2:
    import string
    str_trans = string.maketrans(
        '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' \
            '\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f' \
            ''.encode('ascii'),
        '          \x0a                     '.encode('ascii'))
else:
    str_trans = None
    def buffer(b):
        return b

unicode_trans = {
    0x00 : 0x20, 0x01 : 0x20, 0x02 : 0x20, 0x03 : 0x20,
    0x04 : 0x20, 0x05 : 0x20, 0x06 : 0x20, 0x07 : 0x20,
    0x08 : 0x20, 0x09 : 0x20, 0x0a : 0x0a, 0x0b : 0x20,
    0x0c : 0x20, 0x0d : 0x20, 0x0e : 0x20, 0x0f : 0x20,
    0x10 : 0x20, 0x11 : 0x20, 0x12 : 0x20, 0x13 : 0x20,
    0x14 : 0x20, 0x15 : 0x20, 0x16 : 0x20, 0x17 : 0x20,
    0x18 : 0x20, 0x19 : 0x20, 0x1a : 0x20, 0x1b : 0x20,
    0x1c : 0x20, 0x1d : 0x20, 0x1e : 0x20, 0x1f : 0x20
    }

random.seed()


def RSS_Resource_db():
    db = sqlite3.Connection(DB_FILENAME, 60000)
    db.isolation_level = None
    db.cursor().execute('PRAGMA synchronous=NORMAL')

    return db

class Null_Synchronizer:
    def acquire(self):
        return

    def release(self):
        return


# configuration settings
INTERVAL_DIVIDER = 3
MIN_INTERVAL = 45*60
MAX_INTERVAL = 24*60*60
DB_FILENAME = 'parserss.db'

def init_parserss(db_fname = DB_FILENAME,
                  min_interval = MIN_INTERVAL,
                  max_interval = MAX_INTERVAL,
                  interval_div = INTERVAL_DIVIDER,
                  dbsync_obj = Null_Synchronizer()):
    global DB_FILENAME, MIN_INTERVAL, MAX_INTERVAL, INTERVAL_DIVIDER

    DB_FILENAME = db_fname
    MIN_INTERVAL = min_interval
    MAX_INTERVAL = max_interval
    INTERVAL_DIVIDER = interval_div

    RSS_Resource._db_sync = dbsync_obj


class UrlError(ValueError):
    pass

def split_url(url):
    u = urlsplit(url)

    protocol = u.scheme

    netloc_comp = u.netloc.split(':', 2)
    host = netloc_comp[0].lower().split('.')
    if len(netloc_comp) >= 2:
        port = netloc_comp[1]
    else:
        port = None

    path = u.path
    if u.query:
        path += '?' + u.query

    validhost = False

    if len(host) == 1 and host[0][:1] == '[' and host[0][-1:] == ']':
        try:
            host[0] = '[%s]' % (socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, host[0][1:-1])))
            validhost = True
        except socket.error:
            validhost = False
    elif len(host) == 4:
        try:
            host = socket.inet_ntop(socket.AF_INET, socket.inet_pton(socket.AF_INET, '.'.join(host))).split('.')
            if int(host[0]) == 10:
                pass
            elif int(host[0]) == 172 and int(host[1]) in range(16, 32):
                pass
            elif int(host[0]) == 192 and int(host[1]) == 168:
                pass
            elif int(host[0]) >= 240:
                pass
            else:
                validhost = True
        except socket.error:
            validhost = False

    if not validhost and len(host) >= 2:
        if len(host[-1]) >= 2 and host[-1].isalpha():
            validhost = True

    if not validhost:
        raise UrlError('invalid host in URL "%s"' % ('.'.join(host),))

    if protocol == 'http':
        if port not in (None, '80', 'http'):
            raise UrlError('http ports != 80 not allowed')
    elif protocol == 'https':
        if port not in (None, '443', 'https'):
            raise UrlError('https ports != 443 not allowed')
    else:
        raise UrlError('unsupported protocol "%s"' % (protocol))

    if path == '':
        path = '/'

    while path[:2] == '//':
        path = path[1:]

    return protocol, '.'.join(host), path


def normalize_text(s):
    if type(s) == type(b''.decode('ascii')):
        s = s.translate(unicode_trans)
    else:
        s = s.translate(str_trans)

    s = '\n'.join(filter(lambda x: x != '', [ x.strip() for x in s.split('\n') ]))
    s = ' '.join(filter(lambda x: x != '', s.split(' ')))
    return s

def normalize_obj(o):
    for attr in dir(o):
        if attr[0] != '_':
            value = getattr(o, attr)
            if type(value) in (type(''), type(b''.decode('ascii'))):
                setattr(o, attr, normalize_text(value))

    return o

def normalize_item(item):
    normalize_obj(item)

    if item.descr == '':
        item.descr = None

    if not hasattr(item, 'descr_plain'):
        item.descr_plain = item.descr

    if not hasattr(item, 'descr_xhtml'):
        item.descr_xhtml = None

    if item.descr_plain:
        item.descr_plain = item.descr_plain[:4096]

    del item.descr

    return item


re_dateTime = re.compile('^(?P<year>[1-9][0-9][0-9][0-9])-(?P<month>[01][0-9])-(?P<day>[0-3][0-9])T(?P<hour>[0-2][0-9]):(?P<min>[0-6][0-9]):(?P<sec>[0-6][0-9])(\\.[0-9]+)?(Z|(?P<tzsign>[-+])(?P<tzhour>[01][0-9]):(?P<tzmin>[0-6][0-9]))$')

def parse_dateTime(s):
    if s == None:
        return None

    mo = re_dateTime.match(s)
    if mo != None:
        year, month, day, hour, min, sec = [ int(x) for x in mo.group('year', 'month', 'day', 'hour', 'min', 'sec')]

        tzsign, tzhour, tzmin = mo.group('tzsign', 'tzhour', 'tzmin')
        if tzhour != None and tzmin != None:
            tzoff = 60*(60*int(tzhour) + int(tzmin))
        else:
            tzoff = 0

        if tzsign == '-':
            tzoff = -tzoff

        tstamp = int(mktime_tz((year, month, day, hour, min, sec, 0, 0, 0, tzoff)))
    else:
        tstamp = None

    return tstamp

def parse_Rfc822DateTime(s):
    if s == None:
        return None

    try:
        tstamp = int(mktime_tz(parsedate_tz(s)))
    except:
        tstamp = None

    return tstamp


def compare_items(l, r):
    lguid, ltitle, llink = l.guid, l.title, l.link
    rguid, rtitle, rlink = r.guid, r.title, r.link

    if ltitle == rtitle:
        if (lguid != None) and (rguid != None):
            return lguid == rguid

        lurl = urlsplit(llink)
        rurl = urlsplit(rlink)

        if lurl.scheme == rurl.scheme and lurl.path == rurl.path and \
                lurl.query == rurl.query and lurl.fragment == rurl.fragment:
            lhostparts = lurl.netloc.lower().split('.')
            if lhostparts[-1] == '':
                del lhostparts[-1]

            rhostparts = rurl.netloc.lower().split('.')
            if rhostparts[-1] == '':
                del rhostparts[-1]

            if len(lhostparts) >= 2:
                del lhostparts[-1]
            if len(rhostparts) >= 2:
                del rhostparts[-1]

            if len(lhostparts) > len(rhostparts):
                tmp = lhostparts
                lhostparts = rhostparts
                rhostparts = tmp
                del tmp

            if len(lhostparts) == len(rhostparts):
                return lhostparts == rhostparts
            else:
                return lhostparts == rhostparts[-len(lhostparts):]
        else:
            return 0
    else:
        return 0

class CleanupOnError:
    def __init__(self, callable=None):
        self.__callable = callable

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_value, traceback):
        if self.__callable != None and exc_type != None:
            self.__callable()

class Cursor:
    def __init__(self, dbconn, parent=None):
        self._txn, self._locked = False, False
        self._parent = parent
        if self._parent == None:
            if not hasattr(dbconn, 'cursor'):
                self._cursor = dbconn().cursor()
            else:
                self._cursor = dbconn.cursor()
        else:
            self._cursor = None

    def __enter__(self):
        if self._parent == None:
            return self
        else:
            return self._parent

    def __exit__(self, exc_type, exc_value, traceback):
        if self._parent == None:
            self.commit()

    def commit(self):
        try:
            if self._txn:
                self._cursor.execute('COMMIT')
                self._txn = False
        finally:
            if self._locked:
                RSS_Resource._db_sync.release()
                self._locked = False

    def begin(self):
        if not self._locked:
            RSS_Resource._db_sync.acquire()
            self._locked = True

        if not self._txn:
            self._cursor.execute('BEGIN')
            self._txn = True

    def execute(self, stmt, bindings=None):
        self.begin()

        if bindings == None:
            return self._cursor.execute(stmt)
        else:
            return self._cursor.execute(stmt, bindings)

    def __getattr__(self, name):
        if name == 'lastrowid':
            return self._cursor.lastrowid
        elif name == 'rowcount':
            return self._cursor.rowcount

        raise AttributeError('object has no attribute \'%s\'' % (name,))

    def getdb(self):
        return self._cursor.getconnection()

RSS_Resource_Cursor = Cursor

class Data:
    def __init__(self, **kw):
        for key, value in kw.items():
            setattr(self, key, value)


class FeedError(Exception):
    def __init__(self, e):
        Exception.__init__(self, e)

class RetryAsHtml(Exception):
    def __init__(self):
        Exception.__init__(self)


def findtag(parent, tags):
    elem = None

    for tag in tags:
        elem = parent.find(tag)
        if elem != None:
            break

    return elem

def findattr(l, textattr, attr=None, values=(), default=''):
    text, typ = '', None
    for e in l:
        thistyp = -1
        if attr != None:
            try:
                thistyp = values.index(e.get(attr, default))
            except ValueError:
                pass

        if text == '' or thistyp > typ:
            if e.get(textattr, None):
                text, typ = e.get(textattr, None), thistyp

    return text

def findelem(l, attr=None, values=(), default=''):
    elem, typ = None, None
    for e in l:
        thistyp = -1
        if attr != None:
            try:
                thistyp = values.index(e.get(attr, default))
            except ValueError:
                pass

        if elem == None or thistyp > typ:
            elem, typ = e, thistyp

    return elem


def typedtext(elem):
    if elem == None:
        return ''
    if elem.get('type', None) == 'html':
        return htmlelem2plain(elem)
    else:
        buf = StringIO()
        xml2plain(elem, buf)
        text = buf.getvalue()
        buf.close()
        return text


class Feed_Parser:
    class Handler:
        def __init__(self):
            self.__doctype, self.__data, self.__elem, self.__last, self.__tail = None, [], [], None, None

            self.__toplevel_handler = {
                '{http://www.w3.org/2005/Atom}feed' :
                    (self.atom10_feed_start, self.atom10_feed_end),
                '{http://purl.org/atom/ns#}feed' :
                    (self.atom03_feed_start, self.atom03_feed_end),

                '{http://www.w3.org/1999/02/22-rdf-syntax-ns#}RDF' :
                    (self.rss_start, self.rss_end),
                'rss' :
                    (self.rss_start, self.rss_end),
                '{http://backend.userland.com/rss2}rss' :
                    (self.rss_start, self.rss_end),

                # RSS 1.1, see http://inamidst.com/rss1.1/
                '{http://purl.org/net/rss1.1#}Channel' :
                    (self.rss11_start, self.rss11_end),
                }
            self.__end_handler, self.__element_handler = None, {}

            self.redirect_url, self.info, self.elements = None, None, []

        def close(self):
            assert len(self.__elem) == 0, "missing end tags"
            assert self.__last != None, "missing toplevel element"
            return self.__last

        def __flush(self):
            if self.__data:
                if self.__last is not None:
                    text = ''.join(self.__data)
                    if self.__tail:
                        assert self.__last.tail is None, "internal error (tail)"
                        self.__last.tail = text
                    else:
                        assert self.__last.text is None, "internal error (text)"
                        self.__last.text = text
                self.__data = []

        def data(self, data):
            self.__data.append(data)

        def start(self, tag, attrs):
            if attrs == None:
                attrs = {}
            self.__flush()
            self.__last = elem = Element(tag, attrs)

            if len(self.__elem) == 0:
                try:
                    handler, self.__end_handler = self.__toplevel_handler[tag]
                except KeyError:
                    handler = None

                if handler:
                    handler(elem)
                elif tag in ('html', '{http://www.w3.org/1999/xhtml}html'):
                    raise RetryAsHtml()
                elif self.__doctype == 'html':
                    raise RetryAsHtml()
                else:
                    raise FeedError('Unknown start tag %s' % (tag,))

            self.__elem.append(elem)
            self.__tail = False
            return elem

        def end(self, tag):
            self.__flush()
            self.__last = self.__elem.pop()
            assert self.__last.tag == tag,\
                   "end tag mismatch (expected %s, got %s)" % (
                       self.__last.tag, tag)
            self.__tail = True

            if len(self.__elem) == 0:
                self.__end_handler(self.__last)
            else:
                try:
                    handler = self.__element_handler[tag]
                except KeyError:
                    handler, keep = None, len(self.__elem) >= 2

                if handler:
                    keep = handler(self.__last)
                if keep:
                    self.__elem[-1].append(self.__last)

            self._root = self.__last
            return self.__last


        def keep_elem(self, elem):
            return True


        def atom03_feed_start(self, elem):
            self.__element_handler = {
                '{http://purl.org/atom/ns#}entry' :
                    self.atom03_entry,
                '{http://purl.org/atom/ns#}title' :
                    self.keep_elem,
                '{http://purl.org/atom/ns#}link' :
                    self.keep_elem,
                '{http://purl.org/atom/ns#}tagline' :
                    self.keep_elem,
                '{http://purl.org/atom/ns#}id' :
                    self.keep_elem,
                '{http://purl.org/atom/ns#}created' :
                    self.keep_elem,
                '{http://purl.org/atom/ns#}modified' :
                    self.keep_elem,
                }

        def atom03_feed_end(self, elem):
            ns = '{http://purl.org/atom/ns#}'

            title = typedtext(elem.find(ns + 'title'))
            descr = typedtext(elem.find(ns + 'tagline'))
            link = findattr(elem.findall(ns + 'link'),
                            'href', 'rel',
                            ['via', 'related', 'enclosure', 'alternate'],
                            'alternate')
            guid = elem.findtext(ns + 'id')
            published = parse_dateTime(elem.findtext(ns + 'created') or \
                                           elem.findtext(ns + 'modified') or \
                                           None)

            self.info = Data(title=title, descr=descr, link=link,
                             guid=guid, published=published)


        def atom03_entry(self, elem):
            ns = '{http://purl.org/atom/ns#}'

            title = typedtext(elem.find(ns + 'title'))
            descr = typedtext(findelem(elem.findall(ns + 'summary') +
                                       elem.findall(ns + 'content'),
                                       'type', ['html', 'xhtml', 'text'],
                                       'text'))
            link = findattr(elem.findall(ns + 'link'),
                            'href', 'rel',
                            ['via', 'related', 'enclosure', 'alternate'],
                            'alternate')
            guid = elem.findtext(ns + 'id')
            published = parse_dateTime(elem.findtext(ns + 'created') or \
                                           elem.findtext(ns + 'modified') or \
                                           None)

            self.elements.append(Data(title=title, descr=descr, link=link,
                                      guid=guid, published=published))
            return False

        def atom10_feed_start(self, elem):
            self.__element_handler = {
                '{http://www.w3.org/2005/Atom}entry' :
                    self.atom10_entry,
                '{http://www.w3.org/2005/Atom}title' :
                    self.keep_elem,
                '{http://www.w3.org/2005/Atom}link' :
                    self.keep_elem,
                '{http://www.w3.org/2005/Atom}subtitle' :
                    self.keep_elem,
                '{http://www.w3.org/2005/Atom}id' :
                    self.keep_elem,
                '{http://www.w3.org/2005/Atom}updated' :
                    self.keep_elem,
                }

        def atom10_feed_end(self, elem):
            ns = '{http://www.w3.org/2005/Atom}'

            title = typedtext(elem.find(ns + 'title'))
            descr = typedtext(elem.find(ns + 'subtitle'))
            link = findattr(elem.findall(ns + 'link'),
                            'href', 'rel',
                            ['via', 'related', 'enclosure', 'alternate'],
                            'alternate')
            guid = elem.findtext(ns + 'id')
            published = parse_dateTime(elem.findtext(ns + 'published') or \
                                           elem.findtext(ns + 'updated') or \
                                           None)

            self.info = Data(title=title, descr=descr, link=link,
                             guid=guid, published=published)


        def atom10_entry(self, elem):
            ns = '{http://www.w3.org/2005/Atom}'

            title = typedtext(elem.find(ns + 'title'))
            descr = typedtext(findelem(elem.findall(ns + 'summary') +
                                       elem.findall(ns + 'content'),
                                       'type', ['html', 'xhtml', 'text'],
                                       'text'))
            link = findattr(elem.findall(ns + 'link'),
                            'href', 'rel',
                            ['via', 'related', 'enclosure', 'alternate'],
                            'alternate')
            guid = elem.findtext(ns + 'id')
            published = parse_dateTime(elem.findtext(ns + 'published') or \
                                           elem.findtext(ns + 'updated') or \
                                           None)

            self.elements.append(Data(title=title, descr=descr, link=link,
                                      guid=guid, published=published))
            return False


        def rss_start(self, elem):
            self.__element_handler = {
                'channel' :
                    self.keep_elem,
                '{http://purl.org/rss/1.0/}channel' :
                    self.keep_elem,
                '{http://purl.org/rss/2.0/}channel' :
                    self.keep_elem,
                '{http://backend.userland.com/rss2}channel' :
                    self.keep_elem,
                '{http://my.netscape.com/publish/formats/rss-0.91.dtd}channel' :
                    self.keep_elem,
                '{http://my.netscape.com/rdf/simple/0.9/}channel' :
                    self.keep_elem,

                'item' :
                    self.rss_entry,
                '{http://purl.org/rss/1.0/}item' :
                    self.rss_entry,
                '{http://purl.org/rss/2.0/}item' :
                    self.rss_entry,
                '{http://backend.userland.com/rss2}item' :
                    self.rss_entry,
                '{http://my.netscape.com/publish/formats/rss-0.91.dtd}item' :
                    self.rss_entry,
                '{http://my.netscape.com/rdf/simple/0.9/}item' :
                    self.rss_entry,
                }

        def rss_end(self, elem):
            channel = findtag(elem,
                              ('channel',
                               '{http://backend.userland.com/rss2}channel',
                               '{http://purl.org/rss/1.0/}channel',
                               '{http://purl.org/rss/2.0/}channel',
                               '{http://my.netscape.com/publish/formats/rss-0.91.dtd}channel',
                               '{http://my.netscape.com/rdf/simple/0.9/}channel'))

            if channel != None:
                if channel.tag[0] == '{':
                    ns = channel.tag.split('}')[0] + '}'
                else:
                    ns = ''

                title = htmlelem2plain(channel.find(ns + 'title'))
                descr = htmlelem2plain(channel.find(ns + 'description'))
                link = channel.findtext(ns + 'link')
                guid = channel.get('{http://www.w3.org/1999/02/22-rdf-syntax-ns#}about', None)
                published = parse_dateTime(channel.findtext('{http://purl.org/dc/elements/1.1/}date')) or \
                    parse_Rfc822DateTime(channel.findtext(ns + 'lastBuildDate')) or \
                    None

                self.info = Data(title=title, descr=descr, link=link,
                                 guid=guid, published=published)

        def rss_entry(self, elem):
            if elem.tag[0] == '{':
                ns = elem.tag.split('}')[0] + '}'
            else:
                ns = ''

            title = htmlelem2plain(elem.find(ns + 'title'))
            descr = htmlelem2plain(elem.find(ns + 'description'))
            link = elem.findtext('{http://www.pheedo.com/namespace/pheedo}origLink') or \
                elem.findtext('{http://rssnamespace.org/feedburner/ext/1.0}origLink') or \
                elem.findtext(ns + 'link')

            enclosure = elem.find(ns + 'enclosure')
            if enclosure != None and enclosure.get('url', ''):
                if not link or enclosure.get('type', '') in ('audio/mpeg',):
                    # prioritise certain types of enclosures
                    link = enclosure.get('url', '')

            if link == None:
                link = ''

            guid = elem.get('{http://www.w3.org/1999/02/22-rdf-syntax-ns#}about', None) or \
                elem.findtext(ns + 'guid')

            published = parse_dateTime(elem.findtext('{http://purl.org/dc/elements/1.1/}date')) or \
                parse_Rfc822DateTime(elem.findtext(ns + 'pubDate')) or \
                None

            self.elements.append(Data(title=title, descr=descr, link=link,
                                      guid=guid, published=published))
            return False


        def rss11_start(self, elem):
            self.__element_handler = {
                '{http://purl.org/net/rss1.1#}title' :
                    self.keep_elem,
                '{http://purl.org/net/rss1.1#}link' :
                    self.keep_elem,
                '{http://purl.org/net/rss1.1#}description' :
                    self.keep_elem,

                '{http://purl.org/net/rss1.1#}item' :
                    self.rss11_entry,
                }

        def rss11_end(self, elem):
            ns = '{http://purl.org/net/rss1.1#}'

            title = elem.findtext(ns + 'title') or ''
            descr = elem.findtext(ns + 'description') or ''
            link = elem.findtext(ns + 'link') or ''
            guid = None
            published = None

            self.info = Data(title=title, descr=descr, link=link,
                             guid=guid, published=published)

        def rss11_entry(self, elem):
            ns = '{http://purl.org/net/rss1.1#}'

            title = elem.findtext(ns + 'title') or ''
            descr = elem.findtext(ns + 'description') or ''
            link = elem.findtext(ns + 'link') or ''
            guid = elem.get('{http://www.w3.org/1999/02/22-rdf-syntax-ns#}about', None)
            published = None

            self.elements.append(Data(title=title, descr=descr, link=link,
                                      guid=guid, published=published))
            return False

    class HtmlLinkParser(HTMLParser):
        def __init__(self):
            HTMLParser.__init__(self)
            self.redirect_url, self.info, self.elements = None, None, []

        def close(self):
            HTMLParser.close(self)

            if not self.redirect_url:
                raise FeedError('No RSS autodiscovery links found in html')

        def handle_starttag(self, tag, attrs):
            if tag == 'link' and self.redirect_url == None:
                dattrs = dict(attrs)
                if (dattrs.get('rel') == 'alternate' and
                    dattrs.get('type') in ('application/atom+xml', 'application/rdf+xml', 'application/rss+xml')):
                    self.redirect_url = dattrs.get('href')
                    self.info = Data(title=dattrs.get('title', ''),
                                     descr='', link=self.redirect_url,
                                     guid=None, published=None)
            elif tag == 'body' and not self.redirect_url:
                raise FeedError('No RSS autodiscovery links found in html')

        def handle_startendtag(self, tag, attrs):
            return self.handle_starttag(tag, attrs)

        def handle_endtag(self, tag):
            if tag == 'head' and not self.redirect_url:
                raise FeedError('No RSS autodiscovery links found in html')


    def __init__(self, base_url, encoding):
        self.__buf = []
        self.__base_url = base_url
        self.__handler = Feed_Parser.Handler()
        if hasattr(XMLParser, 'feed_error_log'):
            self.__parser = XMLParser(target=self.__handler, recover=True, encoding=encoding)
        else:
            self.__parser = XMLParser(target=self.__handler, encoding=encoding)


    def get_error_log(self):
        if hasattr(self.__parser, 'feed_error_log'):
            return self.__parser.feed_error_log
        return None

    def get_info(self):
        return self.__handler.info

    def get_items(self):
        return self.__handler.elements

    def get_redirect_url(self):
        return self.__handler.redirect_url


    def __resolve_link(self, url):
        return urljoin('%s://%s/%s' % (self.__base_url), url)

    def __retry_as_html(self):
        self.__handler = Feed_Parser.HtmlLinkParser()
        self.__parser = self.__handler

        for data in self.__buf:
            self.__parser.feed(data.decode('iso8859-1'))
        self.__buf = None


    def feed(self, data):
        try:
            try:
                res = self.__parser.feed(data)
            finally:
                if self.__buf != None:
                    self.__buf.append(data)
        except RetryAsHtml:
            self.__retry_as_html()

    def close(self):
        try:
            self.__parser.close()
            elem = self.__handler.close()
        except RetryAsHtml:
            self.__retry_as_html()
            elem = None

        info = self.__handler.info
        if info != None:
            info.link = self.__resolve_link(info.link)
        else:
            raise Exception('No feed information found')

        redirect_url = self.__handler.redirect_url
        if redirect_url != None:
            self.__handler.redirect_url = self.__resolve_link(redirect_url)

        for item in self.__handler.elements:
            item.link = self.__resolve_link(item.link)

        return elem


def default_redirect_cb(redirect_url, db, redirect_count,
                        generate_id, connect_timeout, timeout):
    resource_url = RSS_Resource_simplify(redirect_url)
    while resource_url != None:
        redirect_resource = RSS_Resource(resource_url, db, generate_id, connect_timeout, timeout)
        resource_url, redirect_seq = redirect_resource.redirect_info(db)

    new_items, next_item_id, redirect_target, redirect_seq, redirects = redirect_resource.update(db, redirect_count)

    if len(new_items) > 0:
        redirects.insert(0, (redirect_resource, new_items, next_item_id))

    if redirect_target != None:
        redirect_resource = redirect_target

    return redirect_resource, redirects


@functools.total_ordering
class RSS_Resource:
    NR_ITEMS = 64

    _db_sync = Null_Synchronizer()
    http_proxy = None


    def __init__(self, url, res_db=None, generate_id=None,
                 connect_timeout=30, timeout=20):
        self._lock = threading.Lock()
        self._url = url
        self._url_protocol, self._url_host, self._url_path = split_url(url)
        self._generate_id = generate_id
        self._connect_timeout, self._timeout = connect_timeout, timeout

        self._id = None
        self._last_updated, self._last_modified = None, None
        self._etag = None
        self._invalid_since, self._err_info = None, None
        self._redirect, self._redirect_seq = None, None
        self._penalty = 0
        title, description, link = None, None, None

        if res_db == None:
            db = RSS_Resource_db()
        else:
            db = res_db

        with Cursor(db) as cursor:
            result = cursor.execute('SELECT rid, last_updated, last_modified, etag, invalid_since, redirect, redirect_seq, penalty, err_info, title, description, link FROM resource WHERE url=?',
                                    (self._url,))
            for row in result:
                self._id, self._last_updated, self._last_modified, self._etag, self._invalid_since, self._redirect, self._redirect_seq, self._penalty, self._err_info, title, description, link = row

            if self._id == None:
                if generate_id == None:
                    cursor.execute('INSERT INTO resource (url) VALUES (?)',
                                   (self._url,))
                    self._id = cursor.lastrowid
                else:
                    for i in range(0, 5):
                        try:
                            id = generate_id()
                            cursor.execute('INSERT INTO resource (rid, url) VALUES (?, ?)',
                                           (id, self._url))
                            self._id = id
                            break
                        except sqlite3.IntegrityError:
                            pass

                    if self._id == None:
                        raise UrlError('Unable to add to database')

            if self._last_updated == None:
                self._last_updated = 0

            if self._penalty == None:
                self._penalty = 0

            if title == None:
                title = self._url
            if link == None:
                link = ''
            if description == None:
                description = ''

            self._channel_info = Data(title=title, link=link, descr=description)

            self._history = []
            result = cursor.execute('SELECT time_items0, time_items1, time_items2, time_items3, time_items4, time_items5, time_items6, time_items7, time_items8, time_items9, time_items10, time_items11, time_items12, time_items13, time_items14, time_items15, nr_items0, nr_items1, nr_items2, nr_items3, nr_items4, nr_items5, nr_items6, nr_items7, nr_items8, nr_items9, nr_items10, nr_items11, nr_items12, nr_items13, nr_items14, nr_items15 FROM resource_history WHERE rid=?',
                           (self._id,))
            for row in result:
                history_times = filter(lambda x: x!=None, row[0:16])
                history_nr = filter(lambda x: x!=None, row[16:32])
                self._history = list(zip(history_times, history_nr))
        del db


    def __eq__(self, other):
        return (other != None) and (self._id == other._id)

    def __lt__(self, other):
        return (other != None) and (self._id < other._id)


    def sync(self):
        return self._lock

    def lock(self):
        self._lock.acquire()

    def unlock(self):
        self._lock.release()


    def url(self):
        return self._url

    def id(self):
        return self._id

    def channel_info(self):
        return self._channel_info

    def times(self):
        last_updated, last_modified, invalid_since = self._last_updated, self._last_modified, self._invalid_since
        if last_modified == None:
            last_modified = 0
    
        return last_updated, last_modified, invalid_since

    def redirect_info(self, res_db=None):
        if self._redirect == None:
            return None, None

        if res_db == None:
            db = RSS_Resource_db()
        else:
            db = res_db

        with Cursor(db) as cursor:
            result = cursor.execute('SELECT url FROM resource WHERE rid=?',
                                    (self._redirect,))
            redirect_url = None
            for row in result:
                redirect_url = row[0]

        return redirect_url, self._redirect_seq

    def penalty(self):
        return self._penalty

    def error_info(self):
        return self._err_info


    def history(self):
        return self._history


    # @return ([item], next_item_id, redirect_resource, redirect_seq, [redirects])
    # locks the resource object if new_items are returned
    def update(self, db=RSS_Resource_db, redirect_count=5,
               redirect_cb=default_redirect_cb):
        now = int(time.time())

        # sanity check update interval
        if now - self._last_updated < 60:
            return [], None, None, None, []

        error_info = None
        nr_new_items = 0
        feed_xml_downloaded = False
        feed_xml_changed = False
        first_item_id = None
        items = []

        prev_updated = self._last_updated
        self._last_updated = now

        if not self._invalid_since:
            # expect the worst, will be reset later
            self._invalid_since = now

        sess = requests.Session()
        sess.headers.update({ 'User-Agent' :
                              'JabRSS (http://jabrss.cmeerw.org)' })

        redirect_penalty = 0
        redirect_tries = redirect_count
        redirect_permanent = True
        redirect_resource = None
        redirect_seq = None
        redirects = []

        with Cursor(db) as cursor:
            try:
                url_protocol, url_host, url_path = self._url_protocol, self._url_host, self._url_path
                logger.debug('updating %s://%s%s' % (url_protocol, url_host, url_path))

                while redirect_tries > 0:
                    redirect_tries = -(redirect_tries - 1)

                    if redirect_permanent:
                        redirect_url = url_protocol + '://' + url_host + url_path
                        if redirect_url != self._url:
                            redirect_resource, redirects = redirect_cb(redirect_url, db, -redirect_tries + 1, self._generate_id, self._connect_timeout, self._timeout)

                            # only perform the redirect if target is valid
                            if redirect_resource._invalid_since:
                                error_info = redirect_resource._err_info
                                self._last_modified = redirect_resource._last_modified
                                self._etag = redirect_resource._etag
                                redirect_resource = None
                            else:
                                redirect_items, redirect_seq = redirect_resource.get_headlines(0, cursor)

                                items, first_item_id, nr_new_items = self._process_new_items(redirect_items, cursor)
                                del redirect_items

                                self._last_modified, self._etag = None, None

                                self._redirect = redirect_resource._id
                                self._redirect_seq = redirect_seq
                                cursor.execute('UPDATE resource SET redirect=?, redirect_seq=? WHERE rid=?',
                                               (self._redirect,
                                                self._redirect_seq, self._id))

                            break


                    headers = {}
                    if self._last_modified:
                        headers['If-Modified-Since'] = formatdate(self._last_modified, usegmt=True)
                    if self._etag != None:
                        headers['If-None-Match'] = self._etag

                    response = sess.get('%s://%s%s' % (url_protocol, url_host,
                                                       url_path),
                                        allow_redirects=False, stream=True,
                                        timeout=self._connect_timeout)

                    errcode = response.status_code
                    errmsg = response.reason
                    headers = response.headers

                    # check the error code
                    # handle "304 Not Modified"
                    if errcode == 304 or errcode == 412:
                        # RSS resource is valid
                        self._invalid_since = None
                    elif (errcode >= 200) and (errcode < 300):
                        feed_xml_downloaded = True

                        self._last_modified, self._etag = parse_Rfc822DateTime(headers.get('last-modified', None)), headers.get('etag', None)

                        # only use an encoding if it has been explicitly specified
                        charset = list(filter(lambda s: s.startswith('charset='), [ s.strip() for s in headers.get('content-type', '').split(';')[1:] ]))[:1]
                        if charset:
                            encoding = charset[0][len('charset='):]
                        else:
                            encoding = None

                        rss_parser = Feed_Parser((self._url_protocol, self._url_host, self._url_path), encoding)

                        bytes_received = 0
                        bytes_processed = 0
                        xml_started = False
                        file_hash = hashlib.md5()

                        for data in response.iter_content(4096):
                            file_hash.update(data)

                            if not xml_started:
                                data = data.lstrip()
                                if data:
                                    xml_started = True

                            bytes_processed = bytes_processed + len(data)
                            if bytes_processed > 2 * 1024 * 1024:
                                raise ValueError('file exceeds maximum allowed decompressed size')

                            rss_parser.feed(data)

                        response.close()
                        rss_parser.close()

                        redirect_url = rss_parser.get_redirect_url()
                        if redirect_url:
                            logger.info('Following feed autodiscovery to "%s"' % (redirect_url,))
                            url_protocol, url_host, url_path = split_url(redirect_url)
                            redirect_tries = -redirect_tries
                        else:
                            error_log = rss_parser.get_error_log()
                            if error_log:
                                logger.warn('XML parser error log:\n%s' % (error_log,))

                            new_channel_info = normalize_obj(rss_parser.get_info())

                            hash_buffer = buffer(file_hash.digest())
                            cursor.execute('UPDATE resource SET hash=? WHERE rid=? AND (hash IS NULL OR hash<>?)',
                                           (hash_buffer, self._id, hash_buffer))
                            feed_xml_changed = (cursor.rowcount != 0)

                            self._update_channel_info(new_channel_info, cursor)

                            new_items = [ normalize_item(x) for x in rss_parser.get_items() ]
                            new_items.reverse()

                            items, first_item_id, nr_new_items = self._process_new_items(new_items, cursor)
                            del new_items

                    # handle "301 Moved Permanently", "302 Found" and
                    # "307 Temporary Redirect"
                    elif (errcode >= 300) and (errcode < 400):
                        bytes_received = 0
                        for data in response.iter_content(4096):
                            bytes_received = bytes_received + len(data)
                            if bytes_received > 128 * 1024:
                                raise ValueError('file exceeds maximum allowed size')

                        response.close()

                        if errcode != 301:
                            redirect_permanent = False
                            redirect_penalty += 1

                        redirect_url = headers.get('location', None)
                        if redirect_url:
                            base_url = '%s://%s/%s' % (url_protocol, url_host, url_path)
                            redirect_url = urljoin(base_url, redirect_url)
                            logger.info('Following redirect (%d) to "%s"' % (errcode, redirect_url))
                            url_protocol, url_host, url_path = split_url(redirect_url)
                            redirect_tries = -redirect_tries
                        else:
                            error_info = 'HTTP: %d %s' % (errcode, repr(errmsg))
                            logger.warn(error_info + '\n' + str(headers))
                    else:
                        error_info = 'HTTP: %d %s' % (errcode, repr(errmsg))
                        logger.warn(error_info + '\n' + str(headers))

                if self._invalid_since and not error_info and redirect_tries == 0:
                    error_info = 'redirect: maximum number of redirects exceeded'
            except socket.timeout as e:
                error_info = 'timeout: ' + str(e)
            except requests.exceptions.HTTPError as e:
                error_info = 'HTTP: ' + str(e)
            except requests.exceptions.ConnectionError as e:
                error_info = 'HTTP connection: ' + str(e)
            except socket.error as e:
                error_info = 'socket: ' + str(e)
            except IOError as e:
                error_info = 'I/O error: ' + str(e)
            except FeedError as e:
                error_info = 'feed: ' + str(e)
            except AssertionError as e:
                error_info = 'assertion: ' + str(e)
            except DecompressorError as e:
                error_info = 'decompressor: ' + str(e)
            except UnicodeError as e:
                error_info = 'encoding: ' + str(e)
            except LookupError as e:
                error_info = 'encoding: ' + str(e)
            except ValueError as e:
                error_info = 'misc: ' + str(e)
            except HTMLParseError as e:
                error_info = 'html: ' + str(e)
            except:
                traceback.print_exc(file=sys.stdout)

            if error_info:
                logger.warn('Error: %s' % (error_info,))

            if error_info != self._err_info:
                self._err_info = error_info
                cursor.execute('UPDATE resource SET err_info=? WHERE rid=?',
                               (self._err_info, self._id))

            if not self._invalid_since:
                if feed_xml_downloaded:
                    if nr_new_items > 0:
                        # downloaded and new items available, good
                        self._penalty = (5 * self._penalty) // 6
                    elif not feed_xml_changed:
                        # downloaded, but not changed, very bad
                        self._penalty = (3 * self._penalty) // 4 + 256
                    else:
                        # downloaded and changed, but no new items, bad
                        self._penalty = (15 * self._penalty) // 16 + 64
                else:
                    # "not modified" response from server, good
                    self._penalty = (3 * self._penalty) // 4

            if redirect_penalty > 0:
                # penalty for temporary redirects
                self._penalty = (7 * self._penalty) // 8 + 128


            cursor.execute('UPDATE resource SET last_modified=?, last_updated=?, etag=?, invalid_since=?, penalty=? WHERE rid=?',
                           (self._last_modified, self._last_updated, self._etag,
                            self._invalid_since, self._penalty, self._id))

        if nr_new_items:
            new_items = items[-nr_new_items:]
            next_item_id = first_item_id + len(items)
        else:
            new_items = []
            next_item_id = None

        return new_items, next_item_id, redirect_resource, redirect_seq, redirects


    def _update_channel_info(self, new_channel_info, cursor):
        if self._channel_info != new_channel_info:
            self._channel_info = new_channel_info

            cursor.execute('UPDATE resource SET title=?, link=?, description=? WHERE rid=?',
                           (self._channel_info.title,
                            self._channel_info.link,
                            self._channel_info.descr,
                            self._id))


    # @return ([item], first_item_id, nr_new_items)
    def _process_new_items(self, new_items, cursor):
        items, next_item_id = self.get_headlines(0, cursor)
        first_item_id = next_item_id - len(items)

        nr_new_items = self._update_items(items, new_items)
        del new_items

        if nr_new_items:
            # we must not have any other objects locked when trying to lock
            # a resource
            cursor.commit()
            self.lock()
            cleanup = CleanupOnError(self.unlock)
        else:
            cleanup = CleanupOnError()

        with cleanup:
            cursor.begin()
    
            if len(items) > RSS_Resource.NR_ITEMS:
                first_item_id += len(items) - RSS_Resource.NR_ITEMS
                del items[:-RSS_Resource.NR_ITEMS]
                cursor.execute('DELETE FROM resource_data WHERE rid=? AND seq_nr<?',
                               (self._id, first_item_id))
    
            # RSS resource is valid
            self._invalid_since = None
    
            if nr_new_items:
                # update history information
                self._history.append((int(time.time()), nr_new_items))
                self._history = self._history[-16:]
    
                history_times = [ x[0] for x in self._history ]
                if len(history_times) < 16:
                    history_times += (16 - len(history_times)) * [None]
    
                history_nr = [ x[1] for x in self._history ]
                if len(history_nr) < 16:
                    history_nr += (16 - len(history_nr)) * [None]
    
                cursor.execute('INSERT INTO resource_history (rid, time_items0, time_items1, time_items2, time_items3, time_items4, time_items5, time_items6, time_items7, time_items8, time_items9, time_items10, time_items11, time_items12, time_items13, time_items14, time_items15, nr_items0, nr_items1, nr_items2, nr_items3, nr_items4, nr_items5, nr_items6, nr_items7, nr_items8, nr_items9, nr_items10, nr_items11, nr_items12, nr_items13, nr_items14, nr_items15) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                               tuple([self._id] + history_times + history_nr))
    
                i = first_item_id
                for item in items:
                    cursor.execute('INSERT INTO resource_data (rid, seq_nr, published, title, link, guid, descr_plain, descr_xhtml) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                                   (self._id, i,
                                    item.published, item.title, item.link,
                                    item.guid, item.descr_plain, item.descr_xhtml))
                    i += 1
    
            return items, first_item_id, nr_new_items


    # @return nr_new_items
    def _update_items(self, items, new_items):
        nr_old_items = len(items)
        nr_new_items = 0

        tstamplist = list(filter(lambda x: x != None,
                                 [ x.published for x in items ]))
        tstamplist.sort()

        if (len(tstamplist) > 4) and (len(new_items) > RSS_Resource.NR_ITEMS):
            tstamplist = tstamplist[len(tstamplist) // 2 : -len(tstamplist) // 6]
            cutoff = sum(tstamplist) // len(tstamplist)
        elif len(tstamplist) > 2:
            cutoff = tstamplist[0]
        else:
            cutoff = 0

        new_items = list(filter(lambda x: (x.published == None) or (x.published >= cutoff), new_items))
        new_items.sort(key=lambda x: x.published or 0)

        for item in new_items:
            found = False

            for i in range(0, len(items)):
                if compare_items(items[i], item):
                    items[i] = item
                    found = True

            if not found:
                items.append(item)
                nr_new_items = nr_new_items + 1

        return nr_new_items


    # @return ([item], next id)
    def get_headlines(self, first_id, db_cursor=None, db=RSS_Resource_db):
        with Cursor(db, db_cursor) as cursor:
            if first_id == None:
                first_id = 0

            result = cursor.execute('SELECT seq_nr, published, title, link, guid, descr_plain, descr_xhtml FROM resource_data WHERE rid=? AND seq_nr>=? ORDER BY seq_nr',
                                    (self._id, first_id))
            items = []
            last_id = first_id
            for seq_nr, published, title, link, guid, descr_plain, descr_xhtml in result:
                if seq_nr >= last_id:
                    last_id = seq_nr + 1
                items.append(Data(published=published, title=title, link=link,
                                  guid=guid, descr_plain=descr_plain,
                                  descr_xhtml=descr_xhtml))

        return items, last_id


    def next_update(self, randomize=True):
        min_interval = MIN_INTERVAL
        max_interval = MAX_INTERVAL

        if len(self._history) >= 2:
            hist_items = len(self._history)

            sum_items = 0
            for h in self._history[1:]:
                sum_items += h[1]
            time_span = self._last_updated - self._history[0][0]

            if hist_items >= 12:
                time_span_old = self._history[hist_items // 2][0] - self._history[0][0]
                sum_items_old = 0
                for h in self._history[1:hist_items // 2 + 1]:
                    sum_items_old += h[1]

                if (3 * sum_items_old < sum_items) and (5 * time_span_old < time_span):
                    time_span = time_span_old
                    sum_items = sum_items_old
                # sum_items_new = sum_items - sum_items_old
                elif (3 * sum_items_old > 2 * sum_items) and (5 * time_span_old > 4 * time_span):
                    time_span = time_span - time_span_old
                    sum_items = sum_items - sum_items_old

            interval = time_span // sum_items // INTERVAL_DIVIDER

            # apply a bonus for well-behaved feeds
            interval = 32 * interval // (64 - self._penalty // 28)
            max_interval = 32 * max_interval // (64 - self._penalty // 28)
            min_interval = 32 * min_interval // (48 - self._penalty // 64)
        elif len(self._history) == 1:
            time_span = self._last_updated - self._history[0][0]

            interval = 30*60 + time_span // 3
            min_interval = 60*60
        elif self._invalid_since:
            time_span = self._last_updated - self._invalid_since

            interval = 4*60*60 + time_span // 4
            max_interval = 48*60*60
        else:
            interval = 8*60*60

        if self._url.lower().find('slashdot.org') != -1:
            # yes, slashdot sucks - this is a special slashdot
            # throttle to avaoid being banned by slashdot
            interval = interval + 150*60

        # apply upper and lower bounds to the interval
        interval = min(max_interval, max(min_interval, interval))

        # and add some random factor
        if randomize:
            return self._last_updated + interval + int(random.normalvariate(30, 50 + interval // 50))
        else:
            return self._last_updated + interval


def RSS_Resource_id2url(res_id, db_cursor=None):
    with Cursor(RSS_Resource_db) as cursor:
        url = None
        result = cursor.execute('SELECT url FROM resource WHERE rid=?',
                                (res_id,))
        for row in result:
            url = row[0]

    if url == None:
        raise KeyError(res_id)

    return url


def RSS_Resource_simplify(url):
    url_protocol, url_host, url_path = split_url(url)
    simple_url = '%s://%s%s' % (url_protocol, url_host, url_path)
    return url


if __name__ == '__main__':
    import locale, sys

    if sys.version_info[0] == 2:
        encoding = locale.getlocale()[1]
        if not encoding:
            encoding = 'us-ascii'
        sys.stdout = codecs.getwriter(encoding)(sys.stdout, errors='replace')
        sys.stderr = codecs.getwriter(encoding)(sys.stderr, errors='replace')

    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)

    init_parserss()
    db = RSS_Resource_db()

    for url in sys.argv[1:]:
        while url != None:
            resource = RSS_Resource(url, db)
            url, seqnr = resource.redirect_info(db)

        new_items, next_item_id, redirect_resource, redirect_seq, redirects = resource.update(db)
        channel_info = resource.channel_info()
        print('%s %s %s' % (channel_info.title, channel_info.link, channel_info.descr))
        error_info = resource.error_info()
        if error_info:
            print('error info %s' % (error_info))

        if len(new_items) > 0:
            print('new items (next id: %d):\n  %s' %
                  (next_item_id,
                   '\n  '.join(['%s - %s' % (x.title, x.link) for x in new_items])))

    db.close()
    del db
