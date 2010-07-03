#!/usr/bin/python
# Copyright (C) 2001-2010, Christof Meerwald
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

import codecs, hashlib, logging, rfc822, os, random, re, socket, string, struct
import sys, time, threading, traceback, types, zlib
import sqlite3

from array import array

import warnings
warnings.filterwarnings('ignore',
                        category=DeprecationWarning,
                        message='The xmllib module is obsolete.  Use xml.sax instead.')
import xmllib

if sys.version_info[0] == 2:
    import httplib
else:
    import http.client as httplib


logger = logging.getLogger('parserss')


__all__ = [
    'RSS_Resource', 'RSS_Resource_id2url', 'RSS_Resource_simplify'
    'RSS_Resource_db', 'RSS_Resource_Cursor',
    'UrlError', 'init_parserss',
]

re_validprotocol = re.compile('^(?P<protocol>[a-z]+):(?P<rest>.*)$')

re_validhost = re.compile('^(?P<host>[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+)(:(?P<port>[0-9a-z]+))?(?P<path>(/.*)?)$')
re_blockhost = re.compile('^(10\.|127\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.)')

re_spliturl = re.compile('^(?P<protocol>[a-z]+)://(?P<host>[^/]+)(?P<path>/?.*)$')

str_trans = string.maketrans(
    '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
    '\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f',
    '          \x0a                     ')

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
DB_FILENAME = 'jabrss_res.db'

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
    mo = re_validprotocol.match(url)
    if not mo:
        raise UrlError('can\'t parse protocol of URL "%s"' % (url,))

    url_protocol, url_rest = mo.group('protocol', 'rest')

    if url_rest[:2] != '//':
        raise UrlError('missing "//" after "%s:"' % (url_protocol,))

    url_rest = url_rest[2:]
    mo = re_validhost.match(url_rest)
    if not mo:
        raise UrlError('invalid host in URL "%s"' % (url,))

    url_host, url_port, url_path = mo.group('host', 'port', 'path')

    url_host = url_host.lower()

    if url_protocol == 'http':
        if (url_port != '80') and (url_port != 'http') and (url_port != None):
            raise UrlError('http ports != 80 not allowed')
    elif url_protocol == 'https':
        if (url_port != '443') and (url_port != 'https') and (url_port != None):
            raise UrlError('https ports != 443 not allowed')
    else:
        raise UrlError('unsupported protocol "%s"' % (url_protocol))

    if url_path == '':
        url_path = '/'

    while url_path[:2] == '//':
        url_path = url_path[1:]

    if re_blockhost.match(url_host):
        raise UrlError('host "%s" not allowed' % (url_host,))

    return url_protocol, url_host, url_path


def normalize_text(s):
    if type(s) == types.UnicodeType:
        s = s.translate(unicode_trans)
    else:
        s = s.translate(str_trans)

    s = '\n'.join(filter(lambda x: x != '', map(lambda x: x.strip(), s.split('\n'))))
    s = ' '.join(filter(lambda x: x != '', s.split(' ')))
    return s

def normalize_obj(o):
    for attr in dir(o):
        if attr[0] != '_':
            value = getattr(o, attr)
            if type(value) in types.StringTypes:
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

    del item.descr

    return item


re_dateTime = re.compile('^(?P<year>[1-9][0-9][0-9][0-9])-(?P<month>[01][0-9])-(?P<day>[0-3][0-9])T(?P<hour>[0-2][0-9]):(?P<min>[0-6][0-9]):(?P<sec>[0-6][0-9])(\\.[0-9]+)?(Z|(?P<tzsign>[-+])(?P<tzhour>[01][0-9]):(?P<tzmin>[0-6][0-9]))$')

def parse_dateTime(s):
    if s == None:
        return None

    mo = re_dateTime.match(s)
    if mo != None:
        year, month, day, hour, min, sec = map(lambda x: string.atoi(x), mo.group('year', 'month', 'day', 'hour', 'min', 'sec'))

        tzsign, tzhour, tzmin = mo.group('tzsign', 'tzhour', 'tzmin')
        if tzhour != None and tzmin != None:
            tzoff = 60*(60*string.atoi(tzhour) + string.atoi(tzmin))
        else:
            tzoff = 0

        if tzsign == '-':
            tzoff = -tzoff

        tstamp = int(rfc822.mktime_tz((year, month, day, hour, min, sec, 0, 0, 0, tzoff)))
    else:
        tstamp = None

    return tstamp

def parse_Rfc822DateTime(s):
    if s == None:
        return None

    try:
        tstamp = int(rfc822.mktime_tz(rfc822.parsedate_tz(s)))
    except:
        tstamp = None

    return tstamp


def compare_items(l, r):
    lguid, ltitle, llink = l.guid, l.title, l.link
    rguid, rtitle, rlink = r.guid, r.title, r.link

    if ltitle == rtitle:
        if (lguid != None) and (rguid != None):
            return lguid == rguid

        lmo = re_spliturl.match(llink)
        rmo = re_spliturl.match(rlink)

        if lmo and rmo:
            lprotocol, lhost, lpath = lmo.group('protocol', 'host', 'path')
            rprotocol, rhost, rpath = rmo.group('protocol', 'host', 'path')

            if lprotocol == rprotocol and lpath == rpath:
                lhostparts = string.split(string.lower(lhost), '.')
                if lhostparts[-1] == '':
                    del lhostparts[-1]

                rhostparts = string.split(string.lower(rhost), '.')
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
            return llink == rlink
    else:
        return 0


class Cursor:
    def __init__(self, _db):
        self._txn = False
        self._locked = False
        self._cursor = _db.cursor()

        self._locked = True
        RSS_Resource._db_sync.acquire()

    def __del__(self):
        try:
            if self._txn:
                self._cursor.execute('COMMIT')
                pass
        finally:
            if self._locked:
                RSS_Resource._db_sync.release()


    def unlock(self):
        if self._txn:
            self._cursor.execute('COMMIT')
            self._txn = False

        if self._locked:
            RSS_Resource._db_sync.release()
            self._locked = False

    def lock(self):
        if not self._locked:
            RSS_Resource._db_sync.acquire()
            self._locked = True

    def begin(self):
        self.lock()

        if not self._txn:
            self._cursor.execute('BEGIN')
            self._txn = True

    def execute(self, stmt, bindings=None):
        self.lock()

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


class HTTPConnection(httplib.HTTPConnection):
    def __init__(self, host, port=None, strict=None,
                 timeout=socket.getdefaulttimeout(),
                 read_timeout=socket.getdefaulttimeout()):
        httplib.HTTPConnection.__init__(self, host, port=port, strict=strict)
        self.timeout = timeout
        self.__read_timeout = read_timeout

    def connect(self):
        httplib.HTTPConnection.connect(self)
        self.sock.settimeout(self.__read_timeout)

    def putrequest(self, method, url):
        self._http_vsn = 10
        httplib.HTTPConnection.putrequest(self, method, url, True)
        self._http_vsn = 11


class HTTPSConnection(httplib.HTTPSConnection):
    def __init__(self, host, port=None, strict=None,
                 timeout=socket.getdefaulttimeout(),
                 read_timeout=socket.getdefaulttimeout()):
        httplib.HTTPSConnection.__init__(self, host, port=port, strict=strict)
        self.timeout = timeout
        self.__read_timeout = read_timeout

    def connect(self):
        httplib.HTTPSConnection.connect(self)
        self.sock.settimeout(self.__read_timeout)

    def putrequest(self, method, url):
        self._http_vsn = 10
        httplib.HTTPConnection.putrequest(self, method, url, True)
        self._http_vsn = 11


class DecompressorError(ValueError):
    pass

class Null_Decompressor:
    def feed(self, s):
        return s

    def flush(self):
        return ''


class Deflate_Decompressor:
    def __init__(self):
        self._adler32 = zlib.adler32('')
        self._raw_deflate = False

        self._decompress = zlib.decompressobj()
        self._buffer = ''

        self._state_feed = Deflate_Decompressor._feed_header

    def _update_adler32(self, data):
        self._adler32 = zlib.adler32(data, self._adler32)


    def feed(self, s):
        self._buffer = self._buffer + s
        data = ''

        while self._state_feed and len(self._buffer):
            res = self._state_feed(self)

            if res:
                self._update_adler32(res)
                data += res

            if res != None:
                break

        return data

    def flush(self):
        data = ''

        while self._state_feed:
            res = self._state_feed(self)

            if res:
                self._update_adler32(res)
                data += res
            elif res == '' and self._state_feed != None:
                raise IOError('premature EOF')

        if len(self._buffer):
            raise IOError('extra data at end of compressed data')

        return data


    def _feed_header(self):
        if len(self._buffer) >= 2:
            header = self._buffer[:2]
            header_int = struct.unpack('>H', header)[0]
            if header_int % 31 != 0:
                self._raw_deflate = True
                self._buffer = '\x78\x9c' + self._buffer

            self._state_feed = Deflate_Decompressor._feed_data
            return None

        # need more data
        return ''

    def _feed_data(self):
        if len(self._buffer) > 0:
            data = self._decompress.decompress(self._buffer)
            self._buffer = self._decompress.unused_data
        else:
            data = self._decompress.flush()
            self._buffer = self._decompress.unused_data
            self._state_feed = Deflate_Decompressor._feed_eof

            if not data:
                return None

        if self._buffer:
            self._state_feed = Deflate_Decompressor._feed_eof
            if not data:
                return None

        return data

    def _feed_eof(self):
        self._state_feed = None
        return ''


class Gzip_Decompressor:
    FTEXT, FHCRC, FEXTRA, FNAME, FCOMMENT = 1, 2, 4, 8, 16

    def __init__(self):
        self._crc = zlib.crc32('')
        self._size = 0

        self._decompress = zlib.decompressobj(-zlib.MAX_WBITS)
        self._header_flag = 0
        self._buffer = ''

        self._state_feed = Gzip_Decompressor._feed_header_static

    def _update_crc32(self, data):
        self._crc = zlib.crc32(data, self._crc)
        self._size = self._size + len(data)

    def feed(self, s):
        self._buffer = self._buffer + s
        data = ''

        while self._state_feed and len(self._buffer):
            res = self._state_feed(self)

            if res:
                self._update_crc32(res)
                data += res

            if res != None:
                break

        return data

    def flush(self):
        data = ''

        while self._state_feed:
            res = self._state_feed(self)

            if res:
                self._update_crc32(res)
                data += res
            elif res == '' and self._state_feed != None:
                raise IOError('premature EOF')

        if len(self._buffer):
            raise IOError('extra data at end of compressed data')

        return data

    def _feed_header_static(self):
        if len(self._buffer) >= 10:
            magic = self._buffer[:2]
            if magic != '\037\213':
                raise IOError('Not a gzipped file')
            method = ord(self._buffer[2])
            if method != 8:
                raise IOError('Unknown compression method')
            self._header_flag = ord(self._buffer[3])
            # modtime = self.fileobj.read(4)
            # extraflag = self.fileobj.read(1)
            # os = self.fileobj.read(1)
            self._buffer = self._buffer[10:]

            self._state_feed = Gzip_Decompressor._feed_header_flags
            return None

        # need more data
        return ''

    def _feed_header_flags(self):
        if self._header_flag & Gzip_Decompressor.FEXTRA:
            if len(self._buffer) >= 2:
                # Read & discard the extra field, if present
                xlen = struct.unpack('<H', self._buffer[:2])[0]
                if len(self._buffer) >= (2 + xlen):
                    self._buffer = self._buffer[2 + xlen:]
                    self._header_flag = self._header_flag & ~Gzip_Decompressor.FEXTRA
                    return None
        elif self._header_flag & Gzip_Decompressor.FNAME:
            # Read and discard a null-terminated string containing the filename
            pos = string.find(self._buffer, '\0')
            if pos != -1:
                self._buffer = self._buffer[pos + 1:]
                self._header_flag = self._header_flag & ~Gzip_Decompressor.FNAME
                return None
        elif self._header_flag & Gzip_Decompressor.FCOMMENT:
            # Read and discard a null-terminated string containing a comment
            pos = string.find(self._buffer, '\0')
            if pos != -1:
                self._buffer = self._buffer[pos + 1:]
                self._header_flag = self._header_flag & ~Gzip_Decompressor.FCOMMENT
                return None
        elif self._header_flag & Gzip_Decompressor.FHCRC:
            if len(self._buffer) >= 2:
                self._buffer = self._buffer[2:]
                self._header_flag = self._header_flag & ~Gzip_Decompressor.FHCRC
                return None
        else:
            self._state_feed = Gzip_Decompressor._feed_data
            return None

        # need more data
        return ''

    def _feed_data(self):
        if len(self._buffer) > 0:
            data = self._decompress.decompress(self._buffer)
            self._buffer = self._decompress.unused_data
        else:
            data = self._decompress.flush()
            self._buffer = self._decompress.unused_data
            self._state_feed = Gzip_Decompressor._feed_eof

            if not data:
                return None

        if self._buffer:
            self._state_feed = Gzip_Decompressor._feed_eof
            if not data:
                return None

        return data

    def _feed_eof(self):
        if len(self._buffer) >= 8:
            crc32, isize = struct.unpack("<ll", self._buffer[:8])
            if crc32 % 0x100000000 != self._crc % 0x100000000:
                raise DecompressorError('CRC check failed')
            elif isize != self._size:
                raise DecompressorError('Incorrect length of data produced')

            self._buffer = self._buffer[8:]
            self._state_feed = None
        return ''


ENTITIES = {
    'nbsp' : '\xa0',
    'iexcl' : '\xa1',
    'cent' : '\xa2',
    'pound' : '\xa3',
    'curren' : '\xa4',
    'yen' : '\xa5',
    'brvbar' : '\xa6',
    'sect' : '\xa7',
    'uml' : '\xa8',
    'copy' : '\xa9',
    'ordf' : '\xaa',
    'laquo' : '\xab',
    'not' : '\xac',
    'shy' : '\xad',
    'reg' : '\xae',
    'macr' : '\xaf',
    'deg' : '\xb0',
    'plusmn' : '\xb1',
    'sup2' : '\xb2',
    'sup3' : '\xb3',
    'acute' : '\xb4',
    'micro' : '\xb5',
    'para' : '\xb6',
    'middot' : '\xb7',
    'cedil' : '\xb8',
    'sup1' : '\xb9',
    'ordm' : '\xba',
    'raquo' : '\xbb',
    'frac14' : '\xbc',
    'frac12' : '\xbd',
    'frac34' : '\xbe',
    'iquest' : '\xbf',
    'Agrave' : '\xc0',
    'Aacute' : '\xc1',
    'Acirc' : '\xc2',
    'Atilde' : '\xc3',
    'Auml' : '\xc4',
    'Aring' : '\xc5',
    'AElig' : '\xc6',
    'Ccedil' : '\xc7',
    'Egrqave' : '\xc8',
    'Eacute' : '\xc9',
    'Ecirc' : '\xca',
    'Euml' : '\xcb',
    'Igrave' : '\xcc',
    'Iacute' : '\xcd',
    'Icirc' : '\xce',
    'Iuml' : '\xcf',
    'ETH' : '\xd0',
    'Ntilde' : '\xd1',
    'Ograve' : '\xd2',
    'Oacute' : '\xd3',
    'Ocirc' : '\xd4',
    'Otilde' : '\xd5',
    'Ouml' : '\xd6',
    'times' : '\xd7',
    'Oslash' : '\xd8',
    'Ugrave' : '\xd9',
    'Uacute' : '\xda',
    'Ucirc' : '\xdb',
    'Uuml' : '\xdc',
    'Yacute' : '\xdd',
    'THORN' : '\xde',
    'szlig' : '\xdf',
    'agrave' : '\xe0',
    'aacute' : '\xe1',
    'acirc' : '\xe2',
    'atilde' : '\xe3',
    'auml' : '\xe4',
    'aring' : '\xe5',
    'aelig' : '\xe6',
    'ccedil' : '\xe7',
    'egrave' : '\xe8',
    'eacute' : '\xe9',
    'ecirc' : '\xea',
    'euml' : '\xeb',
    'igrave' : '\xec',
    'iacute' : '\xed',
    'icirc' : '\xee',
    'iuml' : '\xef',
    'eth' : '\xf0',
    'ntilde' : '\xf1',
    'ograve' : '\xf2',
    'oacute' : '\xf3',
    'ocirc' : '\xf4',
    'otilde' : '\xf5',
    'ouml' : '\xf6',
    'divide' : '\xf7',
    'oslash' : '\xf8',
    'ugrave' : '\xf9',
    'uacute' : '\xfa',
    'ucirc' : '\xfb',
    'uuml' : '\xfc',
    'yacute' : '\xfd',
    'thorn' : '\xfe',
    'yuml' : '\xff',
    }


class Feed_Parser(xmllib.XMLParser):
    def __init__(self, base_url, charset=None, default_charset=None):
        xmllib.XMLParser.__init__(self, accept_utf8=1)

        self.elements = {
            'http://www.w3.org/1999/02/22-rdf-syntax-ns# RDF' :
            (self.rss_rdf_start, self.rss_rdf_end),
            'rss' :
            (self.rss_rss_start, self.rss_rss_end),
            'http://backend.userland.com/rss2 rss' :
            (self.rss_rss_start, self.rss_rss_end),
            # RSS 0.90, see http://www.purplepages.ie/RSS/netscape/rss0.90.html
            # RSS 0.91, see http://my.netscape.com/publish/formats/rss-spec-0.91.html
            'http://my.netscape.com/rdf/simple/0.9/ rss' :
            (self.rss_rss_start, self.rss_rss_end),
            # non-standard, but allow anyway
            'http://my.netscape.com/rdf/simple/0.91/ rss' :
            (self.rss_rss_start, self.rss_rss_end),
            # RSS 1.0, see http://web.resource.org/rss/1.0/spec
            'http://purl.org/rss/1.0/ rss' :
            (self.rss_rss_start, self.rss_rss_end),
            'http://purl.org/rss/2.0/ rss' :
            (self.rss_rss_start, self.rss_rss_end),
            # Atom 0.3
            'http://purl.org/atom/ns# feed' :
            (self.atom03_feed_start, self.atom03_feed_end),
            # Atom 1.0
            'http://www.w3.org/2005/Atom feed' :
            (self.atom10_feed_start, self.atom10_feed_end),

            # RSS 1.1, see http://inamidst.com/rss1.1/
            'http://purl.org/net/rss1.1# Channel' :
            (self.rss_rss11_start, self.rss_rss11_end)
            }

        self._base_url = base_url
        self._charset = charset
        self._default_charset = default_charset

        self._format = ''
        self._encoding = 'utf-8'
        self._feed_encoding = None
        self._bytes = 0

        self._state = 0
        self._content_mode = None
        self._summary = None

        self._channel = Data(title='', link='', descr='')
        self._items = []

        self._reset_cdata()
        self._set_encoding(None)

    def _set_encoding(self, encoding):
        if not self._feed_encoding:
            if self._charset:
                encoding = self._charset
            elif not encoding:
                if self._default_charset:
                    encoding = self._default_charset

            if encoding:
                encoding = encoding.lower()
                if encoding[:8] == 'windows-':
                    encoding = 'cp' + encoding[8:]

                self._encoding = encoding

    def _get_atom_attr(self, attrs, name):
        for ns in ['', 'http://purl.org/atom/ns# ',
                   'http://www.w3.org/2005/Atom ']:
            if attrs.has_key(ns + name):
                return attrs[ns + name]

        return None

    def handle_xml(self, encoding, standalone):
        self._set_encoding(encoding)

    def resolve_url(self, url):
        if url.startswith('/'):
            return '%s://%s%s' % (self._base_url[0], self._base_url[1],
                                  url.encode('ascii'))
        else:
            return url.encode('ascii')


    def feed(self, data):
        if self._bytes == 0:
            if data[:4] == codecs.BOM64_LE:
                # probably not supported
                self._feed_encoding = 'utf-32-le'
                self._encoding = 'utf-8'
                data = data[4:]
            elif data[:4] == codecs.BOM64_BE:
                # probably not supported
                self._feed_encoding = 'utf-32-be'
                self._encoding = 'utf-8'
                data = data[4:]
            elif data[:3] == '\xef\xbb\xbf':
                self._feed_encoding = None
                self._encoding = 'utf-8'
                data = data[3:]
            elif data[:2] == codecs.BOM32_LE:
                self._feed_encoding = 'utf-16-le'
                self._encoding = 'utf-8'
                data = data[2:]
            elif data[:2] == codecs.BOM32_BE:
                self._feed_encoding = 'utf-16-be'
                self._encoding = 'utf-8'
                data = data[2:]

        self._bytes = self._bytes + len(data)
        if self._feed_encoding:
            data = data.decode(self._feed_encoding).encode('utf-8')

        return xmllib.XMLParser.feed(self, data)


    def rss_rdf_start(self, attrs):
        self._format = 'rdf'
        self.elements.update({
            'http://my.netscape.com/rdf/simple/0.9/ channel' :
            (self.rss_channel_start, self.rss_channel_end),
            'http://purl.org/rss/1.0/ channel' :
            (self.rss_channel_start, self.rss_channel_end),
            'http://purl.org/rss/2.0/ channel' :
            (self.rss_channel_start, self.rss_channel_end),

            'http://my.netscape.com/rdf/simple/0.9/ item' :
            (self.rss_item_start, self.rss_item_end),
            'http://purl.org/rss/1.0/ item' :
            (self.rss_item_start, self.rss_item_end),
            'http://purl.org/rss/2.0/ item' :
            (self.rss_item_start, self.rss_item_end),
            # not strictly conforming...
            'item' :
            (self.rss_item_start, self.rss_item_end),

            'http://my.netscape.com/rdf/simple/0.9/ title' :
            (self.rss_title_start, self.rss_title_end),
            'http://purl.org/dc/elements/1.1/ title' :
            (self.rss_title_start, self.rss_title_end),
            'http://purl.org/rss/1.0/ title' :
            (self.rss_title_start, self.rss_title_end),
            'http://purl.org/rss/2.0/ title' :
            (self.rss_title_start, self.rss_title_end),
            # not strictly conforming...
            'title' :
            (self.rss_title_start, self.rss_title_end),

            'http://my.netscape.com/rdf/simple/0.9/ link' :
            (self.rss_link_start, self.rss_link_end),
            'http://purl.org/rss/1.0/ link' :
            (self.rss_link_start, self.rss_link_end),
            'http://purl.org/rss/2.0/ link' :
            (self.rss_link_start, self.rss_link_end),
            # not strictly conforming...
            'link' :
            (self.rss_link_start, self.rss_link_end),

            'http://my.netscape.com/rdf/simple/0.9/ description' :
            (self.rss_description_start, self.rss_description_end),
            'http://purl.org/dc/elements/1.1/ description' :
            (self.rss_description_start, self.rss_description_end),
            'http://purl.org/rss/1.0/ description' :
            (self.rss_description_start, self.rss_description_end),
            'http://purl.org/rss/2.0/ description' :
            (self.rss_description_start, self.rss_description_end),
            # not strictly conforming...
            'description' :
            (self.rss_description_start, self.rss_description_end),

            'http://purl.org/dc/elements/1.1/ date' :
            (self.rss_date_start, self.rss_date_end)
            })

    def rss_rdf_end(self):
        self.elements = {}


    def rss_rss_start(self, attrs):
        self._format = 'rss'
        self.elements.update({
            'channel' :
            (self.rss_channel_start, self.rss_channel_end),
            'http://backend.userland.com/rss2 channel' :
            (self.rss_channel_start, self.rss_channel_end),
            'http://my.netscape.com/publish/formats/rss-0.91.dtd channel' :
            (self.rss_channel_start, self.rss_channel_end),
            'http://purl.org/rss/1.0/ channel' :
            (self.rss_channel_start, self.rss_channel_end),
            'http://purl.org/rss/2.0/ channel' :
            (self.rss_channel_start, self.rss_channel_end),

            'item' :
            (self.rss_item_start, self.rss_item_end),
            'http://backend.userland.com/rss2 item' :
            (self.rss_item_start, self.rss_item_end),
            'http://my.netscape.com/publish/formats/rss-0.91.dtd item' :
            (self.rss_item_start, self.rss_item_end),
            'http://purl.org/rss/1.0/ item' :
            (self.rss_item_start, self.rss_item_end),
            'http://purl.org/rss/2.0/ item' :
            (self.rss_item_start, self.rss_item_end),

            'title' :
            (self.rss_title_start, self.rss_title_end),
            'http://backend.userland.com/rss2 title' :
            (self.rss_title_start, self.rss_title_end),
            'http://my.netscape.com/publish/formats/rss-0.91.dtd title' :
            (self.rss_title_start, self.rss_title_end),
            'http://purl.org/dc/elements/1.1/ title' :
            (self.rss_title_start, self.rss_title_end),
            'http://purl.org/rss/1.0/ title' :
            (self.rss_title_start, self.rss_title_end),
            'http://purl.org/rss/2.0/ title' :
            (self.rss_title_start, self.rss_title_end),

            'link' :
            (self.rss_link_start, self.rss_link_end),
            'http://backend.userland.com/rss2 link' :
            (self.rss_link_start, self.rss_link_end),
            'http://my.netscape.com/publish/formats/rss-0.91.dtd link' :
            (self.rss_link_start, self.rss_link_end),
            'http://purl.org/rss/1.0/ link' :
            (self.rss_link_start, self.rss_link_end),
            'http://purl.org/rss/2.0/ link' :
            (self.rss_link_start, self.rss_link_end),

            'http://www.pheedo.com/namespace/pheedo origLink' :
            (self.rss_origlink_start, self.rss_origlink_end),

            'http://rssnamespace.org/feedburner/ext/1.0 origLink' :
            (self.rss_origlink_start, self.rss_origlink_end),

            'description' :
            (self.rss_description_start, self.rss_description_end),
            'http://backend.userland.com/rss2 description' :
            (self.rss_description_start, self.rss_description_end),
            'http://my.netscape.com/publish/formats/rss-0.91.dtd description' :
            (self.rss_description_start, self.rss_description_end),
            'http://purl.org/dc/elements/1.1/ description' :
            (self.rss_description_start, self.rss_description_end),
            'http://purl.org/rss/1.0/ description' :
            (self.rss_description_start, self.rss_description_end),
            'http://purl.org/rss/2.0/ description' :
            (self.rss_description_start, self.rss_description_end),

            'enclosure' :
            (self.rss_enclosure_start, self.rss_enclosure_end),

            'guid' :
            (self.rss_guid_start, self.rss_guid_end),

            'pubDate' :
            (self.rss_pubdate_start, self.rss_pubdate_end),
            'http://purl.org/rss/2.0/ pubDate' :
            (self.rss_pubdate_start, self.rss_pubdate_end),
            'http://purl.org/dc/elements/1.1/ date' :
            (self.rss_date_start, self.rss_date_end)
            })

    def rss_rss_end(self):
        self.elements = {}


    def rss_rss11_start(self, attrs):
        self._format = 'rss11'
        self.elements.update({
            'http://purl.org/net/rss1.1# item' :
            (self.rss_item_start, self.rss_item_end),

            'http://purl.org/net/rss1.1# title' :
            (self.rss_title_start, self.rss_title_end),

            'http://purl.org/net/rss1.1# link' :
            (self.rss_link_start, self.rss_link_end),

            'http://purl.org/net/rss1.1# description' :
            (self.rss_description_start, self.rss_description_end)
            })
        self._state = self._state | 0x04

    def rss_rss11_end(self):
        self._state = self._state & ~0x04
        self.elements = {}


    def atom03_feed_start(self, attrs):
        self._format = 'atom03'
        self.elements.update({
            'http://purl.org/atom/ns# entry' :
            (self.atom_entry_start, self.atom_entry_end),

            'http://purl.org/atom/ns# title' :
            (self.atom_title_start, self.atom_title_end),

            'http://purl.org/atom/ns# link' :
            (self.atom_link_start, self.atom_link_end),

            'http://purl.org/atom/ns# tagline' :
            (self.atom_subtitle_start, self.atom_subtitle_end),

            'http://purl.org/atom/ns# summary' :
            (self.atom_summary_start, self.atom_summary_end),

            'http://purl.org/atom/ns# content' :
            (self.atom_content_start, self.atom_content_end),

            'http://purl.org/atom/ns# id' :
            (self.atom_id_start, self.atom_id_end),

            'http://purl.org/atom/ns# created' :
            (self.atom_published_start, self.atom_published_end),
            'http://purl.org/atom/ns# modified' :
            (self.atom_updated_start, self.atom_updated_end)
            })

        self._state = self._state | 0x04

    def atom03_feed_end(self):
        self._state = self._state & ~0x04
        self.elements = {}


    def atom10_feed_start(self, attrs):
        self._format = 'atom10'
        self.elements.update({
            'http://www.w3.org/2005/Atom entry' :
            (self.atom_entry_start, self.atom_entry_end),

            'http://www.w3.org/2005/Atom title' :
            (self.atom_title_start, self.atom_title_end),

            'http://www.w3.org/2005/Atom link' :
            (self.atom_link_start, self.atom_link_end),

            'http://www.w3.org/2005/Atom subtitle' :
            (self.atom_subtitle_start, self.atom_subtitle_end),

            'http://www.w3.org/2005/Atom summary' :
            (self.atom_summary_start, self.atom_summary_end),

            'http://www.w3.org/2005/Atom content' :
            (self.atom_content_start, self.atom_content_end),

            'http://www.w3.org/2005/Atom id' :
            (self.atom_id_start, self.atom_id_end),

            'http://www.w3.org/2005/Atom published' :
            (self.atom_published_start, self.atom_published_end),
            'http://www.w3.org/2005/Atom updated' :
            (self.atom_updated_start, self.atom_updated_end)
            })

        self._state = self._state | 0x04

    def atom10_feed_end(self):
        self._state = self._state & ~0x04
        self.elements = {}


    def rss_channel_start(self, attrs):
        self._state = self._state | 0x04

    def rss_channel_end(self):
        self._state = self._state & ~0x04


    def rss_item_start(self, attrs):
        if attrs.has_key('http://www.w3.org/1999/02/22-rdf-syntax-ns# about'):
            guid = attrs['http://www.w3.org/1999/02/22-rdf-syntax-ns# about']
        else:
            guid = None

        self._state = self._state | 0x08
        self._items.append(Data(guid=guid, published=None, title='', link='', descr=''))

    def rss_item_end(self):
        elem = self._current_elem()
        if (elem != None) and hasattr(elem, 'origlink'):
            elem.link = elem.origlink
            delattr(elem, 'origlink')

        self._state = self._state & ~0x08


    def rss_title_start(self, attrs):
        if self._state & 0xfc:
            self._reset_cdata('')

    def rss_title_end(self):
        if self._state & 0xfc:
            elem = self._current_elem()
            if elem != None:
                elem.title = self.cdata()

        self._reset_cdata()


    def rss_link_start(self, attrs):
        if self._state & 0xfc:
            self._reset_cdata('')

    def rss_link_end(self):
        if self._state & 0xfc:
            elem = self._current_elem()
            if elem != None:
                elem.link = self.resolve_url(self.cdata())

        self._reset_cdata()


    def rss_origlink_start(self, attrs):
        if self._state & 0xfc:
            self._reset_cdata('')

    def rss_origlink_end(self):
        if self._state & 0xfc:
            elem = self._current_elem()
            if elem != None:
                elem.origlink = self.resolve_url(self.cdata())

        self._reset_cdata()


    def rss_description_start(self, attrs):
        if self._state & 0xfc:
            self._reset_cdata('')

    def rss_description_end(self):
        if self._state & 0xfc:
            elem = self._current_elem()
            if elem != None:
                elem.descr = self.cdata()

        self._reset_cdata()


    def rss_guid_start(self, attrs):
        if self._state & 0x8:
            self._reset_cdata('')

    def rss_guid_end(self):
        if self._state & 0x8:
            elem = self._current_elem()
            if elem != None:
                elem.guid = self.cdata()

            self._reset_cdata()


    def rss_enclosure_start(self, attrs):
        if self._state & 0x8:
            elem = self._current_elem()
            if elem != None and elem.link == '':
                if attrs.has_key('url'):
                    elem.link = self.resolve_url(attrs['url'])

            self._reset_cdata('')

    def rss_enclosure_end(self):
        if self._state & 0x8:
            self._reset_cdata()


    def rss_date_start(self, attrs):
        if self._state & 0x8:
            self._reset_cdata('')

    def rss_date_end(self):
        if self._state & 0x8:
            elem = self._current_elem()
            published = parse_dateTime(self.cdata())
            if elem != None:
                elem.published = published
            self._reset_cdata()


    def rss_pubdate_start(self, attrs):
        if self._state & 0x8:
            self._reset_cdata('')

    def rss_pubdate_end(self):
        if self._state & 0x8:
            elem = self._current_elem()
            published = parse_Rfc822DateTime(self.cdata())
            if elem != None:
                elem.published = published
            self._reset_cdata()


    def atom_entry_start(self, attrs):
        self._state = (self._state & ~0x04) | 0x08
        self._items.append(Data(guid=None, published=None, title='', link='', descr=''))

    def atom_entry_end(self):
        if self._items[-1].descr == '' and self._summary:
            self._items[-1].descr = self._summary

        self._state = (self._state & ~0x08) | 0x04


    def atom_title_start(self, attrs):
        if self._state & 0xfc:
            self._reset_cdata('')

    def atom_title_end(self):
        if self._state & 0xfc:
            elem = self._current_elem()
            if elem != None:
                elem.title = self.cdata()

        self._reset_cdata()


    def atom_link_start(self, attrs):
        elem = self._current_elem()
        if elem == None:
            return

        attr_type = self._get_atom_attr(attrs, 'type')

        if elem.link:
            if (attr_type != None) and (attr_type != 'text/html') and (attr_type != 'application/xhtml+xml') and (attr_type != 'xhtml') and (attr_type != 'html'):
                return

        attr_href = self._get_atom_attr(attrs, 'href')
        if attr_href != None:
            elem.link = self.resolve_url(attr_href)

    def atom_link_end(self):
        pass


    def atom_subtitle_start(self, attrs):
        if self._state & 0x04:
            self._reset_cdata('')
            if self._format == 'atom03':
                attr_mode = self._get_atom_attr(attrs, 'mode')
                if attr_mode != None:
                    self._content_mode = attr_mode

    def atom_subtitle_end(self):
        if self._state & 0x04:
            cdata = self.cdata()
            if self._content_mode == 'base64':
                cdata = cdata.decode('base64')
            elem = self._current_elem()
            if elem != None:
                elem.descr = cdata

        self._reset_cdata()
        self._content_mode = None


    def atom_content_start(self, attrs):
        if self._state & 0x08:
            self._reset_cdata('')
            if self._format == 'atom03':
                attr_mode = self._get_atom_attr(attrs, 'mode')
                if attr_mode != None:
                    self._content_mode = attr_mode

    def atom_content_end(self):
        if self._state & 0x08:
            cdata = self.cdata()
            if self._content_mode == 'base64':
                cdata = cdata.decode('base64')
            elem = self._current_elem()
            if elem != None and elem != '':
                elem.descr = cdata

        self._reset_cdata()
        self._content_mode = None


    def atom_summary_start(self, attrs):
        if self._state & 0x08:
            self._reset_cdata('')
            if self._format == 'atom03':
                attr_mode = self._get_atom_attr(attrs, 'mode')
                if attr_mode != None:
                    self._content_mode = attr_mode

    def atom_summary_end(self):
        if self._state & 0x08:
            cdata = self.cdata()
            if self._content_mode == 'base64':
                cdata = cdata.decode('base64')
            self._summary = cdata

        self._reset_cdata()
        self._content_mode = None


    def atom_id_start(self, attrs):
        if self._state & 0x8:
            self._reset_cdata('')

    def atom_id_end(self):
        if self._state & 0x8:
            elem = self._current_elem()
            if elem != None:
                elem.guid = self.cdata()
            self._reset_cdata()


    def atom_published_start(self, attrs):
        if self._state & 0x8:
            self._reset_cdata('')

    def atom_published_end(self):
        if self._state & 0x8:
            elem = self._current_elem()
            published = parse_dateTime(self.cdata())
            if elem != None:
                elem.published = published
            self._reset_cdata()

    def atom_updated_start(self, attrs):
        if self._state & 0x8:
            self._reset_cdata('')

    def atom_updated_end(self):
        if self._state & 0x8:
            elem = self._current_elem()
            published = parse_dateTime(self.cdata())
            if elem != None and elem.published == None:
                elem.published = published
            self._reset_cdata()



    def unknown_starttag(self, tag, attrs):
        if self._format == '':
            logger.warn('format not recognised, start-tag %s' % (tag,))
            self._format = 'unknown'

        if (self._cdata != None) and (tag[:29] == 'http://www.w3.org/1999/xhtml '):
            self._cdata += '<' + tag[29:]
            for attr, val in attrs.items():
                if attr[:29] == 'http://www.w3.org/1999/xhtml ':
                    self._cdata += ' ' + attr[29:] + '="' + val.decode(self._encoding) + '"'
            self._cdata += '>'

        if tag[-8:] == ' channel':
            logger.warn('unknown namespace for %s' % (tag,))
        elif tag[-5:] == ' item':
            logger.warn('unknown namespace for %s' % (tag,))
        elif self._state & 0xfc:
            if tag[-6:] == ' title':
                logger.warn('unknown namespace for %s' % (tag,))
            elif tag[-5:] == ' link':
                logger.warn('unknown namespace for %s' % (tag,))
            elif tag[-12:] == ' description':
                logger.warn('unknown namespace for %s' % (tag,))

    def unknown_endtag(self, tag):
        if (self._cdata != None) and (tag[:29] == 'http://www.w3.org/1999/xhtml '):
            self._cdata += '</' + tag[29:] + '>'

    def _reset_cdata(self, data=None):
        if data != None:
            if data == '':
                self._cdata = []
                self._cdatalen = 0
            else:
                self._cdata = [data]
                self._cdatalen = len(data)
        else:
            self._cdata = None
            self._cdatalen = None

    def _append_cdata(self, data):
        if self._cdata != None:
            self._cdatalen += len(data)
            if self._cdatalen > 64 * 1024:
                raise ValueError('item exceeds maximum allowed size')

            if len(self._cdata):
                if type(self._cdata[-1]) == type(data):
                    self._cdata[-1] += data
                else:
                    self._cdata.append(data)
            else:
                self._cdata.append(data)

    def cdata(self):
        if self._cdata == None:
            return None

        s = array('u')
        for elem in self._cdata:
            if type(elem) == types.StringType:
                s.extend(elem.decode(self._encoding))
            else:
                s.extend(elem)

        return s.tounicode()

    def handle_data(self, data):
        self._append_cdata(data)

    def handle_cdata(self, data):
        self._append_cdata(data)

    def handle_charref(self, name):
        try:
            if name[0] == 'x':
                n = int(name[1:], 16)
            else:
                n = int(name)
        except ValueError:
            self.unknown_charref(name)
            return
        if not 0 <= n <= 65535:
            self.unknown_charref(name)
            return
        self._append_cdata(unichr(n))

    def unknown_entityref(self, entity):
        try:
            self._append_cdata(ENTITIES[entity].decode('iso8859-1'))
        except KeyError:
            logger.info('ignoring unknown entity ref %s' % (entity,))

    def _current_elem(self):
        if self._state & 0x08:
            return self._items[-1]
        elif self._state & 0x04:
            return self._channel
        else:
            return None


##
# Database Schema:
#  'S' -> resource_id sequence number (4-byte struct)
#  'S' + resource_id -> URL
#  'R' + URL -> resource_id (4-byte struct)
#  'D' + resource_id -> Resource data
#  'E' + resource_id -> error information (string)
#  'I' + resource_id -> Resource info
#  'H' + resource_id -> Resource history
#  'T' + resource_id -> Resource times
##
class RSS_Resource:
    NR_ITEMS = 64

    _db_sync = Null_Synchronizer()
    http_proxy = None


    def __init__(self, url, res_db=None, connect_timeout=30, timeout=20):
        self._lock = threading.Lock()
        self._url = url
        self._url_protocol, self._url_host, self._url_path = split_url(url)
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
        cursor = Cursor(db)

        result = cursor.execute('SELECT rid, last_updated, last_modified, etag, invalid_since, redirect, redirect_seq, penalty, err_info, title, description, link FROM resource WHERE url=?',
                                (self._url,))
        for row in result:
            self._id, self._last_updated, self._last_modified, self._etag, self._invalid_since, self._redirect, self._redirect_seq, self._penalty, self._err_info, title, description, link = row

        if self._id == None:
            cursor.execute('INSERT INTO resource (url) VALUES (?)',
                           (self._url,))
            self._id = cursor.lastrowid

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
            self._history = zip(history_times, history_nr)

        del cursor
        del db


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
        cursor = Cursor(db)

        result = cursor.execute('SELECT url FROM resource WHERE rid=?',
                                (self._redirect,))
        redirect_url = None
        for row in result:
            redirect_url = row[0]

        del cursor
        return redirect_url, self._redirect_seq

    def penalty(self):
        return self._penalty

    def error_info(self):
        return self._err_info


    def history(self):
        return self._history


    # @return ([item], next_item_id, redirect_resource, redirect_seq, [redirects])
    # locks the resource object if new_items are returned
    def update(self, db=None, redirect_count=5, redirect_cb=None):
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


        if db == None:
            db = RSS_Resource_db()

        cursor = None

        redirect_penalty = 0
        redirect_tries = redirect_count
        redirect_permanent = True
        redirect_resource = None
        redirect_seq = None
        redirects = []

        http_conn = None
        http_protocol = None
        http_host = None

        try:
            url_protocol, url_host, url_path = self._url_protocol, self._url_host, self._url_path

            while redirect_tries > 0:
                redirect_tries = -(redirect_tries - 1)

                if redirect_permanent:
                    redirect_url = url_protocol + '://' + url_host + url_path
                    if redirect_url != self._url:
                        #log_message('redirect: %s -> %s' % (self._url.encode('iso8859-1', 'replace'), redirect_url.encode('iso8859-1', 'replace')))
                        if redirect_cb != None:
                            redirect_resource, redirects = redirect_cb(redirect_url, db, -redirect_tries + 1)

                            # only perform the redirect if target is valid
                            if redirect_resource._invalid_since:
                                error_info = redirect_resource._err_info
                                self._last_modified = redirect_resource._last_modified
                                self._etag = redirect_resource._etag
                                redirect_resource = None
                            else:
                                cursor = Cursor(db)
                                redirect_items, redirect_seq = redirect_resource.get_headlines(0, cursor)

                                items, first_item_id, nr_new_items = self._process_new_items(redirect_items, cursor)
                                del redirect_items

                                self._last_modified = None
                                self._etag = None

                                self._redirect = redirect_resource._id
                                self._redirect_seq = redirect_seq
                                cursor.begin()
                                cursor.execute('UPDATE resource SET redirect=?, redirect_seq=? WHERE rid=?',
                                               (self._redirect,
                                                self._redirect_seq, self._id))

                            break


                if RSS_Resource.http_proxy and (url_protocol == 'http'):
                    host = RSS_Resource.http_proxy
                    request = 'http://' + url_host + url_path
                else:
                    host = url_host
                    request = url_path

                if url_protocol == 'http' and http_protocol == url_protocol and http_host == host and http_conn != None:
                    conn_reused = True
                    h = http_conn
                else:
                    conn_reused = False
                    if url_protocol == 'https':
                        h = HTTPSConnection(host,
                                            timeout=self._connect_timeout,
                                            read_timeout=self._timeout)
                    else:
                        h = HTTPConnection(host,
                                           timeout=self._connect_timeout,
                                           read_timeout=self._timeout)

                http_protocol = url_protocol
                http_host = host
                http_conn = None
                try:
                    h.putrequest('GET', request)

                    if conn_reused:
                        logger.debug('reused HTTP connection')
                except httplib.CannotSendRequest:
                    logger.warn('caught CannotSendRequest, opening new connection')

                    if not conn_reused:
                        raise

                    h = HTTPConnection(host)
                    h.putrequest('GET', request)

                if not RSS_Resource.http_proxy:
                    h.putheader('Host', url_host)
                h.putheader('Connection', 'Keep-Alive')
                h.putheader('Pragma', 'no-cache')
                h.putheader('Cache-Control', 'no-cache')
                h.putheader('Accept-Encoding', 'gzip, deflate, identity')
                h.putheader('User-Agent', 'JabRSS (http://jabrss.cmeerw.org)')
                if self._last_modified:
                    h.putheader('If-Modified-Since',
                                rfc822.formatdate(self._last_modified))
                if self._etag != None:
                    h.putheader('If-None-Match', self._etag)
                h.endheaders()
                response = h.getresponse()

                errcode = response.status
                errmsg = response.reason
                headers = response.msg

                # check the error code
                if (errcode >= 200) and (errcode < 300):
                    feed_xml_downloaded = True

                    self._last_modified = parse_Rfc822DateTime(headers.get('last-modified', None))

                    try:
                        self._etag = headers['etag']
                    except:
                        self._etag = None

                    content_encoding = headers.get('content-encoding', None)
                    transfer_encoding = headers.get('transfer-encoding', None)

                    if (content_encoding == 'gzip') or (transfer_encoding == 'gzip'):
                        logger.debug('gzip-encoded data')
                        decoder = Gzip_Decompressor()
                    elif (content_encoding == 'deflate') or (transfer_encoding == 'deflate'):
                        logger.debug('deflate-encoded data')
                        decoder = Deflate_Decompressor()
                    else:
                        decoder = Null_Decompressor()

                    content_maintype = headers.getmaintype()
                    content_subtype = headers.getsubtype()
                    charset = headers.getparam('charset')
                    default_charset = None

                    if content_maintype == 'text':
                        if content_subtype.startswith('xml'):
                            # or maybe iso8859-1
                            default_charset = 'us-ascii'
                        else:
                            # not strictly conforming here...
                            default_charset = 'iso8859-1'

                    rss_parser = Feed_Parser((self._url_protocol, self._url_host, self._url_path),
                                             charset, default_charset)

                    bytes_received = 0
                    bytes_processed = 0
                    xml_started = 0
                    file_hash = hashlib.md5()

                    l = response.read(4096)
                    while l:
                        bytes_received = bytes_received + len(l)
                        if bytes_received > 384 * 1024:
                            raise ValueError('file exceeds maximum allowed size')

                        data = decoder.feed(l)
                        file_hash.update(data)

                        if not xml_started:
                            data = string.lstrip( data)
                            if data:
                                xml_started = 1

                        bytes_processed = bytes_processed + len(data)
                        if bytes_processed > 512 * 1024:
                            raise ValueError('file exceeds maximum allowed decompressed size')

                        rss_parser.feed(data)

                        l = response.read(4096)

                    response.close()
                    h.close()
                    data = decoder.flush()
                    file_hash.update(data)
                    rss_parser.feed(data)
                    rss_parser.close()
                    new_channel_info = normalize_obj(rss_parser._channel)

                    cursor = Cursor(db)
                    cursor.begin()

                    hash_buffer = buffer(file_hash.digest())
                    cursor.execute('UPDATE resource SET hash=? WHERE rid=? AND (hash IS NULL OR hash<>?)',
                                   (hash_buffer, self._id, hash_buffer))
                    feed_xml_changed = (cursor.rowcount != 0)

                    self._update_channel_info(new_channel_info, cursor)

                    new_items = map(lambda x: normalize_item(x),
                                    rss_parser._items)
                    new_items.reverse()

                    items, first_item_id, nr_new_items = self._process_new_items(new_items, cursor)
                    del new_items

                # handle "304 Not Modified"
                elif errcode == 304:
                    # RSS resource is valid
                    self._invalid_since = None
                # handle "301 Moved Permanently", "302 Found" and
                # "307 Temporary Redirect"
                elif (errcode >= 300) and (errcode < 400):
                    bytes_received = 0
                    l = response.read(4096)
                    while l:
                        bytes_received = bytes_received + len(l)
                        if bytes_received > 128 * 1024:
                            raise ValueError('file exceeds maximum allowed size')

                        l = response.read(4096)

                    response.close()
                    if not response.will_close:
                        # maybe we can reuse the connection
                        http_conn = h

                    if errcode != 301:
                        redirect_permanent = False
                        redirect_penalty += 1

                    redirect_url = headers.get('location', None)
                    if redirect_url:
                        if not re_validprotocol.match(redirect_url):
                            base_url = '%s://%s' % (url_protocol, url_host)
                            if redirect_url[0] != '/':
                                redirect_url = url_path[:url_path.rindex('/')] + '/' + redirect_url

                            redirect_url = base_url + redirect_url

                        logger.info('Following redirect (%d) to "%s"' % (errcode, redirect_url))
                        url_protocol, url_host, url_path = split_url(redirect_url)
                        redirect_tries = -redirect_tries
                    else:
                        logger.warn('%d %s %s' % (errcode, errmsg, str(headers)))
                        error_info = 'HTTP: %d %s' % (errcode, errmsg)
                else:
                    logger.warn(('%d %s %s' % (errcode, errmsg, str(headers))))
                    error_info = 'HTTP: %d %s' % (errcode, errmsg)

            if self._invalid_since and not error_info and redirect_tries == 0:
                error_info = 'redirect: maximum number of redirects exceeded'
        except socket.timeout, e:
            error_info = 'timeout: ' + str(e)
        except socket.error, e:
            error_info = 'socket: ' + str(e)
        except IOError, e:
            error_info = 'I/O error: ' + str(e)
        except httplib.BadStatusLine, e:
            error_info = 'HTTP: bad status line'
        except httplib.IncompleteRead, e:
            error_info = 'HTTP: incomplete read'
        except httplib.UnknownProtocol, e:
            error_info = 'HTTP: unknown protocol'
        except httplib.HTTPException, e:
            error_info = 'HTTP: ' + str(e)
        except DecompressorError, e:
            error_info = 'decompressor: ' + str(e)
        except UnicodeError, e:
            error_info = 'encoding: ' + str(e)
        except LookupError, e:
            error_info = 'encoding: ' + str(e)
        except xmllib.Error, e:
            error_info = 'RDF/XML parser: ' + str(e)
        except ValueError, e:
            error_info = 'misc: ' + str(e)
        except:
            traceback.print_exc(file=sys.stdout)

        if error_info:
            logger.warn('Error: %s' % (error_info,))

        if cursor == None:
            cursor = Cursor(db)
            cursor.begin()

        if error_info != self._err_info:
            self._err_info = error_info
            cursor.execute('UPDATE resource SET err_info=? WHERE rid=?',
                           (self._err_info, self._id))

        if not self._invalid_since:
            if feed_xml_downloaded:
                if nr_new_items > 0:
                    # downloaded and new items available, good
                    self._penalty = (5 * self._penalty) / 6
                elif not feed_xml_changed:
                    # downloaded, but not changed, very bad
                    self._penalty = (3 * self._penalty) / 4 + 256
                else:
                    # downloaded and changed, but no new items, bad
                    self._penalty = (15 * self._penalty) / 16 + 64
            else:
                # "not modified" response from server, good
                self._penalty = (3 * self._penalty) / 4

        if redirect_penalty > 0:
            # penalty for temporary redirects
            self._penalty = (7 * self._penalty) / 8 + 128


        cursor.execute('UPDATE resource SET last_modified=?, last_updated=?, etag=?, invalid_since=?, penalty=? WHERE rid=?',
                       (self._last_modified, self._last_updated, self._etag,
                        self._invalid_since, self._penalty, self._id))
        del cursor

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
            cursor.unlock()
            self.lock()

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

            history_times = map(lambda x: x[0], self._history)
            if len(history_times) < 16:
                history_times += (16 - len(history_times)) * [None]

            history_nr = map(lambda x: x[1], self._history)
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

        tstamplist = filter(lambda x: x != None,
                            map(lambda x: x.published, items))
        tstamplist.sort()

        if (len(tstamplist) > 4) and (len(new_items) > RSS_Resource.NR_ITEMS):
            tstamplist = tstamplist[len(tstamplist) / 2 : -len(tstamplist) / 6]
            cutoff = sum(tstamplist) / len(tstamplist)
        elif len(tstamplist) > 2:
            cutoff = tstamplist[0]
        else:
            cutoff = None

        new_items = filter(lambda x: (x.published == None) or (x.published >= cutoff), new_items)
        new_items.sort(lambda x, y: cmp(x.published, y.published))

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
    def get_headlines(self, first_id, db_cursor=None, db=None):
        if db_cursor == None:
            if db == None:
                cursor = Cursor(RSS_Resource_db())
            else:
                cursor = Cursor(db)
        else:
            cursor = db_cursor

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

        del cursor
        return items, last_id


    def next_update(self, randomize=True):
        min_interval = MIN_INTERVAL
        max_interval = MAX_INTERVAL

        if len(self._history) >= 2:
            hist_items = len(self._history)

            sum_items = reduce(lambda x, y: (y[0], x[1] + y[1]),
                               self._history[1:])[1]
            time_span = self._last_updated - self._history[0][0]

            if hist_items >= 12:
                time_span_old = self._history[hist_items / 2][0] - self._history[0][0]
                sum_items_old = reduce(lambda x, y: (y[0], x[1] + y[1]),
                                       self._history[1:hist_items / 2 + 1])[1]
                if (3 * sum_items_old < sum_items) and (5 * time_span_old < time_span):
                    time_span = time_span_old
                    sum_items = sum_items_old
                # sum_items_new = sum_items - sum_items_old
                elif (3 * sum_items_old > 2 * sum_items) and (5 * time_span_old > 4 * time_span):
                    time_span = time_span - time_span_old
                    sum_items = sum_items - sum_items_old

            interval = time_span / sum_items / INTERVAL_DIVIDER

            # apply a bonus for well-behaved feeds
            interval = 32 * interval / (64 - self._penalty / 28)
            max_interval = 32 * max_interval / (64 - self._penalty / 28)
            min_interval = 32 * min_interval / (48 - self._penalty / 64)
        elif len(self._history) == 1:
            time_span = self._last_updated - self._history[0][0]

            interval = 30*60 + time_span / 3
            min_interval = 60*60
        elif self._invalid_since:
            time_span = self._last_updated - self._invalid_since

            interval = 4*60*60 + time_span / 4
            max_interval = 48*60*60
        else:
            interval = 8*60*60

        if string.find(string.lower(self._url), 'slashdot.org') != -1:
            # yes, slashdot sucks - this is a special slashdot
            # throttle to avaoid being banned by slashdot
            interval = interval + 150*60

        # apply upper and lower bounds to the interval
        interval = min(max_interval, max(min_interval, interval))

        # and add some random factor
        if randomize:
            return self._last_updated + interval + int(random.normalvariate(30, 50 + interval / 50))
        else:
            return self._last_updated + interval


def RSS_Resource_id2url(res_id, db_cursor=None):
    if db_cursor == None:
        cursor = Cursor(RSS_Resource_db())
    else:
        cursor = db_cursor

    url = None
    result = cursor.execute('SELECT url FROM resource WHERE rid=?',
                            (res_id,))
    for row in result:
        url = row[0]

    del cursor
    if url == None:
        raise KeyError(res_id)

    return url


def RSS_Resource_simplify(url):
    url_protocol, url_host, url_path = split_url(url)

    simple_url = url_protocol + '://' + url_host + url_path
    # TODO: return simple_url
    return url


if __name__ == '__main__':
    import locale, sys

    locale.setlocale(locale.LC_CTYPE, '')
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
        resource = RSS_Resource(url, db)

        new_items, next_item_id, redirect_resource, redirect_seq, redirects = resource.update(db)
        channel_info = resource.channel_info()
        print('%s %s %s' % (channel_info.title, channel_info.link, channel_info.descr))
        error_info = resource.error_info()
        if error_info:
            print('error info %s' % (error_info))

        if len(new_items) > 0:
            print('new items (next id; %d):\n  %s' %
                  (next_item_id,
                   '\n  '.join(['%s - %s' % (x.title, x.link) for x in new_items])))

    db.close()
    del db
