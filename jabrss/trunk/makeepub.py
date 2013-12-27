#!/usr/bin/python
# Copyright (C) 2013, Christof Meerwald
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

import codecs, getopt, locale, logging, sys, time, urllib2, uuid

import lxml.html

from lxml.html.clean import Cleaner
from parserss import init_parserss, RSS_Resource, RSS_Resource_db
from urlrewriter import UrlRewriter
from zipfile import ZipFile, ZIP_STORED, ZIP_DEFLATED


HTTP_HEADERS = { 'User-Agent' : 'Lynx/2 (Linux; U; Android; en-us;) Mobile' }

HTML_PREFIX = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">'''

CONTAINER_XML = '''<?xml version="1.0" encoding="UTF-8"?>
<container xmlns="urn:oasis:names:tc:opendocument:xmlns:container" version="1.0">
   <rootfiles>
      <rootfile full-path="OPS/content.opf" media-type="application/oebps-package+xml"/>
   </rootfiles>
</container>
'''

CONTENT_OPF = '''<?xml version="1.0" encoding="UTF-8"?>
<package xmlns="http://www.idpf.org/2007/opf" unique-identifier="id" version="2.0">
  <metadata xmlns:opf="http://www.idpf.org/2007/opf" xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:identifier id="id">urn:uuid:%s</dc:identifier>
    <dc:title>WebRSS: %s</dc:title>
    <dc:creator opf:role="aut">WebRSS</dc:creator>
    <dc:publisher>webrss.cmeerw.net</dc:publisher>
    <dc:source>WebRSS</dc:source>
  </metadata>
  <manifest>
    %s
    <item id="ncx" href="toc.ncx" media-type="application/x-dtbncx+xml"/>
  </manifest>
  <spine toc="ncx">
    %s
  </spine>
</package>
'''

TOC_NCX = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ncx PUBLIC "-//NISO//DTD ncx 2005-1//EN" "http://www.daisy.org/z3986/2005/ncx-2005-1.dtd">
<ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1">
  <head>
    <meta name="dtb:uid" content="%s"/>
    <meta name="dtb:depth" content="1"/>
    <meta name="dtb:totalPageCount" content="0"/>
    <meta name="dtb:maxPageNumber" content="0"/>
  </head>
  <docTitle>
    <text>WebRSS: %s</text>
  </docTitle>
  <navMap>
    %s
  </navMap>
</ncx>
'''


if sys.version_info[0] == 2:
    encoding = locale.getlocale()[1]
    if not encoding:
        encoding = 'us-ascii'
    sys.stdout = codecs.getwriter(encoding)(sys.stdout, errors='replace')
    sys.stderr = codecs.getwriter(encoding)(sys.stderr, errors='replace')

logger = logging.getLogger()
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)

html_cleaner = Cleaner(scripts=True, javascript=False, comments=True,
                       style=False, links=True, meta=True,
                       page_structure=False,
                       processing_instructions=True, embedded=True,
                       frames=True, forms=True, annoying_tags=True,
                       remove_unknown_tags=True, safe_attrs_only=True,
                       add_nofollow=False,
                       kill_tags=['noscript'])


uid = str(uuid.uuid4())
age = 12
epubname = uid + '.epub'
rewrite_db = 'rewrite.db'

opts, args = getopt.getopt(sys.argv[1:], 'a:o:r:',
                           ['age=', 'output=', 'rewrite-db='])
for optname, optval in opts:
    if optname in ('-a', '--age'):
        age = int(optval)
    elif optname in ('-o', '--output'):
        epubname = optval
    elif optname in ('-r', '--rewrite-db'):
        rewrite_db = optval


init_parserss()
db = RSS_Resource_db()
now = int(time.time())
rewriter = UrlRewriter(rewrite_db)

epub = ZipFile(epubname, 'w', ZIP_DEFLATED)
epub.writestr('mimetype', 'application/epub+zip', ZIP_STORED)
epub.writestr('META-INF/container.xml', CONTAINER_XML)

rss_titles, pageinfo, visited, resources = [], [], {}, {}

for rss in args:
    while rss != None:
        resource = RSS_Resource(rss, db)
        rss, seqnr = resource.redirect_info(db)

    resource.update(db)
    channel_info = resource.channel_info()
    items, nextid = resource.get_headlines(None, None, db)

    rss_titles.append(channel_info.title)

    for item in items:
        if item.published < now - age*60*60:
            continue

        url = rewriter.rewrite(item.link)

        if visited.get(url):
            continue
        visited[url] = True

        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())
        try:
            f = opener.open(urllib2.Request(url, None, HTTP_HEADERS))
        except urllib2.URLError as e:
            print url, e
            continue

        html = lxml.html.document_fromstring(f.read())
        html.make_links_absolute(url)

        html = html_cleaner.clean_html(html)
        html.set('xmlns', 'http://www.w3.org/1999/xhtml')

        for element, attribute, link, pos in html.iterlinks():
            if element.tag in ('a',):
                pass
            elif element.tag in ('img',) and attribute == 'src':
                resname = resources.get(link, 'i%03d.img' % (len(resources) + 1,))
                resources[link] = resname
                element.set(attribute, resname)
            elif attribute:
                element.drop_tree()

        pagename = 'p%03d' % (len(pageinfo) + 1,)
        epub.writestr('OPS/%s.html' % (pagename,),
                      lxml.html.tostring(html, encoding='UTF-8',
                                         include_meta_content_type=True,
                                         method='xml', doctype=HTML_PREFIX))
        pageinfo.append((pagename, item.title))

db.close()
del db


resinfo = []
for url, fname in resources.items():
    try:
        f = urllib2.urlopen(urllib2.Request(url))
    except urllib2.URLError as e:
        print url, e
        continue

    ctype = f.info().gettype()
    name, ext = fname.split('.')

    if ctype.startswith('image/'):
        compr = ZIP_STORED
    else:
        compr = ZIP_DEFLATED

    epub.writestr('OPS/%s.%s' % (name, ext), f.read(), compr)
    resinfo.append((name, ext, ctype))


manifest = [ '<item id="%s" href="%s.html" media-type="application/xhtml+xml"/>' % (name, name) for name, title in pageinfo ]
manifest += [ '<item id="%s" href="%s.%s" media-type="%s"/>' % (name, name, ext, ctype) for name, ext, ctype in resinfo ]
spine_toc = [ '<itemref idref="%s" linear="yes"/>' % (name,) for name, title in pageinfo ]

nav = [ '<navPoint id="n%s" playOrder="1"><navLabel><text>%s</text></navLabel><content src="%s.html"/></navPoint>' % (name, title, name) for name, title in pageinfo ]

epub.writestr('OPS/content.opf',
              (CONTENT_OPF % (uid, ', '.join(rss_titles), ''.join(manifest),
                              ''.join(spine_toc))).encode('utf-8'))
epub.writestr('OPS/toc.ncx',
              (TOC_NCX % (uid, ', '.join(rss_titles),
                          ''.join(nav))).encode('utf-8'))

epub.close()
