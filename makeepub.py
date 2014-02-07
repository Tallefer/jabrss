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

import codecs, getopt, locale, logging, sys, time, uuid

import lxml.html, requests

from lxml.html.clean import Cleaner
from parserss import init_parserss, RSS_Resource, RSS_Resource_db
from extract_content import extract_content
from urlrewriter import UrlRewriter
from zipfile import ZipFile, ZIP_STORED, ZIP_DEFLATED


HTML_PREFIX = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">'''

PAGE_PREFIX = '''<html xmlns="http://www.w3.org/1999/xhtml">
<meta http-equiv="Content-Type" content="application/xhtml+xml"/>
<head><title>%s</title></head>
<body><div>
'''

PAGE_SUFFIX = '</div></body></html>'

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
    <dc:title>%s</dc:title>
    <dc:creator opf:role="aut">WebRSS</dc:creator>
    <dc:publisher>webrss.cmeerw.net</dc:publisher>
    <dc:source>WebRSS</dc:source>
  </metadata>
  <manifest>
    %s
    <item id="toc" href="toc.html" media-type="application/xhtml+xml"/>
    <item id="ncx" href="toc.ncx" media-type="application/x-dtbncx+xml"/>
  </manifest>
  <spine toc="ncx">
    <itemref idref="toc" linear="yes"/>
    %s
  </spine>
</package>
'''

TOC_NCX = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ncx PUBLIC "-//NISO//DTD ncx 2005-1//EN" "http://www.daisy.org/z3986/2005/ncx-2005-1.dtd">
<ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1">
  <head>
    <meta name="dtb:uid" content="%s"/>
    <meta name="dtb:depth" content="2"/>
    <meta name="dtb:totalPageCount" content="0"/>
    <meta name="dtb:maxPageNumber" content="0"/>
  </head>
  <docTitle>
    <text>%s</text>
  </docTitle>
  <navMap>
    %s
  </navMap>
</ncx>
'''


TOC_HTML = HTML_PREFIX + '''
<html>
<head><title>WebRSS</title></head>
<body>
<h2>WebRSS</h2>
<hr />
%s
</body>
</html>
'''

def escape(s):
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


if sys.version_info[0] == 2:
    encoding = locale.getlocale()[1]
    if not encoding:
        encoding = 'us-ascii'
    sys.stdout = codecs.getwriter(encoding)(sys.stdout, errors='replace')
    sys.stderr = codecs.getwriter(encoding)(sys.stderr, errors='replace')

logger = logging.getLogger()
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)

html_cleaner = Cleaner(scripts=True, javascript=True, comments=True,
                       style=True, links=True, meta=True,
                       page_structure=True,
                       processing_instructions=True, embedded=True,
                       frames=True, forms=True, annoying_tags=True,
                       remove_unknown_tags=True, safe_attrs_only=True,
                       add_nofollow=False,
                       kill_tags=['noscript'])


uid = str(uuid.uuid4())
age = 12
epubname = uid + '.epub'
rewrite_db = 'rewrite.db'
http_headers = {}

opts, args = getopt.getopt(sys.argv[1:], 'a:o:r:u:',
                           ['age=', 'output=', 'rewrite-db=', 'user-agent='])
for optname, optval in opts:
    if optname in ('-a', '--age'):
        age = int(optval)
    elif optname in ('-o', '--output'):
        epubname = optval
    elif optname in ('-r', '--rewrite-db'):
        rewrite_db = optval
    elif optname in ('-u', '--user-agent'):
        http_headers['User-Agent'] = optval

def get_http_session():
    sess = requests.Session()
    sess.headers.update(http_headers)
    return sess


init_parserss()
db = RSS_Resource_db()
now = int(time.time())
rewriter = UrlRewriter(rewrite_db)

epub = ZipFile(epubname, 'w', ZIP_DEFLATED)
epub.writestr('mimetype', 'application/epub+zip', ZIP_STORED)
epub.writestr('META-INF/container.xml', CONTAINER_XML)

sess = get_http_session()
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
        if item.published and item.published < now - age*60*60:
            continue

        url = rewriter.rewrite(item.link)

        if visited.get(url):
            continue
        visited[url] = True

        try:
            sess.cookies = requests.cookies.RequestsCookieJar()
            f = sess.get(url, headers = {'Referer' : url})
        except requests.RequestException as e:
            logger.info('%s: %s' % (url, str(e)))
            continue

        html = lxml.html.document_fromstring(f.text)
        html.make_links_absolute(url)

        content = []
        for frag in extract_content(html):
            frag = html_cleaner.clean_html(frag)

            for elem, attribute, link, pos in frag.iterlinks():
                if elem.tag in ('a',):
                    pass
                elif elem.tag in ('img',) and attribute == 'src':
                    resname = resources.get(link, 'i%03d.img' % (len(resources) + 1,))
                    resources[link] = resname
                    elem.set(attribute, resname)
                elif attribute:
                    elem.drop_tree()

            content.append(lxml.html.tostring(frag, encoding='utf-8',
                                              method='xml'))

        if not content:
            continue

        pagename = 'p%03d' % (len(pageinfo) + 1,)
        epub.writestr('OPS/%s.html' % (pagename,),
                      (HTML_PREFIX +
                       PAGE_PREFIX % (item.title,)).encode('utf-8') +
                      b'\n'.join(content) +
                      PAGE_SUFFIX.encode('utf-8'))
        pageinfo.append((channel_info.title, pagename, item.title))

db.close()
del db


resinfo = []

for url, fname in resources.items():
    try:
        sess.cookies = requests.cookies.RequestsCookieJar()
        f = sess.get(url, headers = {'Referer' : url})
    except requests.RequestException as e:
        logger.info('%s: %s' % (url, str(e)))
        continue

    name, ext = fname.split('.')
    ctype = f.headers['content-type'].split(';')[0]
    if ctype.startswith('image/'):
        compr = ZIP_STORED
    else:
        compr = ZIP_DEFLATED

    epub.writestr('OPS/%s.%s' % (name, ext), f.content, compr)
    resinfo.append((name, ext, ctype))


manifest = [ '<item id="%s" href="%s.html" media-type="application/xhtml+xml"/>' % (name, name) for chtitle, name, title in pageinfo ]
manifest += [ '<item id="%s" href="%s.%s" media-type="%s"/>' % (name, name, ext, ctype) for name, ext, ctype in resinfo ]
spine_toc = [ '<itemref idref="%s" linear="yes"/>' % (name,) for chtitle, name, title in pageinfo ]

nr, oldchtitle, nav, toc = 1, None, [], []
for chtitle, name, title in pageinfo:
    if oldchtitle != chtitle:
        if oldchtitle != None:
            nav.append('</navPoint>')
        toc.append('<h3><a href="%s.html">%s</a></h3>' % (name, escape(chtitle)))
        nav.append('<navPoint id="t%s" playOrder="%d"><navLabel><text>%s</text></navLabel><content src="%s.html"/>' % (name, nr, escape(chtitle), name))
        oldchtitle = chtitle
        nr += 1

    nav.append('  <navPoint id="n%s" playOrder="%d"><navLabel><text>%s</text></navLabel><content src="%s.html"/></navPoint>' % (name, nr, escape(title), name))
    nr += 1

if oldchtitle != None:
    nav.append('</navPoint>')

epub.writestr('OPS/toc.html',
              (TOC_HTML % ('\n  '.join(toc),)).encode('utf-8'))

epub.writestr('OPS/content.opf',
              (CONTENT_OPF % (uid, escape(', '.join(rss_titles)),
                              '\n    '.join(manifest),
                              '\n    '.join(spine_toc))).encode('utf-8'))
epub.writestr('OPS/toc.ncx',
              (TOC_NCX % (uid, escape(', '.join(rss_titles)),
                          '\n    '.join(nav))).encode('utf-8'))

epub.close()
