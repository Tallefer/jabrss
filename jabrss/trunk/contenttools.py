#!/usr/bin/python
# Copyright (C) 2013-2014, Christof Meerwald
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

import sys

import lxml.html
from lxml.etree import Element, ElementTree
from lxml.html.clean import Cleaner

if sys.version_info[0] == 2:
    from HTMLParser import HTMLParser
    from htmlentitydefs import name2codepoint
    from StringIO import StringIO
else:
    from html.parser import HTMLParser
    from html.entities import name2codepoint
    from io import StringIO
    unichr = chr


html_cleaner = Cleaner(scripts=True, javascript=True, comments=True,
                       style=True, links=True, meta=True,
                       page_structure=True,
                       processing_instructions=True, embedded=True,
                       frames=True, forms=True, annoying_tags=True,
                       remove_unknown_tags=True, safe_attrs_only=True,
                       add_nofollow=False,
                       kill_tags=['noscript'])


def html2plain(html, ignore_errors=False):
    class HTML2Plain(HTMLParser):
        def __init__(self, ignore_errors=False):
            HTMLParser.__init__(self)
            self.__buf = StringIO()
            self.__processed, self.__errors, self.__ignore_errors = 0, 0, ignore_errors
            self.__in_pre, self.__has_space, self.__has_nl = False, True, True

        def close(self):
            HTMLParser.close(self)
            text = self.__buf.getvalue()
            self.__buf.close()

            if self.__ignore_errors or self.__errors == 0 or self.__processed > 3*self.__errors:
                return text
            else:
                return None

        def handle_data(self, data):
            if not self.__in_pre and data:
                l = data.split()
                if l:
                    pre_space = not self.__has_space and (data[:1] in (' ', '\t', '\r', '\n'))
                    post_space = (data[-1:] in (' ', '\t', '\r', '\n'))
                    data = int(pre_space)*' ' + ' '.join(data.split()) + int(post_space)*' '
                    self.__has_space, self.__has_nl = post_space, False
                else:
                    data = ''

            self.__buf.write(data)

        def handle_charref(self, name):
            try:
                self.handle_data(unichr(int(name)))
            except ValueError:
                self.__errors += 1

        def handle_entityref(self, name):
            try:
                self.handle_data(unichr(name2codepoint[name]))
            except KeyError:
                self.__errors += 1

        def handle_starttag(self, tag, attrs):
            if tag in ('br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7',
                       'div', 'p', 'pre', 'tr'):
                if not self.__has_nl:
                    self.__buf.write('\n')
                    self.__has_nl, self.__has_space = True, True
                if tag == 'pre':
                    self.__in_pre = True
            elif tag in ('li',):
                if not self.__has_nl:
                    self.__buf.write('\n')
                self.__buf.write(' * ')
                self.__has_nl, self.__has_space = False, True
            elif tag in ('td',):
                if not self.__has_space and not self.__has_nl:
                    self.__buf.write(' ')
                    self.__has_nl, self.__has_space = False, True
            elif tag == 'img':
                d = dict(attrs)
                self.handle_data(d.get('alt', '') or d.get('title', ''))
            self.__processed += 1

        def handle_startendtag(self, tag, attrs):
            return self.handle_starttag(tag, attrs)

        def handle_endtag(self, tag):
            if tag == 'pre':
                self.__in_pre, self.__has_nl, self.__has_space = False, False, True
            self.__processed += 1

        def handle_comment(self, data):
            self.__processed += 1

        def unknown_decl(self, data):
            self.__errors += 1


    try:
        parser = HTML2Plain(ignore_errors)
        parser.feed(html)
        text = parser.close()
    except:
        text = None

    if text == None:
        return html
    else:
        return text

def xml2plain(elem, buf):
    if elem.text:
        buf.write(elem.text)

    for item in elem:
        xml2plain(item, buf)

    if elem.tail:
        buf.write(elem.tail)

def htmlelem2plain(elem):
    html, text = '', None

    if elem != None:
        try:
            buf = StringIO()
            xml2plain(elem, buf)
            html = buf.getvalue()
            text = html2plain(html)
        except:
            pass

    return text or html
        

def remove_after(elem):
    parent = elem.getparent()
    while parent is not None:
        while elem.getnext() is not None:
            parent.remove(elem.getnext())

        elem, parent = parent, parent.getparent()

def remove_before(elem):
    parent = elem.getparent()
    while parent is not None:
        while elem.getprevious() is not None:
            parent.remove(elem.getprevious())

        elem, parent = parent, parent.getparent()

def categorise(n):
    result = 0

    if n.tag == 'img':
        src = n.get('src', '')
        if not src or src.find('?') != -1 or src.find('&') != -1 or src.find(';') != -1:
            result = -5
        else:
            if n.get('width', None) and n.get('height', None):
                width, height = int(n.get('width', '0')), int(n.get('height', '0'))
                if width * height > 100*100:
                    result = width * height // 16
                else:
                    result = -3
            else:
                result += 4*(len(n.get('title', '')) + len(n.get('alt', '')))
    elif n.tag in ('dd', 'dt', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7', 'li', 'p'):
        result = 10
    elif n.tag in ('dl', 'ol', 'table', 'ul'):
        result = 1
    elif n.tag == 'a':
        if n.get('onclick', None):
            result = -3
        else:
            result = 0
    elif n.tag in ('a', 'b', 'br', 'em', 'i', 'div', 'small', 'span', 'strong',
                   'tbody', 'td', 'thead', 'tr'):
        result = 0
    elif n.tag in ('blink', 'script'):
        result = -5
    else:
        result = -1

    return result

def textlen(s):
    l = 0, 0

    if s:
        words = s.split()
        l = sum(map(len, words)), len(words) - 1

    return l

def valuate(p):
    l, w, c = 0, 0, 0

    if p.tag != 'p':
        c += 3

    for n in p.iter():
        tl, tw = textlen(n.text)
        l += tl
        w += tw

        if n != p:
            tl, tw = textlen(n.tail)
            l += tl
            w += tw

        val = categorise(n)
        if val > 0:
            l += val
        else:
            c -= val

    return l, w, c

def sumval(v1, v2):
    return (v1[0] + v2[0], v1[1] + v2[1], v1[2] + v2[2])

def clean_imgs(elem):
    for n in elem.iter('img'):
        if categorise(n) < 0:
            n.clear()

    return elem

def extract_content(html):
    topnodes = {}

    for tag in ('p', 'li', 'dd', 'dt'):
        for p in html.iter(tag):
            parent, val = p.getparent(), valuate(p)
            topnodes[parent] = sumval(topnodes.get(parent, (0, 0, 0)), val)

    for p in html.iter('img'):
        l = categorise(p)
        if l > 0:
            parent = p.getparent()
            topnodes[parent] = sumval(topnodes.get(parent, (0, 0, 0)), (l, 1, 1))

    toplist = list(map(lambda x: (x[0], 100*x[1][0]*x[1][1] // (x[1][2] + 5)),
                       topnodes.items()))
    if not toplist:
        return []

    toplist.sort(key=lambda x: x[1], reverse=True)
    if toplist[0][0].tag in ('dl', 'ol', 'ul'):
        weighing = 4
    else:
        weighing = 2

    paths = {}
    for top, l in filter(lambda x: weighing*x[1] >= toplist[0][1], toplist):
        node, nesting = top.getparent(), 2
        while node is not None:
            info = paths.get(node, (0, 0))
            paths[node] = (info[0] + 1, max(info[1], nesting))
            node, nesting = node.getparent(), nesting + 1

    pathlist = list(paths.items())
    pathlist.sort(key=lambda x: x[1], reverse=True)

    maxp = pathlist[0][1][0]
    if maxp > 1:
        pathlist = list(filter(lambda x: x[1][0] >= (maxp + 1) // 2, pathlist))
        pathlist.reverse()

        top, info = pathlist[0]
        pathnr, nesting = info
        if info[0] == maxp // 2:
            for top, info in pathlist[1:]:
                if info[0] != pathnr:
                    pathnr, nesting = info
                    break
    else:
        nesting = 1

    highesthdr, content, visited = 7, [], {}

    for p in top.iter():
        if p == top:
            if p.tag in ('dl', 'ol', 'ul'):
                p.tail = ''
                content.append(p)
                break
            else:
                continue

        if categorise(p) <= 0:
            continue

        if p.tag == 'img':
            parent = p.getparent()
            if parent != top:
                p = parent

        if p.tag.startswith('h'):
            towrite = True
            highesthdr = min(highesthdr, int(p.tag[1]))
        else:
            towrite = False

        encl, parent, i = p, p.getparent(), nesting
        while parent is not None and parent is not top:
            encl, parent = parent, parent.getparent()
            i -= 1

        if not towrite:
            towrite = i > 0

        if towrite:
            if not visited.get(encl):
                for elem in encl.iter():
                    visited[elem] = True

                encl.tail = ''
                content.append(encl)

    remove_after(top)
    if top.getparent() is not None:
        parent = top.getparent()
        parent.remove(top)
    else:
        parent = None

    lowesthdr, headers = None, []

    for i in range(1, highesthdr):
        elem = None
        for elem in html.iter('h%d' % (i,)):
            pass

        if elem is not None:
            elem.tail = ''
            headers.append(elem)
            remove_before(elem)
            elem.getparent().remove(elem)
            lowesthdr = i
            break


    if lowesthdr:
        for elem in html.iter():
            if elem.tag in ('h2', 'h3', 'h4', 'h5', 'h6'):
                elem.tail = ''
                headers.append(elem)
                elem.getparent().remove(elem)

        if parent is not None:
            for elem in parent:
                if type(elem.tag) == type(''):
                    elem.tail = ''
                    headers.append(elem)

    headers.extend(content)
    return list(map(clean_imgs, map(html_cleaner.clean_html, headers)))


if __name__ == '__main__':
    import getopt, requests, sys

    as_html = False
    opts, args = getopt.getopt(sys.argv[1:], 'ht', ['html', 'text'])

    for optname, optval in opts:
        if optname in ('-h', '--html'):
            as_html = True
        elif optname in ('-t', '--text'):
            as_html = True

    sess = requests.Session()

    for url in args:
        if url == '-':
            content, encoding = sys.stdin.buffer.read(), None
        else:
            req = sess.get(url)
            content, encoding = req.content, req.encoding

        if encoding:
            parser = lxml.html.HTMLParser(encoding=encoding)
        else:
            parser = None
        html = lxml.html.document_fromstring(content, parser)

        for frag in extract_content(html):
            content = lxml.html.tostring(frag, encoding='utf-8', method='html').decode('utf-8')
            if as_html:
                sys.stdout.write(content)
            else:
                sys.stdout.write(html2plain(content, True))

            sys.stdout.write('\n')
