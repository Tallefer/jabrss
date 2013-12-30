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

import lxml.html


def find_enclosing(elem):
    while elem.getparent() is not None and len(elem.getparent()) == 1:
        elem = elem.getparent()
    return elem

def find_real_parent(elem):
    return find_enclosing(elem.getparent())

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


def extract_content(html):
    topnodes = {}

    for p in html.iter('p'):
        parent = find_real_parent(p)
        l = len(b' '.join(lxml.html.tostring(p, encoding='utf-8',
                                             method='text').split()))
        topnodes[parent] = topnodes.get(parent, 0) + l

    toplist = list(topnodes.items())
    toplist.sort(key=lambda x: x[1], reverse=True)

    paths = {}
    for top, l in filter(lambda x: 2*x[1] >= toplist[0][1], toplist):
        node, nesting = top.getparent(), 1
        while node is not None:
            info = paths.get(node, (0, 0))
            paths[node] = (info[0] + 1, max(info[1], nesting))
            node, nesting = node.getparent(), nesting + 1

    pathlist = list(paths.items())
    pathlist.sort(key=lambda x: x[1][0], reverse=True)

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
            continue

        if p.tag in ('img',):
            parent = p.getparent()
            if parent != top:
                p = parent
        elif p.tag not in ('h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ol', 'p', 'table', 'ul'):
            continue

        encl, parent, towrite = find_enclosing(p), find_real_parent(p), False
        for i in range(nesting):
            if parent == None:
                break
            elif parent == top:
                towrite = True
                break

            parent = parent.getparent()

        if p.tag.startswith('h'):
            towrite = True
            highesthdr = min(highesthdr, int(p.tag[1]))

        if towrite:
            if not visited.get(encl):
                for elem in encl.iter():
                    visited[elem] = True

                content.append(encl)

    remove_after(top)
    top.getparent().remove(top)

    lowesthdr, headers = None, []

    for i in range(1, highesthdr):
        elem = None
        for elem in html.iter('h%d' % (i,)):
            pass

        if elem is not None:
            headers.append(find_enclosing(elem))
            remove_before(elem)
            lowesthdr = i
            break

    if lowesthdr:
        for elem in html.iter():
            if elem.tag in ('h2', 'h3', 'h4', 'h5', 'h6'):
                headers.append(find_enclosing(elem))

    headers.extend(content)
    return headers


if __name__ == '__main__':
    import sys

    html = lxml.html.document_fromstring(sys.stdin.buffer.read())

    for frag in extract_content(html):
        sys.stdout.buffer.write(lxml.html.tostring(frag, encoding='utf-8',
                                                   method='xml'))

    sys.stdout.buffer.write(b'\n')
