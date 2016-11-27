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

import re, sqlite3, sys

if sys.version_info[0] == 2:
    from urlparse import urlsplit, urljoin
else:
    from urllib.parse import urlsplit, urljoin

re_fncall = re.compile('%(([{][a-z]+[}])+)[1-9]')

def hexvalue(c):
    if (c >= '0') and (c <= '9'):
        return ord(c) - ord('0')
    elif (c >= 'A') and (c <= 'Z'):
        return ord(c) - ord('A') + 10
    elif (c >= 'a') and (c <= 'z'):
        return ord(c) - ord('a') + 10

    return None

def hexdecode(s):
    pos = 0

    while True:
        pos = s.find('%', pos)
        if pos == -1:
            break

        highnibble = hexvalue(s[pos + 1])
        lownibble = hexvalue(s[pos + 2])

        s = s[:pos] + chr(highnibble * 16 + lownibble) + s[pos + 3:]
        pos += 1

    return s

def feedsdecode(s):
    return s.replace('0I', '_').replace('0G', '&').replace('0F', '=').replace('0E', '-').replace('0D', '?').replace('0C', '/').replace('0B', '.').replace('0A', '0')

def fixslashes(s):
    mo = re.match('^([a-z]+tp):/([^/].*)', s)
    if mo:
        s = '%s://%s' % (mo.group(1), mo.group(2))

    return s

functions = {
    'feedsdecode' : feedsdecode,
    'fixslashes' : fixslashes,
    'hexdecode' : hexdecode,
}

ranges = {
    'a' : 'a-zA-Z',
    'd' : '0-9',
    'l' : 'a-z',
    'u' : 'A-Z',
    'w' : '0-9a-zA-Z',
}

def pattern_to_regex(pattern):
    result = []

    inset, escaped = False, False

    for c in pattern:
        if escaped:
            repl = ranges.get(c, c)

            if not inset:
                repl = '[' + repl + ']'

            result.append(repl)
            escaped = False
        elif c == '%':
            escaped = True
        elif c == '[':
            inset = True
            result.append(c)
        elif c == ']':
            inset = False
            result.append(c)
        elif c == '\\':
            result.append('\\\\')
        else:
            result.append(c)

    return '^' + ''.join(result) + '$'

def replace_captures(s, mo):
    pos = 0
    while True:
        bpos = s.find('%', pos)
        if bpos == -1:
            break

        pos, fns = bpos, []
        while s[pos + 1] == '{':
            epos = s.index('}', pos + 2)
            fns.append(s[pos + 2:epos])
            pos = epos

        repl = mo.group(int(s[pos + 1]))

        fns.reverse()
        for fn in fns:
            repl = functions[fn](repl)

        s = s[:bpos] + repl + s[pos + 2:]
        pos = bpos + len(repl)

    return s


class NullRewriter:
    def __init__(self):
        pass

    def rewrite(self, orig):
        return orig


class UrlRewriter(NullRewriter):
    def __init__(self, dbname = 'rewrite.db'):
        NullRewriter.__init__(self)
        self.__db = sqlite3.Connection(dbname, 60000)

    def rewrite(self, orig):
        loc = orig

        for i in range(0, 5):
            oldloc = loc
            url = urlsplit(loc)
            host = url.netloc

            for pattern, repl in self.__db.cursor().execute('SELECT pattern, replacement FROM host_rule WHERE hostname=?', (host,)):
                if pattern[0] == '/':
                    pattern = 'https?://[^/]+' + pattern

                mo = re.match(pattern_to_regex(pattern), loc)
                if mo:
                    repl = replace_captures(repl, mo)
                    if repl.startswith('//'):
                        loc = url.scheme + ':' + repl
                    elif repl.startswith('/'):
                        loc = url.scheme + '://' + host + repl
                    else:
                        loc = repl

                    break

            if loc == oldloc:
                break

        return loc


if __name__ == '__main__':
    import sys

    rewriter = UrlRewriter()

    for url in sys.argv[1:]:
        print('%s\n -> %s' % (url, rewriter.rewrite(url)))
