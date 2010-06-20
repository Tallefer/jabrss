#!/usr/bin/python
# Copyright (C) 2003, Christof Meerwald
# http://JabXPCOM.sunsite.dk

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
import gdbm, getopt, string, struct, sys, time


CONF_repair = 0

opts, args = getopt.getopt(sys.argv[1:], 'r',
                           ['repair'])

for optname, optval in opts:
    if optname == '-r' or optname == '--repair':
        CONF_repair = 1


def str2ids(s):
    ids = []
    for i in range(0, len(s), 4):
        ids.append(s[i:i + 4])

    return ids


def ids2str(ids):
    return string.join(ids, '')


if CONF_repair:
    db_mode = 'w'
else:
    db_mode = 'r'

##
# Database schema:
#  'D' + 'user@domain' -> flag user for deletion
#  'S' -> user_id sequence number (4-byte struct)
#  'S' + user_id -> 'user@domain'
#  'T' + user_id -> stat_start, [nr_headlines]
#  'U' + 'user@domain' -> user_id (4-byte struct) + configuration
#  'R' + user_id -> [resource_id (4-byte struct), ...]
#  'I' + user_id + resource_id -> headline_id (4-byte struct)
##
db = gdbm.open('jabrss_users.db', db_mode)
udb = gdbm.open('jabrss_urlusers.db', db_mode)


res_users = {}

for res in udb.keys():
    if res[0] != 'R' or len(res) != 5:
        raise 'TODO'

    res_users[res[1:]] = str2ids(udb[res])


usernames = {}
userids = {}
doy = time.gmtime()[7]

s_keys = filter(lambda x: x[0] == 'S' and len(x) == 5, db.keys())
for s_key in s_keys:
    username = db[s_key].decode('utf8')
    usernames[username] = None
    userids[s_key[1:]] = None
    encusername = username.encode('utf8')
    userid = db['U' + encusername][:4]

    inactive = 0
    try:
        stat_start = struct.unpack('>h', db['T' + userid][0:2])[0]
        if stat_start <= doy:
            shift = (doy - stat_start) / 7
        else:
            shift = (doy + 366 - stat_start) / 7

        if shift > 12:
            print 'found inactive user: %s, id %d' % (username.encode('iso8859-1', 'replace'), struct.unpack('>L', userid)[0])
            inactive = 1
    except KeyError:
        print 'found inactive user: %s, id %d (no statistics record at all)' % (username.encode('iso8859-1', 'replace'), struct.unpack('>L', userid)[0])
        inactive = 1

    if inactive:
        if CONF_repair:
            # flag user for deletion
            db['D' + encusername] = ''
    else:
        res_ids = []
        try:
            res_ids = str2ids(db['R' + userid])
        except KeyError:
            pass

        for res in res_ids:
            try:
                res_users[res].remove(userid)
            except ValueError:
                pass
            except KeyError:
                pass


for key in db.keys():
    if key == 'S':
        pass

    elif key[0] == 'D':
        username = key[1:].decode('utf8')
        if not usernames.has_key(username):
            print 'non-existing user %s flagged for deletion' % (username.encode('iso8859-1', 'replace'),)
            if CONF_repair:
                del db[key]
        else:
            print 'user %s flagged for deletion' % (username.encode('iso8859-1', 'replace'),)

    elif key[0] == 'S' and len(key) == 5:
        # we have already handled these
        pass

    elif key[0] == 'T' and len(key) == 5:
        if not userids.has_key(key[1:]):
            print 'found unreferenced statistics record for user-id %d' % struct.unpack('>L', key[1:5])
            if CONF_repair:
                del db[key]

    elif key[0] == 'R' and len(key) == 5:
        if not userids.has_key(key[1:]):
            print 'found unreferenced resource list for user-id %d' % struct.unpack('>L', key[1:5])
            if CONF_repair:
                del db[key]

    elif key[0] == 'I' and len(key) == 9:
        if not userids.has_key(key[1:5]):
            print 'found unreferenced resource information record for user-id %d, resource-id %d' % struct.unpack('>LL', key[1:9])
            if CONF_repair:
                del db[key]
        else:
            res_ids = str2ids(db['R' + key[1:5]])
            try:
                res_ids.index(key[5:9])
            except ValueError:
                print 'found unreferenced resource information record for user-id %d, resource-id %d (user not subscribed)' % struct.unpack('>LL', key[1:9])
                if CONF_repair:
                    del db[key]

    elif key[0] == 'U' and len(key) > 1:
        username = key[1:].decode('utf8')
        if not usernames.has_key(username):
            print 'username record found, but no corresponding user information record present: username "%s", user-id %d' % (username.encode('iso8859-1', 'replace'), struct.unpack('>L', db[key][:4])[0])


for res, users in res_users.items():
    if len(users) > 0:
        orig_users = str2ids(udb['R' + res])
        for u in users:
            orig_users.remove(u)

        print 'found unreferenced resources %d, %s, %s' % (struct.unpack('>L', res)[0], repr(map(lambda x: struct.unpack('>L', x)[0], users)), repr(map(lambda x: struct.unpack('>L', x)[0], orig_users)))
        if CONF_repair:
            orig_users = str2ids(udb['R' + res])
            for u in users:
                orig_users.remove(u)
            users_str = ids2str(orig_users)
            if users_str:
                udb['R' + res] = users_str
            else:
                del udb['R' + res]

if CONF_repair:
    db.reorganize()
    udb.reorganize()

db.close()
udb.close()
