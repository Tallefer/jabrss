#!/usr/bin/python
# Copyright (C) 2004, Christof Meerwald
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
import gdbm, getopt, string, struct, sys, time
import apsw


def str2ids(s):
    ids = []
    for i in range(0, len(s), 4):
        ids.append(s[i:i + 4])

    return ids


def ids2str(ids):
    return string.join(ids, '')


def convert_users(conn):
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
    db = gdbm.open('jabrss_users.db', 'r')
    cursor = conn.cursor()

    s_keys = map(lambda x: x[1:],
                 filter(lambda x: x[0] == 'S' and len(x) == 5, db.keys()))
    s_keys.sort()

    cursor.execute('BEGIN')
    for s_key in s_keys:
        enc_username = db['S' + s_key]
        username = enc_username.decode('utf8')

        uid = struct.unpack('>L', s_key)[0]

        uid_conf = db['U' + enc_username][4:]

        if len(uid_conf) >= 4:
            conf = struct.unpack('>l', uid_conf[:4])[0]
        else:
            conf = 0

        if len(uid_conf) >= 5:
            store_messages = struct.unpack('>B', uid_conf[4])[0]
        else:
            store_messages = 16

        if len(uid_conf) >= 6:
            size_limit = struct.unpack('>B', uid_conf[5])[0]
        else:
            size_limit = None

        if size_limit == 0:
            size_limit = None

        cursor.execute('INSERT INTO user(uid, jid, conf, store_messages, size_limit) VALUES (?, ?, ?, ?, ?)',
                       (uid, username, conf, store_messages, size_limit))

        #  'R' + user_id -> [resource_id (4-byte struct), ...]
        res_ids = []
        try:
            res_ids = str2ids(db['R' + s_key])
        except KeyError:
            pass

        for res in res_ids:
            #  'I' + user_id + resource_id -> headline_id (4-byte struct)
            try:
                seq_nr = struct.unpack('>L', db['I' + s_key + res])[0] + 1
            except KeyError:
                seq_nr = None

            cursor.execute('INSERT INTO user_resource(uid, rid, seq_nr) VALUES (?, ?, ?)',
                           (uid, struct.unpack('>L', res)[0], seq_nr))


        #  'T' + user_id -> stat_start, [nr_headlines]
        try:
            stat_str = db['T' + s_key]

            if len(stat_str) >= 2:
                stat_start = struct.unpack('>h', stat_str[0:2])[0]

            stat_list = []

            for i in range(0, 8):
                stat_entry = [0, 0]

                if len(stat_str) >= (4 + 2*i):
                    stat_entry[0] = struct.unpack('>H', stat_str[2 + 2*i:4 + 2*i])[0]
                if len(stat_str) >= (22 + 4*i):
                    stat_entry[1] = struct.unpack('>l', stat_str[18 + 4*i:22 + 4*i])[0]

                stat_list.append(stat_entry[0])
                stat_list.append(stat_entry[1])

            stat_fields = ''
            for i in range(0, len(stat_list) / 2):
                stat_fields += (', nr_msgs%d, size_msgs%d' % (i, i))

            cursor.execute('INSERT INTO user_stat(uid, start' + stat_fields + ') VALUES (?, ?' + len(stat_list) * ', ?' + ')',
                           tuple([uid, stat_start] + stat_list))
        except KeyError:
            pass


    cursor.execute('COMMIT')
    db.close()


def convert_resources(conn):
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
    db = gdbm.open('jabrss_urls.db', 'r')
    cursor = conn.cursor()

    s_keys = map(lambda x: x[1:],
                 filter(lambda x: x[0] == 'S' and len(x) == 5, db.keys()))
    s_keys.sort()

    for s_key in s_keys:
        cursor.execute('BEGIN')
        enc_url = db['S' + s_key]
        url = enc_url.decode('utf8')

        print 'processing', repr(url)

        rid = struct.unpack('>L', s_key)[0]


        try:
            res_info = tuple(string.split(db['I' + s_key].decode('utf-8'), '\0'))
            res_title, res_link, res_descr = res_info
        except KeyError:
            res_title, res_link, res_descr = (None, None, None)

        try:
            res_error = db['E' + s_key]
        except KeyError:
            res_error = None

        try:
            times_str = db['T' + s_key]
        except KeyError:
            times_str = ''

        if len(times_str) == 8:
            res_last_modified, res_last_updated = struct.unpack('>ll', times_str)
            res_invalid_since = None
        elif len(times_str) == 12:
            res_last_modified, res_last_updated, res_invalid_since = struct.unpack('>lll', times_str)
        else:
            res_last_modified = None
            res_last_updated = None
            res_invalid_since = None

        if res_invalid_since == 0:
            res_invalid_since = None

        if res_last_modified == 0:
            res_last_modified = None

        res_history = []
        try:
            history_str = db['H' + s_key]
            res_seq_nr = struct.unpack('>l', history_str[0:4])[0]
            for i in range(4, len(history_str), 8):
                res_history += list(struct.unpack('>ll',
                                                  history_str[i:i + 8]))
        except KeyError:
            res_seq_nr = 0

        fields_history = ''
        for i in range(0, len(res_history)/2):
            fields_history += ', time_items%d, nr_items%d' % (i, i)

        cursor.execute('INSERT INTO res.resource (rid, url, last_updated, last_modified, invalid_since, err_info, title, description, link) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                       (rid, url, res_last_updated, res_last_modified, res_invalid_since, res_error, res_title, res_descr, res_link))

        cursor.execute('INSERT INTO res.resource_history (rid' + fields_history + ') VALUES (?' + len(res_history) * ', ?' + ')',
                       [rid] + res_history)


        try:
            res_items = map(lambda x: tuple(string.split(x, '\0')), string.split(db['D' + s_key].decode('utf-8'), '\014'))
        except KeyError:
            res_items = []

        i = res_seq_nr
        if i == None:
            i = 0

        for title, link, descr in res_items:
            if descr == '':
                descr = None

            cursor.execute('INSERT INTO res.resource_data (rid, seq_nr, title, link, descr_plain) VALUES (?, ?, ?, ?, ?)',
                           (rid, i, title, link, descr))
            i += 1

        cursor.execute('COMMIT')

    db.close()


conn = apsw.Connection('jabrss.db')
conn.setbusytimeout(3000)
cursor = conn.cursor()
cursor.execute('ATTACH DATABASE "jabrss_res.db" AS res')

convert_users(conn)
convert_resources(conn)
