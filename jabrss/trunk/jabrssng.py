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

import base64, bisect, codecs, getopt, locale, logging, os, ssl, socket
import sqlite3, string, sys, thread, threading, time, traceback, types

from xmpplify import tobytes, Element, JID, Stanza, XmppStream

from parserss import RSS_Resource, RSS_Resource_id2url, RSS_Resource_simplify
from parserss import RSS_Resource_db, RSS_Resource_Cursor
from parserss import UrlError
from parserss import init_parserss


logger = logging.getLogger('JabRSS')

def log_message(*msg):
    logger.info(u' '.join(map(lambda x: unicode(x), msg)))

init_parserss(dbsync_obj = thread.allocate_lock())


TEXT_WELCOME = '''\
Welcome to JabRSS. Please note that the current privacy policy is quite simple: all your data are belong to me and might be sold to your favorite spammer. :-) For more information, please visit the JabRSS Web site at http://jabrss.cmeerw.org

BTW, if you like this service, you can help keeping it running by making a donation, see http://cmeerw.org/donate.html'''

TEXT_NEWUSER = '''

Now there is only one more thing to do before you can use JabRSS: you have to authorize the presence subscription request from JabRSS. This is necessary so that JabRSS knows your presence status and only sends you RSS headlines when you are online.'''

TEXT_HELP = '''\
Supported commands:

subscribe http://host.domain/path/feed.rss
unsubscribe http://host.domain/path/feed.rss
info http://host.domain/path/feed.rss
list
set ( plaintext | chat | headline )
set also_deliver [ Away ] [ XA ] [ DND ]
set header [ Title ] [ URL ]
set subject  [ Title ] [ URL ]
set size_limit <num>
set store_messages <num>
configuration
show statistics
show usage

Please refer to the JabRSS command reference at http://dev.cmeerw.org/book/view/30 for more information.

And of course, if you like this service you might also consider a donation, see http://cmeerw.org/donate.html'''


JABBER_SERVER = None
JABBER_HOST = None
JABBER_USER = None
JABBER_PASSWORD = None
MAX_MESSAGE_SIZE = 20000


opts, args = getopt.getopt(sys.argv[1:], 'f:h:p:s:u:',
                           ['password-file=', 'password=',
                            'server=', 'connect-host=', 'username='])

for optname, optval in opts:
    if optname in ('-f', '--password-file'):
        fd = open(optval, 'r')
        JABBER_PASSWORD = string.strip(fd.readline())
        fd.close()
    elif optname in ('-c', '--connect-host'):
        JABBER_HOST = optval
    elif optname in ('-p', '--password'):
        JABBER_PASSWORD = optval
    elif optname in ('-s', '--server'):
        JABBER_SERVER = optval
    elif optname in ('-u', '--username'):
        JABBER_USER = optval

if JABBER_SERVER == None:
    JABBER_SERVER = raw_input('Jabber server: ')
if JABBER_USER == None:
    JABBER_USER = raw_input('Username: ')
if JABBER_PASSWORD == None:
    JABBER_PASSWORD = raw_input('Password: ')

if JABBER_HOST == None:
    JABBER_HOST = JABBER_SERVER


http_proxy = os.getenv('http_proxy')
if http_proxy and (http_proxy[:7] == 'http://'):
    http_proxy = http_proxy[7:]
    if http_proxy[-1] == '/':
        http_proxy = http_proxy[:-1]
else:
    http_proxy = None

https_proxy = os.getenv('https_proxy')
if https_proxy and (https_proxy[:7] == 'http://'):
    https_proxy = https_proxy[7:]
    if https_proxy[-1] == '/':
        https_proxy = https_proxy[:-1]
else:
    https_proxy = None

socks_proxy = os.getenv('socks_proxy')

RSS_Resource.http_proxy = http_proxy


class Resource_Guard:
    def __init__(self, cleanup_handler):
        self._cleanup_handler = cleanup_handler

    def __del__(self):
        self._cleanup_handler()

def get_db():
    db = sqlite3.Connection('jabrss.db', 60000)
    db.isolation_level = None
    db.cursor().execute('PRAGMA synchronous=NORMAL')

    return db

class Cursor:
    def __init__(self, _db):
        self._txn = False
        self._cursor = _db.cursor()

        db_sync.acquire()

    def __del__(self):
        try:
            if self._txn:
                self._cursor.execute('COMMIT')
        finally:
            db_sync.release()


    def begin(self):
        self._cursor.execute('BEGIN')
        self._txn = True

    def execute(self, stmt, bindings=None):
        if bindings == None:
            return self._cursor.execute(stmt)
        else:
            return self._cursor.execute(stmt, bindings)

    def next(self):
        return self._cursor.next()

    def __getattr__(self, name):
        if name == 'lastrowid':
            return self._cursor.lastrowid
        elif name == 'rowcount':
            return self._cursor.rowcount

        raise AttributeError('object has no attribute \'%s\'' % (name,))

db = get_db()
db_sync = thread.allocate_lock()

main_res_db = RSS_Resource_db()


class DataStorage:
    def __init__(self):
        self._users = {}
        self._users_sync = thread.allocate_lock()
        self._resources = {}
        self._res_uids = {}
        self._resources_sync = thread.allocate_lock()

        self._redirect_db = None


    def _redirect_cb(self, redirect_url, db, redirect_count):
        redirect_resource = self.get_resource(redirect_url, db)

        # prevent resource from being evicted until redirect is processed
        cursor = Cursor(self._redirect_db)
        try:
            try:
                dummy_user.add_resource(redirect_resource, None, cursor)
            except ValueError:
                pass
        finally:
            del cursor

        redirect_resource.unlock()

        new_items, next_item_id, redirect_target, redirect_seq, redirects = redirect_resource.update(db, redirect_count, redirect_cb = storage._redirect_cb)

        if len(new_items) > 0:
            redirect_resource.unlock()
            redirects.insert(0, (redirect_resource, new_items, next_item_id))
        elif (redirect_target != None) or (redirect_resource._invalid_since):
            redirect_resource.lock()
            cursor = Cursor(self._redirect_db)
            try:
                try:
                    dummy_user.remove_resource(redirect_resource, cursor)
                except ValueError:
                    pass
            finally:
                del cursor
            redirect_resource.unlock()

        if redirect_target != None:
            redirect_resource = redirect_target

        return redirect_resource, redirects


    def users_lock(self):
        self._users_sync.acquire()
        return Resource_Guard(lambda sync=self._users_sync: sync.release())

    def resources_lock(self):
        self._resources_sync.acquire()
        return Resource_Guard(lambda sync=self._resources_sync: sync.release())


    # get resource (by URL) from cache, database or create new object
    # @param res_cursor db cursor for resource database
    # @return resource (already locked, must be unlocked)
    def get_resource(self, url, res_db=None, lock=True, follow_redirect=True):
        resource_url = RSS_Resource_simplify(url)

        if lock:
            resources_unlocker = self.resources_lock()
        else:
            resources_unlocker = None

        while resource_url != None:
            cached_resource = True

            try:
                resource = self._resources[resource_url]
                if lock:
                    resources_unlocker = None
                    resource.lock()
                    resources_unlocker = self.resources_lock()
            except KeyError:
                if lock:
                    resources_unlocker = None
                resource = RSS_Resource(resource_url, res_db)
                if lock:
                    resource.lock()
                    resources_unlocker = self.resources_lock()

                cached_resource = False

            if follow_redirect:
                resource_url, redirect_seq = resource.redirect_info(res_db)
            else:
                resource_url, redirect_seq = None, None

            if resource_url != None and lock:
                resource.unlock()

        if not cached_resource:
            self._resources[resource.url()] = resource
            self._resources[resource.id()] = resource
            RSS_Resource.schedule_update(resource)

        del resources_unlocker
        return resource

    # @throws KeyError
    def get_cached_resource(self, url):
        resource_url = RSS_Resource_simplify(url)

        resources_unlocker = self.resources_lock()
        try:
            return self._resources[resource_url]
        finally:
            del resources_unlocker

    def get_resource_by_id(self, res_id, res_db=None, follow_redirect=False):
        resources_unlocker = self.resources_lock()

        try:
            try:
                return self._resources[res_id]
            except KeyError:
                resource_url = RSS_Resource_id2url(res_id)
                return self.get_resource(resource_url, res_db, False,
                                         follow_redirect)
        finally:
            del resources_unlocker

    def evict_resource(self, resource):
        resources_unlocker = self.resources_lock()
        try:
            try:
                del self._resources[resource.url()]
            except KeyError:
                pass
            try:
                del self._resources[resource.id()]
            except KeyError:
                pass

            try:
                del self._res_uids[resource.id()]
            except KeyError:
                pass
        finally:
            del resources_unlocker


    # @precondition self.resources_lock()
    def get_resource_uids(self, resource, db_cursor=None):
        res_id = resource.id()

        try:
            res_uids = self._res_uids[res_id]
        except KeyError:
            res_uids = []

            if db_cursor == None:
                cursor = Cursor(db)
            else:
                cursor = db_cursor

            result = cursor.execute('SELECT uid FROM user_resource WHERE rid=?',
                                    (res_id,))
            for row in result:
                res_uids.append(row[0])

            self._res_uids[res_id] = res_uids


        return res_uids


    # @throws KeyError
    def get_user(self, jid):
        key = jid.bare().tostring().lower()
        jid_resource = jid.resource()
        if jid_resource == None:
            jid_resource = ''
        return self._users[key], jid_resource

    # @throws KeyError
    def get_user_by_id(self, uid):
        return self._users[uid]

    def get_new_user(self, jid, presence_show):
        key = jid.bare().tostring().lower()
        jid_resource = jid.resource()
        if presence_show == None:
            jid_resource = None
        elif jid_resource == None:
            jid_resource = ''

        try:
            user = self._users[key]
            user.set_presence(jid_resource, presence_show)
            return user, jid_resource
        except KeyError:
            user = JabberUser(key, jid_resource, presence_show)

            users_unlocker = self.users_lock()
            self._users[key] = user
            self._users[user.uid()] = user
            del users_unlocker

            for res_id in user._res_ids:
                try:
                    storage.get_resource_by_id(res_id)
                except:
                    log_message('caught exception loading resource', res_id, 'for new user')
                    traceback.print_exc(file=sys.stdout)

            return user, jid_resource

    def evict_user(self, user):
        users_unlocker = self.users_lock()
        try:
            del self._users[user.jid()]
        except KeyError:
            pass

        try:
            del self._users[user.uid()]
        except KeyError:
            pass
        del users_unlocker

    def evict_all_users(self):
        users_unlocker = self.users_lock()
        self._users = {}
        del users_unlocker


    def remove_user(self, user):
        cursor = Cursor(db)
        cursor.begin()

        try:
            cursor.execute('DELETE FROM user WHERE uid=?',
                           (user.uid(),))
        finally:
            del cursor

        log_message('user %s (id %d) deleted' % (user._jid, user._uid))
        self.evict_user(user)



storage = DataStorage()


def strip_resource(jid):
    pos = string.find(jid, '/')
    if pos != -1:
        jid = jid[:pos]

    return jid.lower()

def get_week_nr():
    t = int(time.time())
    gmtime = time.gmtime(t)

    # converting old entries:
    # 1775 + x/7; 1827 + x/7
    week_nr = t - ((gmtime[3]*60 + gmtime[4])*60 + gmtime[5])
    week_nr -= gmtime[6]*24*60*60
    week_nr += 84*60*60
    week_nr /= 7*24*60*60

    return week_nr


class JabberUser:
    ##
    # self._jid
    # self._uid
    # self._uid_str
    # self._res_ids
    # self._configuration & 0x0003 .. message type
    #   (0 = plain text, 1 = headline messages, 2 = chat message, 3 = reserved)
    # self._configuration & 0x001c .. deliver when away
    #   (4 = away, 8 = xa, 16 = dnd)
    # self._configuration & 0x0020 .. migration flag
    # self._configuration & 0x00c0 .. feed title/URL in message subject
    #   (0x40 .. title, 0x80 .. URL)
    # self._configuration & 0x0300 .. feed title/URL in message text
    #   (0x100 .. title, 0x200 .. URL)
    # self._store_messages .. number of messages that should be stored
    # self._size_limit .. limit the size of descriptions
    # self._stat_start .. first week corresponding to _nr_headlines[-1]
    # self._nr_headlines[8] .. number of headlines delivered (per week)
    # self._size_headlines[8] .. size of headlines delivered (per week)
    #
    # self._unknown_msgs .. number of unknown messages received
    ##
    def __init__(self, jid, jid_resource, show=None):
        self._jid = jid
        if jid_resource != None:
            self._jid_resources = {jid_resource : show}
        else:
            self._jid_resources = {}
        self._update_presence()

        self._configuration = 0
        self._store_messages = 16
        self._size_limit = None

        cursor = Cursor(db)

        try:
            cursor.execute('SELECT uid, conf, store_messages, size_limit FROM user WHERE jid=?',
                       (self._jid,))
            self._uid, self._configuration, self._store_messages, self._size_limit = cursor.next()
        except StopIteration:
            cursor.execute('INSERT INTO user (jid, conf, store_messages, size_limit, since) VALUES (?, ?, ?, ?, ?)',
                           (self._jid, self._configuration, self._store_messages, self._size_limit, get_week_nr()))
            self._uid = cursor.lastrowid

        if self._size_limit == None:
            self._size_limit = 0
        else:
            self._size_limit *= 16


        self._res_ids = []
        result = cursor.execute('SELECT rid FROM user_resource WHERE uid=?',
                                (self._uid,))
        for row in result:
            self._res_ids.append(row[0])

        self._stat_start = 0
        self._nr_headlines = []
        self._size_headlines = []
        self._unknown_msgs = 0

        result = cursor.execute('SELECT start, nr_msgs0, nr_msgs1, nr_msgs2, nr_msgs3, nr_msgs4, nr_msgs5, nr_msgs6, nr_msgs7, size_msgs0, size_msgs1, size_msgs2, size_msgs3, size_msgs4, size_msgs5, size_msgs6, size_msgs7 FROM user_stat WHERE uid=?',
                       (self._uid,))
        for row in result:
            self._stat_start = row[0]
            self._nr_headlines = list(row[1:9])
            self._size_headlines = list(row[9:17])

        del cursor
        self._adjust_statistics()


    def _adjust_statistics(self):
        new_stat_start = get_week_nr()
        shift = new_stat_start - self._stat_start

        self._nr_headlines = self._nr_headlines[shift:]
        self._size_headlines = self._size_headlines[shift:]
        self._stat_start = new_stat_start

        if len(self._nr_headlines) < 8:
            self._nr_headlines += (8 - len(self._nr_headlines)) * [0]
        if len(self._size_headlines) < 8:
            self._size_headlines += (8 - len(self._size_headlines)) * [0]

    def _commit_statistics(self, db_cursor=None):
        if db_cursor == None:
            cursor = Cursor(db)
        else:
            cursor = db_cursor

        cursor.execute('INSERT INTO user_stat (uid, start, nr_msgs0, nr_msgs1, nr_msgs2, nr_msgs3, nr_msgs4, nr_msgs5, nr_msgs6, nr_msgs7, size_msgs0, size_msgs1, size_msgs2, size_msgs3, size_msgs4, size_msgs5, size_msgs6, size_msgs7) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                       tuple([self._uid, self._stat_start] + self._nr_headlines + self._size_headlines))

        del cursor


    def uid(self):
        return self._uid

    def jid(self):
        return self._jid


    # @return (day of year, [nr_headlines])
    def get_statistics(self):
        return (self._stat_start, self._nr_headlines, self._size_headlines)


    def set_message_type(self, message_type):
        self._configuration = (self._configuration & ~0x0003) | (message_type & 0x0003)
        self._update_configuration()

    def get_message_type(self):
        return self._configuration & 0x0003


    def set_subject_format(self, format):
        self._configuration = (self._configuration & ~0x00c0) | (((format ^ 0x1) & 0x0003) << 6)
        self._update_configuration()

    def get_subject_format(self):
        return ((self._configuration & 0x00c0) >> 6) ^ 0x1


    def set_header_format(self, format):
        self._configuration = (self._configuration & ~0x0300) | ((format & 0x0003) << 8)
        self._update_configuration()

    def get_header_format(self):
        return (self._configuration & 0x0300) >> 8


    def set_size_limit(self, size_limit):
        if size_limit > 0:
            self._size_limit = min(size_limit, 3072)
        else:
            self._size_limit = 0
        self._update_configuration()

    def get_size_limit(self):
        if self._size_limit > 0:
            return min(self._size_limit, 3072)
        else:
            return 1024


    def set_store_messages(self, store_messages):
        self._store_messages = min(64, max(0, store_messages))
        self._update_configuration()

    def get_store_messages(self):
        return self._store_messages


    def get_deliver_when_away(self):
        return self._configuration & 0x4

    def get_deliver_when_xa(self):
        return self._configuration & 0x8

    def get_deliver_when_dnd(self):
        return self._configuration & 0x10

    def set_delivery_state(self, state):
        self._configuration = (self._configuration & ~0x001c) | ((state & 7) << 2)
        self._update_configuration()
        

    def _update_configuration(self):
        cursor = Cursor(db)
        cursor.execute('UPDATE user SET conf=?, store_messages=?, size_limit=? WHERE uid=?',
                       (self._configuration, self._store_messages, self._size_limit / 16, self._uid))
        del cursor

    def set_configuration(self, conf, store_messages, size_limit):
        self._configuration = conf
        self._store_messages = store_messages
        self._size_limit = size_limit
        self._update_configuration()

    def get_configuration(self):
        return (self._configuration, self._store_messages, self._size_limit)


    def _update_presence(self):
        new_show = -1
        for show in self._jid_resources.values():
            if (show >= 0) and ((show < new_show) or (new_show < 0)):
                new_show = show

        self._show = new_show

    def set_presence(self, jid_resource, show):
        if show == None:
            return

        if show >= 0:
            self._jid_resources[jid_resource] = show
        else:
            try:
                del self._jid_resources[jid_resource]
            except KeyError:
                pass

            if jid_resource == '':
                for res in self._jid_resources.keys():
                    try:
                        del self._jid_resources[res]
                    except KeyError:
                        pass

        self._update_presence()

    # @throws KeyError
    def presence(self, jid_resource=None):
        if jid_resource == None:
            return self._show
        else:
            return self._jid_resources[jid_resource]


    def get_delivery_state(self, presence=None):
        if presence == None:
            presence = self.presence()

        # self._configuration & 0x001c .. deliver when away
        #   (4 = away, 8 = xa, 16 = dnd)
        return (presence in (0, 1)) or \
            ((presence == 2) and (self._configuration & 0x4)) or \
            ((presence == 3) and (self._configuration & 0x8)) or \
            ((presence == 4) and (self._configuration & 0x10))


    def resources(self):
        return self._res_ids

    # @precondition resource.locked()
    # @throws ValueError
    def add_resource(self, resource, seq_nr=None, db_cursor=None):
        res_id = resource.id()
        if res_id not in self._res_ids:
            self._res_ids.append(res_id)

            # also update storage res->uid mapping
            resources_unlocker = storage.resources_lock()
            try:
                res_uids = storage.get_resource_uids(resource, db_cursor)
                res_uids.append(self.uid())
            finally:
                del resources_unlocker

            if db_cursor == None:
                cursor = Cursor(db)
            else:
                cursor = db_cursor

            cursor.execute('INSERT INTO user_resource (uid, rid, seq_nr) VALUES (?, ?, ?)',
                           (self._uid, res_id, seq_nr))
            del cursor
        else:
            raise ValueError(res_id)

    # @precondition resource.locked()
    # @throws ValueError
    def remove_resource(self, resource, db_cursor=None):
        res_id = resource.id()

        self._res_ids.remove(res_id)

        # also update storage res->uid mapping
        resources_unlocker = storage.resources_lock()
        try:
            res_uids = storage.get_resource_uids(resource)
            try:
                res_uids.remove(self.uid())
            except ValueError:
                pass
        finally:
            del resources_unlocker

        if len(res_uids) == 0:
            storage.evict_resource(resource)

        if db_cursor == None:
            cursor = Cursor(db)
        else:
            cursor = db_cursor

        cursor.execute('DELETE FROM user_resource WHERE uid=? AND rid=?',
                       (self._uid, res_id))
        del cursor

    def headline_id(self, resource, db_cursor=None):
        if db_cursor == None:
            cursor = Cursor(db)
        else:
            cursor = db_cursor

        result = cursor.execute('SELECT seq_nr FROM user_resource WHERE uid=? AND rid=?',
                                (self._uid, resource.id()))

        headline_id = None
        for row in result:
            headline_id = row[0]
        del cursor

        if headline_id == None:
            headline_id = 0

        return headline_id


    def update_headline(self, resource, headline_id, new_items=[],
                        db_cursor=None):
        if db_cursor == None:
            cursor = Cursor(db)
            cursor.begin()
        else:
            cursor = db_cursor

        try:
            cursor.execute('UPDATE user_resource SET seq_nr=? WHERE uid=? AND rid=?',
                           (headline_id, self._uid, resource.id()))

            if new_items:
                self._adjust_statistics()
                self._nr_headlines[-1] += len(new_items)
                items_size = reduce(lambda size, x: (size + len(x.title) +
                                                     len(x.link) +
                                                     (x.descr_plain!=None and len(x.descr_plain))),
                                    [0] + new_items)
                self._size_headlines[-1] += items_size
                self._commit_statistics(cursor)

        finally:
            del cursor


class DummyJabberUser(JabberUser):
    def __init__(self):
        self._jid = None
        self._show = 'xa'
        self._jid_resources = {None: self._show}

        self._configuration = 0x20
        self._store_messages = 0
        self._size_limit = 0

        self._uid = -1

        self._res_ids = []

        self._stat_start = 0
        self._nr_headlines = []
        self._size_headlines = []


    def _commit_statistics(self, db_cursor=None):
        pass

    def _update_configuration(self):
        pass



    def _update_presence(self):
        pass

    def get_delivery_state(self, presence=None):
        return False


    # @precondition resource.locked()
    # @throws ValueError
    def add_resource(self, resource, seq_nr=None, db_cursor=None):
        res_id = resource.id()
        log_message('dummy adding res', res_id, len(self._res_ids))

        if res_id not in self._res_ids:
            self._res_ids.append(res_id)

            # also update storage res->uid mapping
            resources_unlocker = storage.resources_lock()
            try:
                res_uids = storage.get_resource_uids(resource, db_cursor)
                res_uids.append(self.uid())
            finally:
                del resources_unlocker
        else:
            raise ValueError(res_id)

    # @precondition resource.locked()
    # @throws ValueError
    def remove_resource(self, resource, db_cursor=None):
        res_id = resource.id()
        log_message('dummy removing res', res_id, len(self._res_ids))

        if len(self._res_ids) == 0:
            return

        self._res_ids.remove(res_id)

        # also update storage res->uid mapping
        resources_unlocker = storage.resources_lock()
        try:
            res_uids = storage.get_resource_uids(resource, db_cursor)
            try:
                res_uids.remove(self.uid())
            except ValueError:
                pass
        finally:
            del resources_unlocker

        if len(res_uids) == 0:
            storage.evict_resource(resource)


    def headline_id(self, resource, db_cursor=None):
        return 0


    def update_headline(self, resource, headline_id, new_items=[],
                        db_cursor=None):
        pass


dummy_user = DummyJabberUser()


class JabRSSStream(XmppStream):
    def __init__(self, jid, host, password, port=5222):
        self.jid, self._host, self._port = jid, host, port
        self._update_queue = []
        self._update_queue_cond = threading.Condition()
        RSS_Resource.schedule_update = self.schedule_update

        self._io_sync = threading.Lock()
        self._roster_id, self._sock, self._encoding = 0, None, 'utf-8'
        self._term, self._term_flag = threading.Event(), False

        handlers = {
            ('iq', 'get') : self.iq_get,
            ('iq', 'set') : self.iq_set,
            ('message', 'normal') : self.message,
            ('message', 'chat') : self.message,
            ('message', 'headline') : self.message_headline,
            ('presence', None) : self.presence_available,
            ('presence', 'unavailable') : self.presence_unavailable,
            ('presence', 'error') : self.presence_unavailable,
            ('presence', 'subscribe') : self.presence_control,
            ('presence', 'subscribed') : self.presence_control,
            ('presence', 'unsubscribe') : self.presence_control,
            ('presence', 'unsubscribed') : self.presence_control,
            }
        XmppStream.__init__(self, self.jid, handlers,
                            encoding=self._encoding,
                            password=password)


    def _stream_closed(self):
        storage.evict_all_users()
        sock = self._sock
        self._sock = None
        return sock


    def connect(self):
        self._sock = socket.create_connection((self._host, self._port))
        log_message('connected to', self._sock.getpeername())
        self._sock.settimeout(600)
        XmppStream.connect(self)


    def sock(self):
        self._io_sync.acquire()
        try:
            return self._sock
        finally:
            self._io_sync.release()

    def send(self, data):
        self._io_sync.acquire()
        try:
            if self._sock != None:
                logger.debug('>>> ' + repr(data))
                try:
                    self._sock.sendall(data)
                except socket.error:
                    self._stream_closed()
                    raise
        finally:
            self._io_sync.release()

    def closed(self):
        log_message('stream closed')
        self._io_sync.acquire()
        try:
            self._stream_closed()
        finally:
            self._io_sync.release()

    def shutdown(self):
        log_message('stream shutdown')
        self._io_sync.acquire()
        try:
            sock = self._stream_closed()
            if sock != None:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except socket.error:
                    pass
        finally:
            self._io_sync.release()


    def terminate(self):
        self._term_flag = True

        self._update_queue_cond.acquire()
        self._update_queue_cond.notifyAll()
        self._update_queue_cond.release()
        self._term.wait()

    def terminated(self):
        return self._term_flag


    def stream_start(self, elem):
        log_message('stream start')

    def stream_features(self, elem):
        log_message('stream features')

    def stream_error(self, elem):
        log_message('stream error')
        storage.evict_all_users()

    def stream_end(self, elem):
        storage.evict_all_users()


    def starttls_proceed(self, elem):
        log_message('starttls proceed')
        self._sock = ssl.wrap_socket(self._sock, do_handshake_on_connect=False)
        self._sock.do_handshake()
        XmppStream.connect(self)

    def starttls_failure(self, elem):
        # we are unable to recover here...
        log_message('starttls failure')
        self._term_flag = True
        self.disconnect()


    def sasl_failure(self, elem):
        # we are unable to recover from these...
        log_message("authentication failed")
        self._term_flag = True
        self.disconnect()

    def sasl_success(self, elem):
        log_message('authenticated')


    def iq_get(self, iq):
        logmsg = ['iq get']
        iq_id, iq_from = iq.get_id(), iq.get_from()
        if iq_id != None:
            logmsg.append(iq_id)
        if iq_from != None:
            logmsg.append(iq_from.tostring())
        query = iq.get_query()
        if query != None:
            logmsg.append(query.tag)
        log_message(' '.join(logmsg))

        if iq_id != None:
            reply = Stanza.Iq(id=iq_id, type='error',
                              from_=iq.get_to(), to=iq_from)
            self.send(reply.asbytes(self._encoding))

    def iq_set(self, iq):
        logmsg = ['iq set']
        iq_id, iq_from = iq.get_id(), iq.get_from()
        if iq_id != None:
            logmsg.append(iq_id)
        if iq_from != None:
            logmsg.append(iq_from.tostring())
        query = iq.get_query()
        if query != None:
            logmsg.append(query.tag)
        log_message(' '.join(logmsg))

        if query != None:
            if query.tag == '{jabber:iq:roster}query':
                item = query.find('{jabber:iq:roster}item')
                if item != None:
                    self.roster_updated(item)
                    if iq_id != None:
                        reply = Stanza.Iq(id=iq_id, type='result',
                                          from_=iq.get_to(), to=iq_from)
                        self.send(reply.asbytes(self._encoding))
                    return

        if iq_id != None:
            reply = Stanza.Iq(id=iq_id, type='error',
                              from_=iq.get_to(), to=iq_from)
            self.send(reply.asbytes(self._encoding))

    def session_start(self):
        log_message('session start')
        iq = Stanza.Iq(type='get', id='roster')
        iq.create_query('jabber:iq:roster')
        self.send(iq.asbytes(self._encoding))

        result = yield 'roster'
        log_message('roster retrieved')
        query = result.get_query()
        self.roster_updated(query.getchildren())

        log_message('sending presence')
        presence = Stanza.Presence()
        self.send(presence.asbytes(self._encoding))
        return

    def unhandled_stanza(self, stanza):
        log_message('unhandled stanza', stanza.tag())


    def _process_help(self, stanza, user):
        reply = Stanza.Message(to = stanza.get_from(),
                               type = stanza.get_type(),
                               subject = stanza.get_subject(),
                               body = TEXT_HELP)
        self.send(reply.asbytes(self._encoding))

    def _process_list(self, stanza, user):
        reply_body = []
        for res_id in user.resources():
            resource = storage.get_resource_by_id(res_id)
            res_updated, res_modified, res_invalid = resource.times()
            if res_invalid == None:
                reply_body.append(resource.url())
            else:
                error_info = resource.error_info()
                if error_info:
                    reply_body.append('%s (Error: %s)' % (resource.url(),
                                                          error_info))
                else:
                    reply_body.append('%s (error)' % (resource.url(),))

        if reply_body:
            reply_body.sort()
            reply_body = '\n'.join(reply_body)
        else:
            reply_body = 'Sorry, you are currently not subscribed to any RSS feeds.'

        reply = Stanza.Message(to = stanza.get_from(),
                               type = stanza.get_type(),
                               subject = stanza.get_subject(),
                               body = reply_body)
        self.send(reply.asbytes(self._encoding))

    def _parse_format(self, args):
        format = 0
        for arg in args:
            if arg.lower() == 'title':
                format |= 1
            elif arg.lower() == 'url' or arg.lower() == 'link':
                format |= 2
            elif arg.lower() == '<empty>':
                format = 0
                break
            else:
                raise Exception('invalid format')
        return format

    def _process_set(self, stanza, user, argstr):
        try:
            arg = string.strip(argstr)
            if arg == 'plaintext':
                user.set_message_type(0)
                reply_body = 'Message type set to "plaintext"'
            elif arg == 'headline':
                user.set_message_type(1)
                reply_body = 'Message type set to "headline"'
            elif arg == 'chat':
                user.set_message_type(2)
                reply_body = 'Message type set to "chat"'
            else:
                args = string.split(arg)
                if args[0] == 'also_deliver':
                    deliver_cfg = 0

                    for s in args[1:]:
                        s = string.lower(s)
                        if s == 'away':
                            deliver_cfg = deliver_cfg | 1
                        elif s == 'xa':
                            deliver_cfg = deliver_cfg | 2
                        elif s == 'dnd':
                            deliver_cfg = deliver_cfg | 4
                        elif s == 'none':
                            pass
                        else:
                            raise Exception('unknown setting for "also_deliver"')

                    user.set_delivery_state(deliver_cfg)
                    reply_body = '"also_deliver" setting adjusted'
                elif args[0] == 'store_messages':
                    store_messages = string.atoi(args[1])
                    user.set_store_messages(store_messages)
                    reply_body = '"store_messages" setting adjusted'
                elif args[0] == 'size_limit':
                    size_limit = string.atoi(args[1])
                    user.set_size_limit(size_limit)
                    reply_body = '"size_limit" setting adjusted'
                elif args[0] == 'header':
                    format = self._parse_format(args[1:])
                    user.set_header_format(format)
                    reply_body = 'header format adjusted'
                elif args[0] == 'subject':
                    format = self._parse_format(args[1:])
                    user.set_subject_format(format)
                    reply_body = 'subject format adjusted'
                else:
                    reply_body = 'Unknown configuration option'
        except:
            reply_body = 'Unknown error setting configuration option'

        reply = Stanza.Message(to = stanza.get_from(),
                               type = stanza.get_type(),
                               subject = stanza.get_subject(),
                               body = reply_body)
        self.send(reply.asbytes(self._encoding))


    def _format_format_conf(self, format):
        format_text = []
        if format & 1:
            format_text.append('title')
        if format & 2:
            format_text.append('url')
        if format_text == []:
            format_text.append('<empty>')

        return ', '.join(format_text)

    def _process_config(self, stanza, user):
        reply_body = ['Current configuration:']

        message_type = user.get_message_type()
        if message_type == 0:
            reply_body.append('message type "plaintext"')
        elif message_type == 1:
            reply_body.append('message type "headline"')
        elif message_type == 2:
            reply_body.append('message type "chat"')
        else:
            reply_body.append('message type <reserved>')

        deliver_when_away = user.get_deliver_when_away()
        deliver_when_xa = user.get_deliver_when_xa()
        deliver_when_dnd = user.get_deliver_when_dnd()
        if deliver_when_away or deliver_when_xa or deliver_when_dnd:
            deliver_list = []
            if deliver_when_away:
                deliver_list.append('Away')
            if deliver_when_xa:
                deliver_list.append('XA')
            if deliver_when_dnd:
                deliver_list.append('DND')
            reply_body.append('Headlines will also be delivered when you are %s' % (', '.join(deliver_list)))

        subject_format = user.get_subject_format()
        reply_body.append('subject format: %s' % (self._format_format_conf(subject_format),))

        header_format = user.get_header_format()
        reply_body.append('header format: %s' % (self._format_format_conf(header_format),))

        store_messages = user.get_store_messages()
        reply_body.append('At most %d headlines will be stored for later delivery' % (store_messages,))

        size_limit = user.get_size_limit()
        if size_limit:
            reply_body.append('The size of a headline message will be limited to about %d bytes' % (size_limit,))

        reply = Stanza.Message(to = stanza.get_from(),
                               type = stanza.get_type(),
                               subject = stanza.get_subject(),
                               body = '\n'.join(reply_body))
        self.send(reply.asbytes(self._encoding))


    def _process_statistics(self, stanza, user):
        cursor = Cursor(db)
        reply_body = ['Statistics:']

        try:
            result = cursor.execute('SELECT count(uid) FROM user')

            total_users = 0
            for row in result:
                total_users = row[0]

            result = cursor.execute('SELECT count(rid) FROM (SELECT DISTINCT rid FROM user_resource)')

            total_resources = 0
            for row in result:
                total_resources = row[0]
        finally:
            del cursor

        reply_body.append('Users online/total: %d/%d' %
                          (len(storage._users) / 2, total_users))
        reply_body.append('RDF feeds used/total: %d/%d' %
                          (len(storage._resources) / 2, total_resources))

        reply = Stanza.Message(to = stanza.get_from(),
                               type = stanza.get_type(),
                               subject = stanza.get_subject(),
                               body = '\n'.join(reply_body))
        self.send(reply.asbytes(self._encoding))


    def _process_usage(self, stanza, user):
        reply_body = ['Usage Statistics:']

        reply_body.append('subscribed to %d feeds' % (len(user.resources())))

        stat_start, nr_headlines, size_headlines = user.get_statistics()
        stat_start = stat_start - (len(nr_headlines) - 1)

        time_base = stat_start * 7*24*60*60 - 60*60*60

        for i in range(0, len(nr_headlines)):
            nr = nr_headlines[i]
            size = size_headlines[i]
            if nr > 0:
                month1, day1 = time.gmtime(time_base)[1:3]
                month2, day2 = time.gmtime(time_base + 6*24*60*60)[1:3]
                if size > 11*1024:
                    size_str = '%d kiB' % (size / 1024,)
                else:
                    size_str = '%d Bytes' % (size,)
                reply_body.append('%d/%d - %d/%d: %d headlines (%s)' % (day1, month1, day2, month2, nr, size_str))

            time_base += 7*24*60*60

        reply = Stanza.Message(to = stanza.get_from(),
                               type = stanza.get_type(),
                               subject = stanza.get_subject(),
                               body = '\n'.join(reply_body))
        self.send(reply.asbytes(self._encoding))

    def _process_subscribe(self, stanza, user, argstr):
        args = string.split(argstr)
        reply_body = None

        for arg in args:
            try:
                url = arg.encode('ascii')

                resource = storage.get_resource(url)
                try:
                    url = resource.url()
                    user.add_resource(resource)

                    new_items, headline_id = resource.get_headlines(0, db=main_res_db)
                    if new_items:
                        self._send_headlines(user, resource, new_items)
                        user.update_headline(resource, headline_id, new_items)
                finally:
                    resource.unlock()

                log_message(user.jid(), 'subscribed to', url)
                reply_body = 'You have been subscribed to %s' % (url,)
            except UrlError, url_error:
                log_message(user.jid(), 'error (%s) subscribing to' % (url_error.args[0],), url)
                reply_body = 'Error (%s) subscribing to %s' % (url_error.args[0], url)
            except ValueError:
                log_message(user.jid(), 'already subscribed to', url)
                reply_body = 'You are already subscribed to %s' % (url,)
            except:
                log_message(user.jid(), 'error subscribing to', url)
                traceback.print_exc(file=sys.stdout)
                reply_body = 'For some reason you couldn\'t be subscribed to %s' % (url,)

            if reply_body:
                reply = Stanza.Message(to = stanza.get_from(),
                                       type = stanza.get_type(),
                                       subject = stanza.get_subject(),
                                       body = reply_body)
                self.send(reply.asbytes(self._encoding))

    def _process_unsubscribe(self, stanza, user, argstr):
        args = string.split(argstr)
        reply_body = None

        for arg in args:
            url = arg.encode('ascii')

            try:
                resource = storage.get_cached_resource(url)
                resource.lock()
                try:
                    user.remove_resource(resource)
                finally:
                    resource.unlock()

                log_message(user.jid(), 'unsubscribed from', url)
                reply_body = 'You have been unsubscribed from %s' % (url,)
            except KeyError:
                reply_body = 'For some reason you couldn\'t be unsubscribed from %s' % (url,)
            except ValueError:
                reply_body = 'No need to unsubscribe, you weren\'t subscribed to %s anyway' % (url,)

            if reply_body:
                reply = Stanza.Message(to = stanza.get_from(),
                                       type = stanza.get_type(),
                                       subject = stanza.get_subject(),
                                       body = reply_body)
                self.send(reply.asbytes(self._encoding))

    def _process_info(self, stanza, user, argstr):
        args = string.split(argstr)
        reply_body = None

        for arg in args:
            url = arg.encode('ascii')

            try:
                resource = storage.get_cached_resource(url)

                last_updated, last_modified, invalid_since = resource.times()
                next_update = resource.next_update(0)
                penalty = resource.penalty()
                history = resource.history()

                text = ['Information about %s' % (url,)]
                text.append('')
                text.append('Last polled: %s GMT' % (time.asctime(time.gmtime(last_updated)),))

                if len(history):
                    text.append('Last updated: %s GMT' % (time.asctime(time.gmtime(history[-1][0])),))
                text.append('Next poll: ca. %s GMT' % (time.asctime(time.gmtime(next_update)),))
                text.append('Update interval: ~%d min' % ((next_update - last_updated) / 60,))
                text.append('Feed penalty: %d (out of 1024)' % (penalty,))

                if invalid_since:
                    error_info = resource.error_info()
                    if error_info:
                        text.append('')
                        text.append('Error: %s' % (error_info,))

                if len(history) >= 4:
                    sum_items = reduce(lambda x, y: (y[0], x[1] + y[1]),
                                       history[1:-1])[1]
                    time_span = history[-1][0] - history[0][0]

                    msg_rate = sum_items / (time_span / 2592000.0)

                    if msg_rate > 150.0:
                        rate_unit = 'day'
                        msg_rate = int(msg_rate / 30.0)
                    elif msg_rate > 22.0:
                        rate_unit = 'week'
                        msg_rate = int(msg_rate / (30.0/7.0))
                    else:
                        rate_unit = 'month'
                        msg_rate = int(msg_rate)

                    text.append('')
                    text.append('Frequency: ~%d headlines per %s' % (msg_rate, rate_unit))

                reply_body = '\n'.join(text)
            except KeyError:
                reply_body = 'No information available about %s' % (url,)

            if reply_body:
                reply = Stanza.Message(to = stanza.get_from(),
                                       type = stanza.get_type(),
                                       subject = stanza.get_subject(),
                                       body = reply_body)
                self.send(reply.asbytes(self._encoding))


    def _unsubscribe_user(self, jid, send_unsubscribed=True):
        presence = Stanza.Presence(to = jid, type = 'unsubscribe')
        self.send(presence.asbytes(self._encoding))

        if send_unsubscribed:
            presence = Stanza.Presence(to = jid, type = 'unsubscribed')
            self.send(presence.asbytes(self._encoding))

    def _remove_user(self, jid):
        self._roster_id += 1
        iq_id = 'r%d' % (self._roster_id,)
        iq = Stanza.Iq(type='set', id=iq_id)
        query = iq.create_query('jabber:iq:roster')
        item = Element('{jabber:iq:roster}item')
        item.set('jid', jid.tostring())
        item.set('subscription', 'remove')
        query.append(item)
        self.send(iq.asbytes(self._encoding))


    # delete all user information from database and evict user
    def _delete_user(self, jid):
        try:
            user, jid_resource = storage.get_new_user(jid, None)
            log_message('deleting user\'s %s subscriptions: %s' % (jid.tostring(), repr(user.resources())))
            for res_id in user.resources():
                resource = storage.get_resource_by_id(res_id)
                resource.lock()
                try:
                    try:
                        user.remove_resource(resource)
                    except ValueError:
                        pass
                finally:
                    resource.unlock()

            storage.remove_user(user)
        except KeyError:
            traceback.print_exc(file=sys.stdout)


    def message(self, stanza):
        typ, sender, body = (stanza.get_type(), stanza.get_from(),
                             stanza.get_body())
        if typ == None or body == None:
            return

        body = string.strip(body)
        log_message('message', typ, sender.tostring(), body)

        if typ in ('normal', 'chat'):
            try:
                user, jid_resource = storage.get_user(sender)
                unknown_msg = False

                if body == 'help':
                    return self._process_help(stanza, user)
                elif body == 'list':
                    return self._process_list(stanza, user)
                elif body[:4] == 'set ':
                    return self._process_set(stanza, user, body[4:])
                elif (body == 'configuration') or (body == 'config'):
                    return self._process_config(stanza, user)
                elif (body == 'statistics') or (body == 'show statistics'):
                    return self._process_statistics(stanza, user)
                elif (body == 'usage') or (body == 'show usage'):
                    return self._process_usage(stanza, user)
                elif body[:10] == 'subscribe ':
                    return self._process_subscribe(stanza, user, body[10:])
                elif body[:12] == 'unsubscribe ':
                    return self._process_unsubscribe(stanza, user, body[12:])
                elif body[:5] == 'info ':
                    return self._process_info(stanza, user, body[5:])
                else:
                    unknown_msg = True
                    # safe-guard against robot ping-pong
                    if user._unknown_msgs < 2:
                        user._unknown_msgs = user._unknown_msgs + 1
                        reply = Stanza.Message(to = stanza.get_from(),
                                               type = stanza.get_type(),
                                               subject = stanza.get_subject(),
                                               body = 'Unknown command. Please refer to the documentation at http://dev.cmeerw.org/book/view/30')
                        self.send(reply.asbytes(self._encoding))

                if not unknown_msg:
                    user._unknown_msgs = 0
            except KeyError:
                traceback.print_exc(file=sys.stdout)
        elif typ == 'error':
            log_message('ignoring error message from', sender.tostring())
        else:
            log_message('ignoring unknown message type from', sender.tostring())

    def message_headline(self, stanza):
        # silently ignore headline messages
        pass

    def presence_available(self, stanza):
        sender, typ, status, show = (stanza.get_from(), stanza.get_type(),
                                     stanza.get_status(), stanza.get_show())
        log_message('presence', sender.tostring(), typ, show)

        try:
            presence = [None, 'chat', 'away', 'xa', 'dnd'].index(show)
        except ValueError:
            return

        user, jid_resource = storage.get_new_user(sender, presence)
        if user.get_delivery_state(presence):
            subs = None

            for res_id in user.resources()[:]:
                resource = storage.get_resource_by_id(res_id)
                if subs != None:
                    subs.append(resource.url())

                try:
                    resource.lock()

                    while True:
                        headline_id = user.headline_id(resource)
                        old_id = headline_id

                        new_items, headline_id = resource.get_headlines(headline_id, db=main_res_db)
                        if new_items:
                            self._send_headlines(user, resource, new_items)

                        redirect_url, redirect_seq = resource.redirect_info(main_res_db)
                        if redirect_url != None:
                            log_message('processing redirect to', redirect_url)

                            try:
                                user.remove_resource(resource)
                            except ValueError:
                                pass
                            resource.unlock()

                            resource = storage.get_resource(redirect_url, None,
                                                            True, False)
                            try:
                                user.add_resource(resource, redirect_seq)
                            except ValueError:
                                pass

                            continue
                        elif new_items or headline_id != old_id:
                            user.update_headline(resource, headline_id,
                                                 new_items)

                        break
                finally:
                    resource.unlock()

    def presence_unavailable(self, stanza):
        sender, typ, status, show = (stanza.get_from(), stanza.get_type(),
                                     stanza.get_status(), stanza.get_show())
        log_message('presence', sender.tostring(), typ, show)
        try:
            user, jid_resource = storage.get_user(sender)
            user.set_presence(jid_resource, -1)
            if user.presence() < 0:
                log_message('evicting user', user.jid())
                storage.evict_user(user)
        except KeyError:
            pass

    def presence_control(self, stanza):
        reply = []
        sender, typ = stanza.get_from(), stanza.get_type()
        log_message('presence_control', sender.tostring(), typ)

        if typ == 'subscribe':
            msg_text = TEXT_WELCOME
            try:
                storage.get_user(sender)
            except KeyError:
                msg_text += TEXT_NEWUSER

            msg =  Stanza.Message(to = stanza.get_from(),
                                  type = 'normal',
                                  body = msg_text)
            self.send(msg.asbytes(self._encoding))

            reply = Stanza.Presence(to = stanza.get_from(),
                                    type = 'subscribed')
            self.send(reply.asbytes(self._encoding))

            subscr = Stanza.Presence(to = stanza.get_from(),
                                     type = 'subscribe')
            self.send(subscr.asbytes(self._encoding))
        if typ == 'unsubscribed':
            self._unsubscribe_user(sender.bare(), False)
            self._remove_user(sender.bare())


    def roster_updated(self, item):
        if type(item) in (types.ListType, types.TupleType):
            subscribers = {}
            for elem in item:
                user, subscription = elem.get('jid'), elem.get('subscription')
                if subscription == 'both':
                    subscribers[user.lower()] = True
                else:
                    log_message('subscription for user "%s" is "%s" (!= "both")' % (user, subscription))
                    jid = JID(user)
                    self._unsubscribe_user(jid)
                    self._remove_user(jid)

            cursor = Cursor(db)
            result = cursor.execute('SELECT jid, uid FROM user')
            delete_users = []
            for username, uid in result:
                if username.find('/') != -1:
                    storage.remove_user(uid)
                elif not subscribers.has_key(username):
                    delete_users.append(username)
                else:
                    subscribers[username] = False

            del cursor

            for username in delete_users:
                log_message('user "%s" in database, but not subscribed to the service' % (username,))
                jid = JID(username)
                self._unsubscribe_user(jid)
                self._delete_user(jid)


            subscribers = filter(lambda x: x[1] == True,
                                 subscribers.items())
            subscribers = map(lambda x: x[0], subscribers)
            week_nr = get_week_nr()

            cursor = Cursor(db)

            for username in subscribers:
                try:
                    cursor.execute('INSERT INTO user (jid, conf, store_messages, size_limit, since) VALUES (?, ?, ?, ?, ?)',
                                   (username, 0, 16, None, week_nr))
                except:
                    pass

            del cursor

            cursor = Cursor(db)
            result = cursor.execute('SELECT jid FROM user LEFT OUTER JOIN user_stat ON (user.uid=user_stat.uid) WHERE since < ? AND (start < ? OR start IS NULL)',
                                    (week_nr - 3, week_nr - 32))
            delete_users = []
            for row in result:
                delete_users.append(row[0])

            del cursor

            for username in delete_users:
                log_message('user "%s" hasn\'t used the service for more than 40 weeks' % (username,))
                jid = JID(username)
                self._unsubscribe_user(jid)
                self._remove_user(jid)
        else:
            jid, subscription = item.get('jid'), item.get('subscription')
            log_message('roster updated', jid, subscription)
            if subscription == 'remove':
                self._delete_user(JID(jid))

    def _format_header(self, title, url, res_url, format):
        if url == '':
            url = res_url

        if format == 1:
            return '%s' % (title,)
        elif format == 2:
            return '%s' % (url,)
        elif format == 3:
            if title != '':
                return '%s: %s' % (title, url)
            else:
                return url

        return ''

    def _send_headlines(self, user, resource, items, not_stored=False):
        log_message('sending', user.jid(), resource.url())
        message_type = user.get_message_type()
        subject_format = user.get_subject_format()
        header_format = user.get_header_format()

        channel_info = resource.channel_info()

        subject_text = self._format_header(channel_info.title, channel_info.link, resource.url(), subject_format)

        if message_type in (0, 2): # normal message or chat
            body = []
            msgs, l = [body], 0
            header_text = self._format_header(channel_info.title, channel_info.link, resource.url(), header_format)
            if header_text != '':
                body.append('[ %s ]\n' % (header_text,))
                l += len(body[-1])

            if not not_stored and (len(items) > user.get_store_messages()):
                body.append('%d headlines suppressed (from %s)\n' % (len(items) - user.get_store_messages(), channel_info.title))
                l += len(body[-1])
                items = items[-user.get_store_messages():]

            if body:
                body.append('\n')
                l += 1

            for item in items:
                try:
                    title, link, descr = (item.title, item.link, item.descr_plain)
                    
                    if not descr or (descr == title):
                        body.append('%s\n%s\n' % (title, link))
                    else:
                        body.append('%s\n%s\n%s\n' % (title, link,
                                                      descr[:user.get_size_limit()]))
                    l += len(body[-1]) + 1
                    body.append('\n')

                    if l >= MAX_MESSAGE_SIZE:
                        l = len(body[-1]) + 1
                        body = []
                        msgs.append(body)
                except ValueError:
                    log_message('trying to unpack tuple of wrong size', repr(item))

            mt = ('normal', 'chat')[message_type != 0]
            for body in msgs:
                if body:
                    msg = Stanza.Message(to = JID(user.jid()),
                                         type = mt,
                                         subject = subject_text,
                                         body = ''.join(body))
                    self.send(msg.asbytes(self._encoding))

        elif message_type == 1:         # headline
            if not not_stored and (len(items) > user.get_store_messages()):
                msg = Stanza.Message(to = JID(user.jid()),
                                     type = 'headline',
                                     subject = subject_text,
                                     body = '%d headlines suppressed' % (len(items) - user.get_store_messages(),))
                oob_ext = msg.create_x('jabber:x:oob')
                oob_ext_url = Element('{jabber:x:oob}url')
                oob_ext_url.text = channel_info.link
                oob_ext.append(oob_ext_url)

                oob_ext_desc = Element('{jabber:x:oob}desc')
                oob_ext_desc.text = channel_info.descr
                oob_ext.append(oob_ext_desc)
                self.send(msg.asbytes(self._encoding))

                items = items[-user.get_store_messages():]

            for item in items:
                title, link = (item.title, item.link)

                if item.descr_plain:
                    description = item.descr_plain
                else:
                    description = title

                msg = Stanza.Message(to = JID(user.jid()),
                                     type = 'headline',
                                     subject = subject_text,
                                     body = description[:user.get_size_limit()])
                oob_ext = msg.create_x('jabber:x:oob')
                oob_ext_url = Element('{jabber:x:oob}url')
                oob_ext_url.text = link
                oob_ext.append(oob_ext_url)

                oob_ext_desc = Element('{jabber:x:oob}desc')
                oob_ext_desc.text = title
                oob_ext.append(oob_ext_desc)
                self.send(msg.asbytes(self._encoding))


    def schedule_update(self, resource):
        self._update_queue_cond.acquire()
        next_update = resource.next_update()
        log_message('scheduling', resource.url(), time.asctime(time.localtime(next_update)))

        bisect.insort(self._update_queue, (next_update, resource))
        if self._update_queue[0] == (next_update, resource):
            self._update_queue_cond.notifyAll()

        self._update_queue_cond.release()

    def run(self):
        db, res_db = None, None

        try:
            time.sleep(20)
            log_message('starting RSS/RDF updater')
            db = get_db()
            res_db = RSS_Resource_db()
            storage._redirect_db = db

            self._update_queue_cond.acquire()
            while not self._term_flag:
                if self._update_queue:
                    timeout = self._update_queue[0][0] - int(time.time())

                    if timeout > 3:
                        if timeout > 300:
                            log_message('updater waiting for %d seconds' % (timeout,))
                        self._update_queue_cond.wait(timeout)
                    else:
                        resource = self._update_queue[0][1]
                        del self._update_queue[0]

                        self._update_queue_cond.release()
                        self._update_resource(resource, db, res_db)
                        self._update_queue_cond.acquire()
                else:
                    log_message('updater queue empty...')
                    self._update_queue_cond.wait()

            self._update_queue_cond.release()
        except:
            log_message('updater thread caught exception...')
            traceback.print_exc(file=sys.stdout)
            sys.exit(1)

        log_message('updater shutting down...')
        del db
        del storage._redirect_db
        del res_db

        self._term.set()


    def _update_resource(self, resource, db, res_db=None):
        redirect_url, redirect_seq = resource.redirect_info(res_db)
        if redirect_url != None:
            return

        cursor = None
        users_unlocker = None
        redirect_resource = None
        redirect_unlock = False
        redirects = []

        resource.lock(); need_unlock = True
        try:
            cursor = Cursor(db)
            uids = storage.get_resource_uids(resource, cursor)
            cursor = None

            users_unlocker = storage.users_lock()
            used = False
            for uid in uids:
                try:
                    user = storage.get_user_by_id(uid)
                    used = True
                except KeyError:
                    pass

            if not used:
                storage.evict_resource(resource)

            users_unlocker = None

            if used:
                resource.unlock(); need_unlock = False
                try:
                    log_message(time.asctime(), 'updating', resource.url())
                    new_items, next_item_id, redirect_resource, redirect_seq, redirects = resource.update(res_db, redirect_cb = storage._redirect_cb)

                    if len(new_items) > 0:
                        need_unlock = True
                    elif redirect_resource != None:
                        resource.lock(); need_unlock = True

                    if redirect_resource != None:
                        redirect_resource.lock(); redirect_unlock = True

                    if len(new_items) > 0 or redirect_resource != None:
                        deliver_users = []
                        cursor = Cursor(db)
                        uids = storage.get_resource_uids(resource, cursor)
                        cursor.begin()
                        for uid in uids:
                            try:
                                user = storage.get_user_by_id(uid)

                                if redirect_resource != None:
                                    try:
                                        user.add_resource(redirect_resource,
                                                          redirect_seq,
                                                          cursor)
                                    except ValueError:
                                        pass
                                    try:
                                        dummy_user.remove_resource(redirect_resource, cursor)
                                    except ValueError:
                                        pass


                                if len(new_items) and user.get_delivery_state():
                                    if redirect_resource == None:
                                        user.update_headline(resource,
                                                             next_item_id,
                                                             new_items, cursor)
                                    else:
                                        try:
                                            user.remove_resource(resource,
                                                                 cursor)
                                        except ValueError:
                                            pass

                                    deliver_users.append(user)

                                elif len(new_items) == 0:
                                    try:
                                        user.remove_resource(resource, cursor)
                                    except ValueError:
                                        pass

                            except KeyError:
                                # just means that the user is no longer online
                                pass

                        # we need to unlock the resource here to
                        # prevent deadlock (the main thread, which is
                        # needed for sending, might be blocked waiting
                        # to acquire resource)
                        cursor = None
                        if need_unlock:
                            resource.unlock(); need_unlock = False

                        if redirect_unlock:
                            redirect_resource.unlock(); redirect_unlock = False

                        for user in deliver_users:
                            self._send_headlines(user, resource, new_items,
                                                 True)
                except:
                    log_message('exception caught updating', resource.url())
                    traceback.print_exc(file=sys.stdout)

                if need_unlock:
                    resource.unlock(); need_unlock = False
                if redirect_unlock:
                    redirect_resource.unlock(); redirect_unlock = False
                if redirect_resource == None:
                    self.schedule_update(resource)
        finally:
	    del cursor
            del users_unlocker
            if need_unlock:
                resource.unlock(); need_unlock = False

        for resource, new_items, next_item_id in redirects:
            deliver_users = []

            # remember to always lock the resource first
            resource.lock(); need_unlock = True
            cursor = Cursor(db)
            cursor.begin()
            try:
                log_message('processing updated resource', resource.url())
                try:
                    dummy_user.remove_resource(resource, cursor)
                except ValueError:
                    pass

                uids = storage.get_resource_uids(resource, cursor)
                for uid in uids:
                    try:
                        user = storage.get_user_by_id(uid)

                        if user.get_delivery_state():
                            headline_id = user.headline_id(resource, cursor)
                            if headline_id < next_item_id:
                                user.update_headline(resource,
                                                     next_item_id,
                                                     new_items, cursor)

                                deliver_users.append(user)
                    except KeyError:
                        # just means that the user is no longer online
                        pass

            finally:
                del cursor
                if need_unlock:
                    resource.unlock(); need_unlock = False

            for user in deliver_users:
                self._send_headlines(user, resource, new_items, True)


def console_handler(bot):
    db = get_db()

    try:
        while True:
            s = raw_input()
            s = ' '.join(map(string.strip, s.split()))

            if s == '':
                pass
            elif s == 'debug locks':
                # show all locked objects
                log_message('db_sync', db_sync.locked())
                log_message('storage._users_sync', storage._users_sync.locked())
                log_message('storage._resources_sync', storage._resources_sync.locked())

                log_message('RSS_Resource._db_sync', RSS_Resource._db_sync.locked())
                for res in storage._resources.values():
                    if res._lock.locked():
                        log_message('resource %s' % (res._url,))

                log_message('done dumping locked objects')
            elif s == 'debug resources':
                resources = storage._resources.keys()
                resources.sort()
                log_message(repr(resources))
            elif s == 'debug users':
                users = storage._users.keys()
                users.sort()
                log_message(repr(users))
            elif s.startswith('dump user '):
                try:
                    user, resource = storage.get_user(JID(s[10:].strip()))

                    log_message('jid: %s, uid: %d' % (repr(user.jid()), user.uid()))
                    log_message('resources: %s' % (repr(user._jid_resources.items()),))
                    log_message('presence: %d' % (user.presence(),))
                    log_message('delivery state: %d' % (user.get_delivery_state(),))
                    log_message('statistics: %s' % (repr(user.get_statistics()),))
                except KeyError:
                    log_message('user not online')
            elif s == 'statistics':
                cursor = Cursor(db)

                try:
                    result = cursor.execute('SELECT count(uid) FROM user')

                    total_users = 0
                    for row in result:
                        total_users = row[0]

                    result = cursor.execute('SELECT count(rid) FROM (SELECT DISTINCT rid FROM user_resource)')

                    total_resources = 0
                    for row in result:
                        total_resources = row[0]
                finally:
                    del cursor

                log_message('Users online/total: %d/%d' % (len(storage._users) / 2,
                                                           total_users))
                log_message('RDF feeds used/total: %d/%d' % (len(storage._resources) / 2, total_resources))

            elif s == 'shutdown':
                break
            else:
                log_message('Unknown command \'%s\'' % (s,))

    except EOFError:
        pass

    # initiate a clean shutdown
    log_message('JabRSS shutting down...')
    del db

    bot.terminate()
    bot.disconnect()


locale.setlocale(locale.LC_CTYPE, '')
encoding = locale.getlocale()[1]
if not encoding:
    encoding = 'us-ascii'
sys.stdout = codecs.getwriter(encoding)(sys.stdout, errors='replace')
sys.stderr = codecs.getwriter(encoding)(sys.stderr, errors='replace')


logger = logging.getLogger()
logger.addHandler(logging.StreamHandler())
#logger.setLevel(logging.DEBUG)
logger.setLevel(logging.INFO)

bot = JabRSSStream(JID('%s@%s/%s' % (JABBER_USER, JABBER_SERVER, 'JabRSS')),
                   JABBER_HOST, JABBER_PASSWORD)
thread.start_new_thread(bot.run, ())
thread.start_new_thread(console_handler, (bot,))


last_attempt, last_idled = 0, 0
while not bot.terminated():
    if last_attempt != 0:
        delay = 15
        if int(time.time()) - last_attempt < 30:
            delay += 45
        log_message('waiting for next connection attempt in', delay, 'seconds')
        time.sleep(delay)

    last_attempt = int(time.time())
    try:
        bot.connect()
    except socket.error:
        continue

    last_attempt = int(time.time())
    try:
        while True:
            sock = bot.sock()
            if sock == None:
                break

            data = sock.recv(4096)
            logger.debug('<<< ' + repr(data))
            if len(data) == 0:
                bot.close()
                break

            bot.feed(data)
    except socket.error:
        log_message('socket error')
    except SyntaxError:
        log_message('syntax error')
    except KeyboardInterrupt:
        bot.terminate()

    try:
        bot.disconnect()
    except:
        pass
    try:
        bot.close()
    except:
        pass

log_message('exiting...')
