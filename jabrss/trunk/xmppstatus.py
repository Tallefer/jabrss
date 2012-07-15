#!/usr/bin/python
# Copyright (C) 2010-2011, Christof Meerwald
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

import bisect, getopt, socket, ssl, sys, threading, time

from getpass import getpass
from xmpplify import Element, JID, Stanza, XmppStream


class StatusBot(XmppStream):
    def __init__(self, jid, host, password, port=5222):
        self._jid, self._host, self._port = jid, host, port
        self._encoding = 'utf-8'
        self._io_sync = threading.Lock()
        self._closed = threading.Event()

        self._event_queue = []
        self._event_queue_cond = threading.Condition()
        self._term, self._term_flag = threading.Event(), False

        handlers = {
            ('message', 'normal') : self.handle_message,
            ('message', 'chat') : self.handle_message,
            ('presence', None) : self.handle_presence_available,
            ('presence', 'unavailable') : self.handle_presence_unavailable,
            ('presence', 'error') : self.handle_presence_unavailable,
            }
        XmppStream.__init__(self, self._jid, handlers,
                            encoding=self._encoding, password=password,
                            prefer_tls=True)


    def _stream_closed(self):
        sock = self._sock
        self._sock = None
        self._closed.set()
        return sock


    def connect(self):
        # resolve addresses manually for compatibility with Python 2.5
        # which doesn't support create_connection
        exc = socket.gaierror(-2, 'Name or service not known')
        for ai in socket.getaddrinfo(self._host, self._port, socket.AF_UNSPEC, socket.SOCK_STREAM):
            try:
                exc = None
                self._sock = socket.socket(ai[0], ai[1], ai[2])
                self._sock.settimeout(30)
                self._sock.connect(ai[4])
                break
            except socket.error as e:
                exc = e

        if exc != None:
            raise exc

        self._sock.settimeout(600)
        XmppStream.connect(self)


    def terminate(self):
        self._term_flag = True

        self._event_queue_cond.acquire()
        self._event_queue_cond.notifyAll()
        self._event_queue_cond.release()
        self._term.wait()

    def terminated(self):
        return self._term_flag


    def sock(self):
        with self._io_sync:
            return self._sock

    def send(self, data):
        with self._io_sync:
            if self._sock != None:
                try:
                    self._sock.sendall(data)
                except socket.error:
                    self._stream_closed()
                    raise

    def closed(self):
        with self._io_sync:
            self._stream_closed()

    def shutdown(self):
        with self._io_sync:
            sock = self._stream_closed()
            if sock != None:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except socket.error:
                    pass

    def wait(self):
        self._closed.wait()


    def starttls_proceed(self, elem):
        self._sock = ssl.wrap_socket(self._sock, do_handshake_on_connect=False)
        self._sock.do_handshake()
        XmppStream.connect(self)

    def starttls_failure(self, elem):
        pass


    def session_start(self):
        iq = Stanza.Iq(type='get', id='roster')
        iq.create_query('jabber:iq:roster')
        self.send(iq.asbytes(self._encoding))

        result = yield 'roster'
        presence = Stanza.Presence()
        presence.set_priority('-100')
        presence.set_type('unavailable')
        self.send(presence.asbytes(self._encoding))
        return

    def handle_message(self, message):
        subject, body = message.get_subject(), message.get_body()
        print('message %s %s %s' % (message.get_from().tostring(), subject, body))

        if message.get_from().bare() == self._jid.bare():
            b = tuple(body.strip().split())
            if b == ('reset',):
                self.reset_events()
            elif b == ('list',):
                reply = Stanza.Message(to=message.get_from())
                if subject != None: reply.set_subject('Re: ' + subject)
                self._event_queue_cond.acquire()
                l = '\n'.join([ '%s %s' % (time.asctime(time.gmtime(item[0])), item[1]) for item in self._event_queue ])
                self._event_queue_cond.release()
                if l:
                    reply.set_body(l)
                else:
                    reply.set_body('nothing')
                self.send(reply.asbytes(self._encoding))
            elif b[0] == 'in' and len(b) >= 3:
                try:
                    ts = int(time.time()) + int(b[1])
                    if b[2] != '-':
                        status = ' '.join(b[2:])
                    else:
                        status = None
                    self.schedule_event(ts, status)
                except ValueError:
                    pass
            elif b[0] == 'at' and len(b) >= 3:
                try:
                    tm = time.gmtime(time.time())
                    hours = b[1].split(':', 2)
                    secs = reduce(lambda x, y: x*60 + y,
                                  [int(v) for v in hours], 0)
                    secs *= 60**(3-len(hours))
                    ts = time.mktime(tm[0:3] + (0, 0, 0) + tm[6:]) + secs
                    if tm[8] == 1:
                        ts -= time.altzone
                    else:
                        ts -= time.timezone
                    if b[2] != '-':
                        status = ' '.join(b[2:])
                    else:
                        status = None
                    self.schedule_event(ts, status)
                except ValueError:
                    pass

    def handle_presence_available(self, presence):
        print('%s presence available %s %s %s %s' % (
                time.asctime(time.localtime(time.time())),
                presence.get_from().tostring(),
                presence.get_show(), presence.get_status(),
                presence.get_priority()))

    def handle_presence_unavailable(self, presence):
        print('%s presence unavailable %s' % (
                time.asctime(time.localtime(time.time())),
                presence.get_from().tostring()))


    def reset_events(self):
        self._event_queue_cond.acquire()
        del self._event_queue[:]
        self._event_queue_cond.notifyAll()
        self._event_queue_cond.release()

    def schedule_event(self, ts, status):
        with self._event_queue_cond:
            bisect.insort(self._event_queue, (ts, status))
            if self._event_queue[0] == (ts, status):
                self._event_queue_cond.notifyAll()

    def run(self):
        try:
            with self._event_queue_cond:
                while not self._term_flag:
                    if self._event_queue:
                        timeout = self._event_queue[0][0] - int(time.time())

                        if timeout > 3:
                            self._event_queue_cond.wait(timeout)
                        else:
                            status = self._event_queue[0][1]
                            del self._event_queue[0]

                            # broadcast new status
                            presence = Stanza.Presence()
                            presence.set_priority('-100')
                            if status:
                                print('%s status %s' % (
                                        time.asctime(time.localtime(time.time())),
                                        status))

                                presence.set_show('xa')
                                presence.set_status(status)
                            else:
                                print('%s offline' % (
                                        time.asctime(time.localtime(time.time())),))

                                presence.set_type('unavailable')

                            self.send(presence.asbytes(self._encoding))
                    else:
                        self._event_queue_cond.wait()
        except:
            traceback.print_exc(file=sys.stdout)
            sys.exit(1)

        self._term.set()


if not hasattr(__builtins__, 'raw_input'):
    raw_input = input


JABBER_JID = None
JABBER_HOST = None
JABBER_PASSWORD = None

opts, args = getopt.getopt(sys.argv[1:], 'j:f:h:p:',
                           ['jid=', 'password-file=', 'password=',
                            'connect-host='])

for optname, optval in opts:
    if optname in ('-f', '--password-file'):
        fd = open(optval, 'r')
        JABBER_PASSWORD = string.strip(fd.readline())
        fd.close()
    elif optname in ('-c', '--connect-host'):
        JABBER_HOST = optval
    elif optname in ('-p', '--password'):
        JABBER_PASSWORD = optval
    elif optname in ('-j', '--jid'):
        JABBER_JID = JID(optval)

if JABBER_JID == None:
    JABBER_JID = JID(raw_input('JID: '))
if JABBER_HOST == None:
    JABBER_HOST = raw_input('Host: ')
if JABBER_PASSWORD == None:
    JABBER_PASSWORD = getpass('Password: ')

if JABBER_HOST == '':
    JABBER_HOST = JABBER_JID.domain()

bot = StatusBot(JABBER_JID, JABBER_HOST, JABBER_PASSWORD)
threading.Thread(target=bot.run, args=())
bot.connect()

last_attempt = 0
while not bot.terminated():
    if last_attempt != 0:
        delay = 15
        if int(time.time()) - last_attempt < 30:
            delay += 45
        print('waiting for next connection attempt in %d seconds' % (delay,))
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

            now = int(time.time())

            data = sock.recv(4096)
            if len(data) == 0:
                bot.close()
                break

            bot.feed(data)
    except socket.error:
        print('socket error')
    except SyntaxError:
        print('syntax error')
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

print('exiting...')
