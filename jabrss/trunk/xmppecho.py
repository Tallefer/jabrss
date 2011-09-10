#!/usr/bin/python
from __future__ import with_statement

import ssl, socket, threading

from getpass import getpass
from xmpplify import Element, JID, Stanza, XmppStream


class EchoBot(XmppStream):
    def __init__(self, jid, host, password, port=5222):
        self._jid, self._host, self._port = jid, host, port
        self._encoding = 'utf-8'
        self._io_sync = threading.Lock()
        self._closed = threading.Event()

        handlers = {
            ('iq', 'get') : self.handle_iq_get,
            ('iq', 'set') : self.handle_iq_set,
            ('message', 'normal') : self.handle_message,
            ('message', 'chat') : self.handle_message,
            ('presence', None) : self.handle_presence_available,
            ('presence', 'unavailable') : self.handle_presence_unavailable,
            ('presence', 'error') : self.handle_presence_unavailable,
            ('presence', 'subscribe') : self.handle_presence_control,
            ('presence', 'subscribed') : self.handle_presence_control,
            ('presence', 'unsubscribe') : self.handle_presence_control,
            ('presence', 'unsubscribed') : self.handle_presence_control,
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
        self._sock = socket.create_connection((self._host, self._port))
        XmppStream.connect(self)


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


    def handle_iq_get(self, iq):
        print('iq get', iq.get_id())
        query = iq.get_query()
        if query:
            print('iq get', query.tag)

    def handle_iq_set(self, iq):
        print('iq set', iq.get_id())
        query = iq.get_query()
        if query:
            print('iq set', query.tag)

    def session_start(self):
        iq = Stanza.Iq(type='get', id='roster')
        iq.create_query('jabber:iq:roster')
        self.send(iq.asbytes(self._encoding))

        result = yield 'roster'
        presence = Stanza.Presence()
        self.send(presence.asbytes(self._encoding))
        return

    def handle_message(self, message):
        subject, body = message.get_subject(), message.get_body()
        print('message', message.get_from().tostring(), subject, body)
        reply = Stanza.Message(to=message.get_from())
        if subject != None: reply.set_subject('Re: ' + subject)
        if body != None: reply.set_body('> ' + body)
        self.send(reply.asbytes(self._encoding))

    def handle_presence_available(self, presence):
        print('presence available', presence.get_from().tostring(),
              presence.get_show(), presence.get_status(),
              presence.get_priority())

    def handle_presence_unavailable(self, presence):
        print('presence unavailable', presence.get_from().tostring())

    def handle_presence_control(self, presence):
        print('presence', presence.get_type(), presence.get_from().tostring())


if not hasattr(__builtins__, 'raw_input'):
    raw_input = input

jid = JID(raw_input('JID: '))
server = raw_input('server: ')
password = getpass('password: ')

bot = EchoBot(jid, server, password)
bot.connect()

while True:
    try:
        sock = bot.sock()
        if sock == None:
            break

        data = sock.recv(4096)
        if len(data) == 0:
            bot.close()
            break

        bot.feed(data)
    except KeyboardInterrupt:
        print('shutting down')
        bot.disconnect()

bot.wait()
