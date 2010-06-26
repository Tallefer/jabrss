#!/usr/bin/python
import socket, threading

from xmpplify import Element, JID, Stanza, XmppStream


class EchoBot(XmppStream):
    def __init__(self, jid, host, password, port=5222):
        self._jid, self._host, self._port = jid, host, port
        self._sock = socket.create_connection((host, port))
        self._encoding = 'utf-8'
        self._io_sync = threading.Lock()
        self._closed = threading.Event()

        handlers = {
            ('iq', 'get') : self.handle_iq_get,
            ('iq', 'set') : self.handle_iq_set,
            ('iq', 'result') : self.handle_iq_result,
            ('iq', 'error') : self.handle_iq_error,
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
                            encoding=self._encoding, password=password)


    def _stream_closed(self):
        sock = self._sock
        self._sock = None
        self._closed.set()
        return sock


    def connect(self):
        self._sock = socket.create_connection((self._host, self._port))
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
                try:
                    self._sock.sendall(data)
                except socket.error:
                    self._stream_closed()
                    raise
        finally:
            self._io_sync.release()

    def closed(self):
        self._io_sync.acquire()
        try:
            self._stream_closed()
        finally:
            self._io_sync.release()

    def shutdown(self):
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

    def wait(self):
        self._closed.wait()


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

    def handle_iq_result(self, iq):
        if iq.get_id() == 'xmpplify_bind':
            reply = Stanza.Iq(type='set', id='xmpplify_session')
            session = Element('{urn:ietf:params:xml:ns:xmpp-session}session')
            reply.xmlnode().append(session)
            self.send(reply.asbytes(self._encoding))
            return
        elif iq.get_id() == 'xmpplify_session':
            reply = Stanza.Iq(type='get', id='roster')
            reply.create_query('jabber:iq:roster')
            self.send(reply.asbytes(self._encoding))
            return
        elif iq.get_id() == 'roster':
            reply = Stanza.Presence()
            self.send(reply.asbytes(self._encoding))
            return
        else:
            print('iq result', iq.get_id())
            query = iq.get_query()
            if query:
                print('iq result', query.tag)

    def handle_iq_error(self, iq):
        print('iq error', iq.get_id())
        error = iq.get_error()
        if error:
            print('iq error', error.tag)

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
password = raw_input('password: ')

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
