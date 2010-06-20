#!/usr/bin/python
import socket, threading

from xmpplify import Element, JID, Stanza, XmppStream


class EchoBot(XmppStream):
    def __init__(self, jid, host, password, port=5222):
        self._jid, self._password = jid, password
        self._sock = socket.create_connection((host, port))
        self._encoding = 'utf-8'
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
        XmppStream.__init__(self, self._jid.domain(), handlers, self._encoding)

    def fd(self):
        return self._sock

    def send(self, data):
        self._sock.sendall(data)

    def shutdown(self):
        if not self._closed.is_set():
            try:
                self._sock.shutdown(socket.SHUT_WR)
            finally:
                self._closed.set()

    def wait(self):
        self._closed.wait()


    def stream_start(self, elem):
        pass

    def stream_features(self, elem):
        iq = Stanza.Iq(type='get', id='a1')
        query = iq.create_query('jabber:iq:auth')
        query_username = Element('{jabber:iq:auth}username')
        query_username.text = self._jid.user()
        query.append(query_username)
        query_resource = Element('{jabber:iq:auth}resource')
        query_resource.text = self._jid.resource()
        query.append(query_resource)
        self.send(iq.asbytes(self._encoding))

    def stream_error(self, elem):
        XmppStream.stream_error(self, elem)

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
        if iq.get_id() == 'a1':
            reply = Stanza.Iq(type='set', id='a2')
            query = reply.create_query('jabber:iq:auth')
            query_username = Element('{jabber:iq:auth}username')
            query_username.text = self._jid.user()
            query.append(query_username)
            query_resource = Element('{jabber:iq:auth}resource')
            query_resource.text = self._jid.resource()
            query.append(query_resource)
            query_password = Element('{jabber:iq:auth}password')
            query_password.text = self._password
            query.append(query_password)
            self.send(reply.asbytes(self._encoding))
            return
        elif iq.get_id() == 'a2':
            reply = Stanza.Iq(type='get', id='a3')
            reply.create_query('jabber:iq:roster')
            self.send(reply.asbytes(self._encoding))
            return
        elif iq.get_id() == 'a3':
            reply = Stanza.Presence()
            self.send(reply.asbytes(self._encoding))
            return

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

try:
    while True:
        data = bot.fd().recv(4096)
        if len(data) == 0:
            bot.close()
            break

        bot.feed(data)
except KeyboardInterrupt:
    print('shutting down')

bot.disconnect()
bot.wait()
