#!/usr/bin/python
# Copyright (C) 2010, Christof Meerwald
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

import base64, re, threading, types

from xml.etree.cElementTree import Element, TreeBuilder, XMLTreeBuilder


__all__ = [
    'tobytes', 'Element',
    'JID', 'Stanza', 'IqError', 'IqTimeout', 'XmppStream',
]

_evil_characters = re.compile(r"[\000-\010\013\014\016-\037]", re.UNICODE)
_namespace_map = {
    "http://www.w3.org/XML/1998/namespace": "xml",
}


def fixtag(tag, default_ns, namespaces, set_default=False):
    namespace_uri, tag = tag[1:].split("}", 1)
    if namespace_uri == default_ns:
        return tag, None
    elif default_ns == None or set_default:
        return tag, ('xmlns', namespace_uri)
    else:
        prefix = namespaces.get(namespace_uri)
        if prefix is None:
            prefix = _namespace_map.get(namespace_uri)
        if prefix is None:
            prefix = 'ns%d' % len(namespaces)
        namespaces[namespace_uri] = prefix
        if prefix == 'xml':
            xmlns = None
        else:
            xmlns = ('xmlns:%s' % prefix, namespace_uri)
        return '%s:%s' % (prefix, tag), xmlns

def _escape_cdata(text):
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    return text

def _escape_attrib(text):
    text = text.replace('&', '&amp;')
    text = text.replace('\'', '&apos;')
    text = text.replace('"', '&quot;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    return text

def write_xml(node, fobj, namespaces={}, default_ns=None):
    tag, items, xmlns_items = node.tag, node.items(), []

    if tag[:1] == '{':
        tag, xmlns = fixtag(tag, default_ns, namespaces, True)
        if xmlns:
            xmlns_items.append(xmlns)
            default_ns = xmlns[1]

    fobj.write('<' + tag)

    for k, v in xmlns_items:
        fobj.write(' %s="%s"' % (k, _escape_attrib(v)))
    for k, v in items:
        if k[:1] == '{':
            k, xmlns = fixtag(k, default_ns, namespaces)
            if xmlns: xmlns_items.append(xmlns)
        fobj.write(' %s="%s"' % (k, _escape_attrib(v)))

    if node.text or len(node):
        fobj.write('>')
        if node.text:
            fobj.write(_escape_cdata(node.text))
        for n in node:
            write_xml(n, fobj, namespaces, default_ns)
        fobj.write('</' + tag + '>')
    else:
        fobj.write(' />')

    for k, v in xmlns_items:
        if v != default_ns:
            del namespaces[v]

    if node.tail:
        fobj.write(_escape_cdata(node.tail))

def tobytes(node, encoding='utf-8'):
    class writer:
        def __init__(self, encoding):
            self._encoding = encoding
            self._data = []

        def data(self):
            return b''.join(self._data)

        def write(self, data):
            self._data.append(_evil_characters.sub(' ', data).encode(self._encoding))

    fobj = writer(encoding)
    write_xml(node, fobj)
    return fobj.data()


class JID:
    def __init__(self, jid):
        self._jid = jid
        parts = jid.split('@', 1)
        if len(parts) == 2:
            self._user = parts[0]
        else:
            self._user = None

        parts = parts[-1].split('/', 1)
        self._domain = parts[0]
        if len(parts) == 2:
            self._resource = parts[1]
        else:
            self._resource = None

    def as_unicode(self):
        return self._jid

    def tostring(self):
        return self._jid

    def user(self):
        return self._user

    def domain(self):
        return self._domain

    def resource(self):
        return self._resource

    def bare(self):
        return JID(self._user + '@' + self._domain)

    def __eq__(self, other):
        if other == None:
            return False
        elif not isinstance(other, JID):
            return False

        return (self._user == other._user and
                self._domain == other._domain and
                self._resource == other._resource)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __cmp__(self, other):
        a = self.tostring()
        return cmp(a, other)

    def __hash__(self):
        return hash(self._user) ^ hash(self._domain) ^ hash(self._resource)


class IqError(Exception):
    def __init__(self, stanza):
        self.__stanza = stanza

    def stanza(self):
        return self.__stanza

class IqTimeout(Exception):
    pass


class Stanza:
    class Base:
        def __init__(self, xmlnode, **kwargs):
            self._xmlnode = xmlnode
            if xmlnode.tag[:1] == '{':
                self._tag = xmlnode.tag[1:].split('}', 1)[1]

            for k, v in kwargs.items():
                if k[-1:] == '_': k = k[:-1]
                setter = getattr(self, 'set_' + k)
                setter(v)

        def _get_text(self, tag):
            elem = self._xmlnode.find(tag)
            if elem != None: return elem.text
            else: return None

        def _set_text(self, tag, text):
            elem = self._xmlnode.find(tag)
            if text != None:
                if elem == None:
                    elem = Element(tag)
                    self._xmlnode.append(elem)
                elem.text = text

        def _create_elem(self, ns, tag):
            elem = Element('{%s}%s' % (ns, tag))
            self._xmlnode.append(elem)
            return elem

        def _get_elem(self, tag):
            for elem in self._xmlnode.getchildren():
                if elem.tag[:1] == '{' and elem.tag.split('}', 1)[1] == tag:
                    return elem
            return None

        def asbytes(self, encoding='utf-8'):
            return tobytes(self._xmlnode, encoding)

        def xmlnode(self):
            return self._xmlnode

        def tag(self):
            return self._tag


        def get_from(self):
            attr = self._xmlnode.get('from', None)
            if attr: return JID(attr)
            else: return None

        def set_from(self, jid):
            if jid != None:
                self._xmlnode.attrib['from'] = jid.tostring()

        def get_to(self):
            attr = self._xmlnode.get('to', None)
            if attr: return JID(attr)
            else: return None

        def set_to(self, jid):
            if jid != None:
                self._xmlnode.attrib['to'] = jid.tostring()

        def get_type(self):
            return self._xmlnode.get('type', None)

        def set_type(self, typ):
            if typ != None:
                self._xmlnode.attrib['type'] = typ

        def get_id(self):
            return self._xmlnode.get('id', None)

        def set_id(self, val):
            if val != None:
                self._xmlnode.attrib['id'] = val


        def create_error(self):
            return self._create_elem('jabber:client', 'error')

        def get_error(self):
            return self._xmlnode.find('{jabber:client}error')


        def create_x(self, ns):
            return self._create_elem(ns, 'x')

        def get_x(self):
            return self._get_elem('query')

        def get_x_ns(self):
            x = self.get_x()
            if x != None: return x.tag[1:].split('}')[0]
            else: return None


    class Iq(Base):
        def __init__(self, xmlnode=None, **kwargs):
            if xmlnode == None: xmlnode = Element('{jabber:client}iq')
            Stanza.Base.__init__(self, xmlnode, **kwargs)

        def create_query(self, ns):
            return self._create_elem(ns, 'query')

        def get_query(self):
            return self._get_elem('query')

        def get_query_ns(self):
            query = self.get_query()
            if query != None: return query.tag[1:].split('}')[0]
            else: return None


    class Presence(Base):
        def __init__(self, xmlnode=None, **kwargs):
            if xmlnode == None: xmlnode = Element('{jabber:client}presence')
            Stanza.Base.__init__(self, xmlnode, **kwargs)


        def get_show(self):
            return self._get_text('{jabber:client}show')

        def set_show(self, show):
            return self._set_text('{jabber:client}show', show)

        def get_status(self):
            return self._get_text('{jabber:client}status')

        def set_status(self, status):
            return self._set_text('{jabber:client}status', status)

        def get_priority(self):
            return self._get_text('{jabber:client}priority')

        def set_priority(self, priority):
            return self._set_text('{jabber:client}priority', priority)


    class Message(Base):
        def __init__(self, xmlnode=None, **kwargs):
            if xmlnode == None: xmlnode = Element('{jabber:client}message')
            Stanza.Base.__init__(self, xmlnode, **kwargs)

        def get_subject(self):
            return self._get_text('{jabber:client}subject')

        def set_subject(self, text):
            return self._set_text('{jabber:client}subject', text)

        def get_body(self):
            return self._get_text('{jabber:client}body')

        def set_body(self, text):
            return self._set_text('{jabber:client}body', text)


class XmppHandler:
    def __init__(self, stream):
        self.__stream = stream
        self.__data, self.__elem, self.__last, self.__tail = [], [], None, None

    def close(self):
        assert len(self.__elem) == 0, "missing end tags"
        assert self.__last != None, "missing toplevel element"
        return self.__last

    def __flush(self):
        if self.__data:
            if self.__last is not None:
                text = ''.join(self.__data)
                if self.__tail:
                    assert self.__last.tail is None, "internal error (tail)"
                    self.__last.tail = text
                else:
                    assert self.__last.text is None, "internal error (text)"
                    self.__last.text = text
            self.__data = []

    def data(self, data):
        if len(self.__elem) >= 2:
            self.__data.append(data)

    def start(self, tag, attrs):
        if attrs == None:
            attrs = {}
        self.__flush()
        self.__last = elem = Element(tag, attrs)
        if len(self.__elem) == 0:
            self.__stream._stream_start(elem)
        if len(self.__elem) >= 2:
            self.__elem[-1].append(elem)
        self.__elem.append(elem)
        self.__tail = False
        return elem

    def end(self, tag):
        self.__flush()
        self.__last = self.__elem.pop()
        assert self.__last.tag == tag,\
               "end tag mismatch (expected %s, got %s)" % (
                   self.__last.tag, tag)
        self.__tail = True

        if len(self.__elem) == 0:
            self.__stream._stream_end(self.__last)
        elif len(self.__elem) == 1:
            self.element(self.__last)

        return self.__last

    def element(self, elem):
        if elem.tag[:1] == '{':
            ns, tag = elem.tag[1:].split('}', 1)
            if ns == 'jabber:client' and tag in ('iq', 'presence', 'message'):
                cls = Stanza.__dict__[tag.capitalize()]
                self.__stream._call_handler(cls(xmlnode=elem))
            elif ns == 'http://etherx.jabber.org/streams':
                if tag == 'features':
                    self.__stream._stream_features(elem)
                elif tag == 'error':
                    self.__stream._stream_error(elem)
                else:
                    assert False, 'unknown stream element'
            elif ns == 'urn:ietf:params:xml:ns:xmpp-sasl':
                if tag == 'challenge':
                    self.__stream._sasl_challenge(elem)
                elif tag == 'failure':
                    self.__stream._sasl_failure(elem)
                elif tag == 'success':
                    self.__stream._sasl_success(elem)
            elif ns == 'urn:ietf:params:xml:ns:xmpp-tls':
                if tag == 'proceed':
                    self.__stream._starttls_proceed(elem)
                elif tag == 'failure':
                    self.__stream._starttls_failure(elem)
            else:
                assert False, 'unknown top-level tag'
        else:
            assert False, 'unknown top-level tag'


class XmppStream:
    def __init__(self, jid, handlers, encoding='utf-8', password=None,
                 prefer_tls=False):
        self.__jid, self.__password = jid, password
        self.__prefer_tls = prefer_tls
        self.__handlers, self.__encoding = handlers, encoding
        self.__synced_feeder, self.__tb, self.__stream_open = None, None, False

        self.__iq_handlers = {}
        self.__iq_handler_sync = threading.Lock()


    def register_iq_handler(self, regid, handler):
        if regid != None:
            self.__iq_handler_sync.acquire()
            try:
                self.__iq_handlers[regid] = handler
            finally:
                self.__iq_handler_sync.release()

    def __do_callback(self, cb, args=()):
        result = cb(*args)
        if type(result) == types.GeneratorType:
            self.register_iq_handler(result.send(None), result)
        else:
            return result

    def _call_handler(self, stanza):
        key = (stanza.tag(), stanza.get_type())
        if key in (('iq', 'result'), ('iq', 'error')):
            msgid = stanza.get_id()
            iq_handler = None
            try:
                self.__iq_handler_sync.acquire()
                try:
                    iq_handler = self.__iq_handlers[msgid]
                    del self.__iq_handlers[msgid]
                finally:
                    self.__iq_handler_sync.release()
            except KeyError:
                pass

            if iq_handler != None:
                try:
                    if stanza.get_type() == 'result':
                        reg = iq_handler.send(stanza)
                    else:
                        reg = iq_handler.throw(IqError(stanza))

                    self.register_iq_handler(reg, iq_handler)
                except StopIteration:
                    pass

                return

        handler = None
        for i in range(len(key), 0, -1):
            try:
                handler = self.__handlers[key[:i]]
            except KeyError:
                pass
            if handler != None:
                self.__do_callback(handler, (stanza,))
                break

        if handler == None:
            self.unhandled_stanza(stanza)


    def connect(self):
        self.__tb = XMLTreeBuilder(target=XmppHandler(self))
        self.send(('<?xml version=\'1.0\'?><stream:stream xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client" to="%s" version="1.0">' % (_escape_attrib(self.__jid.domain()),)).encode(self.__encoding))
        self.__stream_open = True

    def disconnect(self):
        if self.__stream_open:
            self.__stream_open = False
            self.send('</stream:stream>'.encode(self.__encoding))

    def feed(self, data):
        self.__tb.feed(data)

    def close(self):
        self.__tb.close()
        if self.__tb != None:
            self.__synced_feeder, self.__tb = None, None
            self.closed()


    def _stream_start(self, elem):
        self.stream_start(elem)


    def __bind_and_start_session(self, elem):
        if elem.find('{urn:ietf:params:xml:ns:xmpp-bind}bind') != None:
            iq = Stanza.Iq(type='set', id='xmpplify_bind')
            bind = Element('{urn:ietf:params:xml:ns:xmpp-bind}bind')
            resource = Element('{urn:ietf:params:xml:ns:xmpp-bind}resource')
            resource.text = self.__jid.resource()
            if not resource.text:
                resource.text = 'xmpplify'
            bind.append(resource)
            iq.xmlnode().append(bind)
            self.send(iq.asbytes(self.__encoding))

            stanza = yield 'xmpplify_bind'

        if elem.find('{urn:ietf:params:xml:ns:xmpp-session}session') != None:
            iq = Stanza.Iq(type='set', id='xmpplify_session')
            session = Element('{urn:ietf:params:xml:ns:xmpp-session}session')
            iq.xmlnode().append(session)
            self.send(iq.asbytes(self._encoding))

            stanza = yield 'xmpplify_session'

        self.__do_callback(self.session_start)
        return


    def _stream_features(self, elem):
        sasl_mechanisms = [mech.text for mech in elem.findall('{urn:ietf:params:xml:ns:xmpp-sasl}mechanisms/{urn:ietf:params:xml:ns:xmpp-sasl}mechanism')]

        starttls = elem.find('{urn:ietf:params:xml:ns:xmpp-tls}starttls')
        if starttls != None:
            required = starttls.find('{urn:ietf:params:xml:ns:xmpp-tls}required')
            if required != None or self.__prefer_tls:
                starttls = Element('{urn:ietf:params:xml:ns:xmpp-tls}starttls')
                self.send(tobytes(starttls, self.__encoding))
                return

        if ('PLAIN' in sasl_mechanisms) and (self.__password != None):
            # try SASL PLAIN authentication
            auth = Element('{urn:ietf:params:xml:ns:xmpp-sasl}auth')
            auth.set('mechanism', 'PLAIN')
            auth.text = base64.b64encode(('\x00%s\x00%s' % (self.__jid.user(), self.__password)).encode('utf-8')).decode('ascii').strip()
            self.send(tobytes(auth, self.__encoding))
            return

        self.__do_callback(self.__bind_and_start_session, (elem,))
        self.__do_callback(self.stream_features, (elem,))

    def _stream_error(self, elem):
        self.stream_error(elem)
        self.disconnect()
        self.shutdown()

    def _stream_end(self, elem):
        self.stream_end(elem)
        self.disconnect()
        self.shutdown()


    def _sasl_challenge(self, elem):
        self.sasl_challenge(elem)

    def _sasl_failure(self, elem):
        self.sasl_failure(elem)

    def _sasl_success(self, elem):
        self.sasl_success(elem)
        XmppStream.connect(self)


    def _starttls_proceed(self, elem):
        self.starttls_proceed(elem)

    def _starttls_failure(self, elem):
        self.starttls_failure(elem)


    def stream_start(self, elem):
        pass

    def stream_features(self, elem):
        pass

    def stream_error(self, elem):
        pass

    def stream_end(self, elem):
        pass

    def sasl_challenge(self, elem):
        pass

    def sasl_failure(self, elem):
        pass

    def sasl_success(self, elem):
        pass

    def session_start(self):
        pass

    def starttls_proceed(self, elem):
        pass

    def starttls_failure(self, elem):
        pass


    def send(self, data):
        assert False, 'send method not implemented'

    def shutdown(self):
        pass

    def closed(self):
        pass

    def unhandled_stanza(self, stanza):
        pass
