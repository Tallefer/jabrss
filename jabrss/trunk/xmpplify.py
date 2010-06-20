#!/usr/bin/python
import re, threading

from xml.etree.cElementTree import Element, TreeBuilder, XMLTreeBuilder


__all__ = [
    'Element',
    'JID',
    'Stanza',
    'XmppStream',
]

_evil_characters = re.compile(r"[\000-\010\013\014\016-\037]", re.UNICODE)
_namespace_map = {
    "http://www.w3.org/XML/1998/namespace": "xml",
}


class Synced_Invoke:
    def __init__(self):
        self._lock, self._queue, self._flag = threading.Lock(), [], False

    def __call__(self, fn, args):
        self._lock.acquire()
        try:
            if self._flag:
                self._queue.append((fn, args))
                return
            else:
                self._flag = True
        finally:
            self._lock.release()

        while True:
            try:
                fn(*args)
            except:
                self._lock.acquire()
                try:
                    del self._queue[:]
                    self._flag = False
                    raise
                finally:
                    self._lock.release()

            self._lock.acquire()
            try:
                if len(self._queue):
                    fn, args = self._queue[0]
                    del self._queue[0]
                else:
                    self._flag = False
                    return
            finally:
                self._lock.release()


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
        self._stream = stream
        self._data, self._elem, self._last, self._tail = [], [], None, None

    def close(self):
        assert len(self._elem) == 0, "missing end tags"
        assert self._last != None, "missing toplevel element"
        return self._last

    def _flush(self):
        if self._data:
            if self._last is not None:
                text = ''.join(self._data)
                if self._tail:
                    assert self._last.tail is None, "internal error (tail)"
                    self._last.tail = text
                else:
                    assert self._last.text is None, "internal error (text)"
                    self._last.text = text
            self._data = []

    def data(self, data):
        if len(self._elem) >= 2:
            self._data.append(data)

    def start(self, tag, attrs):
        if attrs == None:
            attrs = {}
        self._flush()
        self._last = elem = Element(tag, attrs)
        if len(self._elem) == 0:
            self._stream.stream_start(elem)
        if len(self._elem) >= 2:
            self._elem[-1].append(elem)
        self._elem.append(elem)
        self._tail = False
        return elem

    def end(self, tag):
        self._flush()
        self._last = self._elem.pop()
        assert self._last.tag == tag,\
               "end tag mismatch (expected %s, got %s)" % (
                   self._last.tag, tag)
        self._tail = True

        if len(self._elem) == 0:
            self._stream.stream_end(self._last)
        elif len(self._elem) == 1:
            self.element(self._last)

        return self._last

    def element(self, elem):
        if elem.tag[:1] == '{':
            ns, tag = elem.tag[1:].split('}', 1)
            if ns == 'jabber:client' and tag in ('iq', 'presence', 'message'):
                cls = Stanza.__dict__[tag.capitalize()]
                self._stream._call_handler(cls(xmlnode=elem))
            elif ns == 'http://etherx.jabber.org/streams':
                if tag == 'features':
                    self._stream.stream_features(elem)
                elif tag == 'error':
                    self._stream.stream_error(elem)
                else:
                    assert False, 'unknown stream element'
            else:
                assert False, 'unknown top-level tag'
        else:
            assert False, 'unknown top-level tag'


class XmppStream:
    def __init__(self, server, handlers, encoding='utf-8'):
        self._server, self._handlers, self._encoding = server, handlers, encoding
        self._synced_feeder, self._tb, self._disconnected = None, None, False

    def _call_handler(self, stanza):
        key_lookup = {
            'iq' : (Stanza.Iq.tag, Stanza.Iq.get_type),
            'presence' : (Stanza.Presence.tag, Stanza.Presence.get_type),
            'message' : (Stanza.Message.tag, Stanza.Message.get_type),
            }

        fns = key_lookup[stanza.tag()]
        key = tuple([fn(stanza) for fn in fns])
        handler = None
        for i in range(len(key), 0, -1):
            try:
                handler = self._handlers[key[:i]]
            except KeyError:
                pass
            if handler != None:
                handler(stanza)
                break

        if handler == None:
            self.unknown_stanza(stanza)


    def connect(self):
        self._synced_feeder = Synced_Invoke()
        self._tb = XMLTreeBuilder(target=XmppHandler(self))
        self.send(('<?xml version=\'1.0\'?><stream:stream xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client" to="%s" version="1.0">' % (_escape_attrib(self._server),)).encode(self._encoding))

    def disconnect(self):
        if self._tb and not self._disconnected:
            self._disconnected = True
            self.send('</stream:stream>'.encode(self._encoding))
        self.shutdown()


    def stream_start(self, elem):
        pass

    def stream_features(self, elem):
        pass

    def stream_error(self, elem):
        self.disconnect()

    def stream_end(self, elem):
        self.disconnect()
        self._tb = None

    def send(self, data):
        assert False, 'send method not implemented'

    def shutdown(self):
        assert False, 'shutdown method not implemented'

    def unknown_stanza(self, stanza):
        assert False, 'unknown stanza received'


    def feed(self, data):
        cdata = data.decode(self._encoding)
        self._synced_feeder(self._tb.feed, (cdata,))

    def close(self):
        if self._tb != None:
            self._synced_feeder(self._tb.close, ())
        self._synced_feeder(self.closed, ())
