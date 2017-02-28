# JabRSS

Never miss a headline again! JabRSS is a simple RSS (RDF Site Summary: http://en.wikipedia.org/wiki/RDF_Site_Summary ) headline notification service for Jabber ( http://www.jabber.org/ ). It is released under the GNU General Public License ( http://www.gnu.org/copyleft/gpl.html ).

### Source Code

The complete source code is available from the JabRSS repository ( http://svn.cmeerw.net/src/jabrss/ ).

#### Requirements for Running JabRSS

* Python >= 2.6 or Python >= 3 (tested with Python 2.7 and Python 3.2)
* python-lxml is highly recommended


### Summary of Commands

* `subscribe http://host.domain/path/to/file.rss` -- subscribe to the given RSS URL

* `unsubscribe http://host.domain/path/to/file.rss` -- unsubscribe from the given RSS URL

* `list` -- list currently subscribed RSS URLs (if a URL is marked with "error" it means that the last update of the RSS resource failed for some reason)

* `info http://host.domain/path/to/file.rss` -- display some information about the given RSS URL

* `set plaintext` -- set the message type for headline notifications to normal/plaintext (default)

* `set chat` -- set the message type for headline notifications to chat/plaintext

* `set headline` -- set the message type for headline notifications to headline (please note that not all Jabber clients support headline messages)

* `set also_deliver` [`Away`] [`XA`] [`DND`] -- also deliver headline messages when your presence is "Away", "Extended Away" or "Do Not Disturb" (default is empty)

* `set size_limit` <`number`> -- limit the size of headline message to the specified amount of bytes (default is 1024)

* `set store_messages` <`number`> -- store at most the specified number of messages for later delivery (note that there is a hard limit of 48, default is 16)

* `set header` [`Title`] [`URL`] -- include an optional header line in headline notifications with the title and/or URL of the feed (default is empty)

* `set subject` [`Title`] [`URL`] -- include an optional subject in headline notifications with the title and/or URL of the feed (default is title)

* `configuration` -- displays your current configuration

* `show statistics` -- displays some basic server statistics

* `show usage` -- displays some basic usage statistics

### Usage

First of all you have to subscribe to JabRSS's presence (I am running a JabRSS server with JID jabrss@cmeerw.net) and have to accept the subscription request from JabRSS. Then you can start using it by subscribing to your favorite RSS headlines by sending a subscription command to JabRSS ("subscribe http://some.url/path/to/rss", e.g. send "subscribe http://slashdot.org/slashdot.rdf" to subscribe to Slashdot headlines; or better yet try "subscribe http://cmeerw.org/blog.rdf" which is my Weblog where I will announce JabRSS updates).

If you are looking for other RSS sources, you might want to take a look at Syndic8.com ( http://www.syndic8.com/ ) - just search for a feed and subscribe to the RSS URL via jabrss.

There is also a short description on using JabRSS in Spanish on the Biso*os Usuarios de Linux de Mallorca y Alrededores web site ( http://bulmalug.net/body.phtml?nIdNoticia=1399 ).

### Terms of Use and Privacy Policy

You are invited to use JabRSS at your own risk. But be warned that any abuse will be acted upon.

The service is provided "as is" without warranty of any kind and might be changed or discontinued at any time without prior notice.

Currently, there is no real privacy policy. Any Jabber message sent to JabRSS might be logged and analysed for debugging purposes. No information about you will be passed on to third parties without your permission.

BTW, if you like this service you could also consider a donation ( http://cmeerw.org/donate.html ) to keep it running.

### HTTP Bot Features

* User-Agent header: "JabRSS (http://jabrss.cmeerw.org)"
* conditional HTTP GET (Last-Modified and ETag supported)
* gzip and deflate encoded HTTP requests
* RSS parser supports RSS 0.90, RSS 0.91, RSS 2.0, RDF 1.0 and Atom 0.3
* adaptive polling intervals based on the update frequency of the feed (every 30 minutes up to once per day)
* feeds not supporting conditional HTTP requests will be slightly penalized
* support for widely-used character data encodings (including UTF-8, UTF-16, ISO8859-1)
* mostly compliant with RFC 3023
* proper handling of redirects

### Internals

* SQLite database backend
* multi-threaded architecture: one thread handling the XMPP communication, another thread polling RSS feeds only feeds that are subscribed to by online users will be polled

### Installation

* create the SQLite database:

`sqlite3 jabrss.db <db.sqlite`

* NB: this will create `jabrss.db` and `jabrss_res.db`

* start JabRSS and enjoy
