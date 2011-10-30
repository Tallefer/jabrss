/*
 * Copyright (C) 2008-2011, Christof Meerwald
 * http://cmeerw.org
 */
function updateLinks(reqprefix) {
  var ridlist = '';
  for (var i = 0; i < rids.length; i++) { ridlist += rids[i] + ','; }
  if (ridlist.length != 0) { ridlist = ridlist.substr(0, ridlist.length - 1); }

  var bookmark = $('bookmark');
  bookmark.setAttribute('href', reqprefix + ridlist);
  document.forms[0].action = reqprefix + ridlist;
}

function addFeed(reqprefix, url) {
  var xmlHttp = window.ActiveXObject ? new ActiveXObject("Microsoft.XMLHTTP") : new XMLHttpRequest();
  xmlHttp.onreadystatechange = function() {
    if (xmlHttp.readyState == 4) {
      var rid = xmlHttp.getResponseHeader('X-Feed-Id');
      if (rid) {
        rids[rids.length] = rid;

        var feeds = $('feeds');
        var element = document.createElement('span');
        element.setAttribute('id', 'feed-' + rid);
        element.style.display = 'block';
        element.style.overflow = 'hidden';
        element.style.position = 'absolute';
        element.style.visibility = 'hidden';
        feeds.appendChild(element);
        element.innerHTML = xmlHttp.responseText;
        var height = $(element).getSize().y;
        element.style.height = '0';
        element.style.visibility = '';
        element.style.position = '';

        updateLinks(reqprefix);

        var fx = new Fx.Morph(element,
                              { duration: 1000,
                                onComplete : function() { element.style.height = ''; }});
          fx.start({'height' : [10, height], 'opacity' : [0, 1]});
      } else {
        var errMsg = xmlHttp.getResponseHeader('X-Feed-Error');
        if (errMsg) {
          alert(errMsg);
        }
      }
    }
  }
  xmlHttp.open('POST', reqprefix + '../url', true);
  data = 'url=' + encodeURIComponent(url) + '&reqprefix=' + encodeURIComponent(reqprefix);

  xmlHttp.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
  xmlHttp.setRequestHeader('Content-length', data.length);
  xmlHttp.send(data);
}

function delFeed(reqprefix, rid) {
  var feeds = $('feeds');
  var element = $('feed-' + rid);
  var height = $(element).getSize().y;

  var newrids = [];
  for (var i = 0; i < rids.length; i++) { if (rids[i] != rid) newrids[newrids.length] = rids[i]; }
  rids = newrids;
  updateLinks(reqprefix);

  var fx = new Fx.Morph(element,
                        { duration: 1000,
                          onComplete : function() { feeds.removeChild(element); }});
  fx.start({'height' : [height, 0], 'opacity' : [1, 0]});;
}
