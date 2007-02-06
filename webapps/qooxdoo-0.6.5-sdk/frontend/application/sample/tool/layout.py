#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, os, optparse, codecs



basic = u"""
qx.log.Logger.ROOT_LOGGER.removeAllAppenders();
qx.log.Logger.ROOT_LOGGER.addAppender(new qx.log.DivAppender("demoDebug"));

document.write('<div id="demoHead">qooxdoo: <span>The new era of web development</span></div>');
document.write('<div id="demoFoot">');
document.write('[<a href="javascript:qx.dev.Pollution.consoleInfo(\"window\");">Global Pollution</a>] &#160;');
document.write('[<a href="javascript:qx.core.Object.summary();">Object Summary</a>] &#160;');
document.write('</div>');
document.write('<div id="demoDebug"></div>');
document.write('<div id="demoFrame">&#160;</div>');

(function(sitemap)
{
  document.write('<select id="demoFiles" onchange="if(this.options[this.selectedIndex].value)window.location.href=this.options[this.selectedIndex].value">');
  var url = window.location.pathname.split('/');
  var basename = window.location.href.substring(0, window.location.href.lastIndexOf("/"));
  var cat = url[url.length-2];
  var file = url[url.length-1];

  var pages = sitemap[cat];
  pages.sort();

  var index = pages.indexOf(file);
  
  for( var i=0; i<pages.length; i++ )
  {
    var href = window.location.href;
    var page = cat + "/" + pages[i];
    var pageuri = "../" + page;
    var pageid = pages[i].replace(".html", "").replace("_", " ");
    document.write('<option value="' + pageuri + '"');
    if(href.lastIndexOf(page) === href.length-page.length) {
      document.write(' selected="selected"');
    
    }
    document.write('>' + pageid + '</option>');
  }
  document.write('</select>');
  
  document.write('<div id="demoJump">');
  if (index > 0) {
    document.write("<button onclick='window.location.href=\\"" + basename + '/' + pages[index-1] + "\\"'>&lt;</button>");
  }
  if (index < pages.length-1) {
    document.write("<button onclick='window.location.href=\\"" + basename + '/' + pages[index+1] + "\\"'>&gt;</button>");
  }
  document.write('</div>');
 
})(%s);

(function()
{
  var url = location.href;
  var pos = url.indexOf("/html/")+6;
  var split = url.substring(pos).split("/");
  var category = split[0];
  category = category.charAt(0).toUpperCase() + category.substring(1);
  var pagename = split[1].replace(".html", "").replace(/_/g, " ");
  pagename = pagename.charAt(0).toUpperCase() + pagename.substring(1);

  document.title = "qooxdoo » Demo » Sample » " + category + " » " + pagename;

  if (window.location.href.indexOf("demo.qooxdoo.org") != -1)
  {
    document.write('<script type="text/javascript">var a_vars = []; var pagename=""; var phpmyvisitesSite = 5; var phpmyvisitesURL = "http://counter.qooxdoo.org/phpmyvisites.php";</script>');
    document.write('<script type="text/javascript" src="http://counter.qooxdoo.org/phpmyvisites.js"></script>');
    document.write('<script type="text/javascript" src="http://www.google-analytics.com/urchin.js"></script>');
    document.write('<script type="text/javascript">_uacct = "UA-415440-1"; function urchinStart() { urchinTracker() }; if(window.addEventListener)window.addEventListener("load", urchinStart, false); else if(window.attachEvent)window.attachEvent("onload", urchinStart);</script>');
  }
})();
"""


def main(dist, scan):
  res = ""
  res += "{"

  firstCategory = True
  # for category in os.listdir(scan):
  for category in [ "example", "test", "performance" ]:
    if category == ".svn":
      continue

    if not firstCategory:
      res += ","

    res += category + ":["

    firstItem = True
    for item in os.listdir(os.path.join(scan, category)):
      if item == ".svn":
        continue

      if os.path.splitext(item)[1] != ".html":
        continue

      if item == "index.html":
        continue

      if not firstItem:
        res += ","

      res += '"%s"' % item

      firstItem = False

    res += "]"
    firstCategory = False

  res += "}"

  distdir = os.path.dirname(dist)

  if not os.path.exists(distdir):
    os.makedirs(distdir)

  content = basic % res

  outputFile = codecs.open(dist, encoding="utf-8", mode="w", errors="replace")
  outputFile.write(content)
  outputFile.flush()
  outputFile.close()




if __name__ == '__main__':
  try:
    parser = optparse.OptionParser()

    (options, args) = parser.parse_args()

    dist = args[0]
    scan = args[1]

    main(dist, scan)

  except KeyboardInterrupt:
    print
    print "  * Keyboard Interrupt"
    sys.exit(1)
