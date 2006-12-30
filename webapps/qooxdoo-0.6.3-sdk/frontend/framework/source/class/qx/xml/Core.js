/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2006 by 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)

************************************************************************ */

/* ************************************************************************


************************************************************************ */

qx.OO.defineClass("qx.xml.Core");

// Create a XML dom node
qx.xml.Core.createXmlDom = function()
{
  // The Mozilla style
  if (document.implementation && document.implementation.createDocument) {
    return document.implementation.createDocument("", "", null);
  }

  // The Microsoft style
  if (window.ActiveXObject) {
    /*
     According to information on the Microsoft XML Team's WebLog
     it is recommended to check for availability of MSXML versions 6.0 and 3.0.
     Other versions are included for completeness, 5.0 is excluded as it is
     "off-by-default" in IE7 (which could trigger a goldbar).

     http://blogs.msdn.com/xmlteam/archive/2006/10/23/using-the-right-version-of-msxml-in-internet-explorer.aspx
     http://msdn.microsoft.com/library/default.asp?url=/library/en-us/xmlsdk/html/aabe29a2-bad2-4cea-8387-314174252a74.asp

     See similar code in qx.lang.XmlEmu, qx.io.remote.XmlHttpTransport
    */
    var vServers =
    [
      "MSXML2.DOMDocument.6.0",
      "MSXML2.DOMDocument.3.0",
      "MSXML2.DOMDocument.4.0",
      "MSXML2.DOMDocument",  // v3.0
      "MSXML.DOMDocument",   // v2.x
      "Microsoft.XMLDOM"     // v2.x
    ];

    var vObject;

    for (var i=0, l=vServers.length; i<l; i++)
    {

      try
      {
        vObject = new ActiveXObject(vServers[i]);
        break;
      }
      catch(ex)
      {
        vObject = null;
      }
    }

    return vObject;
  }

  throw new Error("This browser does not support xml dom creation.");
};
