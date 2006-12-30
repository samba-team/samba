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

#module(dev)

************************************************************************ */

qx.OO.defineClass("qx.dev.Pollution");

qx.Class.names =
{
  "window" : window,
  "document" : document,
  "body" : document.body
}

qx.Class.ignore =
{
  "window" :
  [
    // Firefox
    "__firebug__",
    "Components",
    "controllers",

    // Firefox extension: Firebug
    "console",

    // IE
    "event",
    "offscreenBuffering",
    "clipboardData",
    "clientInformation",
    "Option",
    "Image",
    "external",
    "screenTop",
    "screenLeft",

    // Standard
    "length",
    "window",
    "document",
    "location",
    "navigator",
    "netscape",
    "parent",
    "frames",
    "top",
    "scrollbars",
    "name",
    "scrollX",
    "scrollY",
    "self",
    "screen",
    "history",
    "content",
    "menubar",
    "toolbar",
    "locationbar",
    "personalbar",
    "statusbar",
    "directories",
    "closed",
    "crypto",
    "pkcs11",
    "opener",
    "status",
    "defaultStatus",
    "innerWidth",
    "innerHeight",
    "outerWidth",
    "outerHeight",
    "screenX",
    "screenY",
    "pageXOffset",
    "pageYOffset",
    "scrollMaxX",
    "scrollMaxY",
    "fullScreen",
    "frameElement"
  ],

  "document" :
  [
    "domConfig",
    "location",
    "compatMode",
    "implementation",
    "defaultView",
    "title",
    "body",
    "styleSheets",
    "documentElement",
    "nodeName",
    "nodeType",
    "firstChild",
    "lastChild",
    "doctype",
    "images",
    "applets",
    "links",
    "forms",
    "anchors",
    "cookie",
    "embeds",
    "plugins",
    "designMode",
    "childNodes"
  ],

  "body" :
  [
    "textContent",
    "innerHTML",
    "outerHTML",
    "innerText",
    "outerText",
    "scopeName",
    "parentElement",
    "tagName",
    "filters",
    "contentEditable",
    "document",
    "currentStyle",
    "isMultiLine",
    "clientHeight",
    "clientWidth",

    "lastChild",
    "firstChild",
    "offsetTop",
    "offsetLeft",
    "offsetWidth",
    "offsetHeight",
    "tabIndex",
    "className",
    "attributes",
    "previousSibling",
    "nextSibling",
    "ownerDocument",
    "localName",
    "childNodes",
    "parentNode",
    "nodeType",
    "nodeName",
    "style",

    "scrollTop",
    "scrollLeft",
    "scrollWidth",
    "scrollHeight"
  ]
}

qx.Class.consoleInfo = function(object)
{
  alert("Global namespace is polluted by:\n\n" + qx.dev.Pollution.getTextList(object));
}

qx.Class.extract = function(object)
{
  var ext = [];
  var ign = qx.dev.Pollution.ignore[object];
  var obj = qx.dev.Pollution.names[object];

  for (var key in obj)
  {
    try
    {
      // Ignore null or undefined values
      if (typeof obj[key] == "undefined" || obj[key] === null) {
        continue;
      }

      // Ignore native code
      if (typeof obj[key] == "function" && obj[key].toString().indexOf("[native code]") != -1) {
        continue;
      }

      // Ignore if configured
      if (qx.lang.Array.contains(ign, key)) {
        continue;
      }
    }
    catch(ex)
    {
      continue;
    }

    ext.push({ "key" : key, "value" : obj[key] });
  }

  return ext;
}

qx.Class.getHtmlTable = function(object)
{
  var all = [];

  var rowStart = "<tr style='vertical-align:top'><td>";
  var cellSplit = "</td><td>";
  var rowEnd = "</td></tr>";

  all.push("<table>");

  var ext = this.extract(object);

  for (var i=0; i<ext.length; i++) {
    all.push(rowStart + ext[i].key + cellSplit + ext[i].value + rowEnd);
  }

  all.push("</table>");

  return all.join("");
}

qx.Class.getTextList = function(object)
{
  var all = [];

  var cellSplit = ": ";
  var rowEnd = "\n";

  var ext = this.extract(object);

  for (var i=0; i<ext.length; i++) {
    all.push(ext[i].key + cellSplit + ext[i].value + rowEnd);
  }

  return all.join("");
}
