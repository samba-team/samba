/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2007 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)

************************************************************************ */

/* ************************************************************************


************************************************************************ */

qx.OO.defineClass("qx.ui.embed.LinkEmbed", qx.ui.embed.HtmlEmbed,
function(vHtml, vUri, vTarget)
{
  qx.ui.embed.HtmlEmbed.call(this, vHtml);

  if (typeof vUri != "undefined") {
    this.setUri(vUri);
  }

  if (typeof vTarget != "undefined") {
    this.setTarget(vTarget);
  }
});






/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

/*!
  Any valid html URI
*/
qx.OO.addProperty({ name : "uri", type : "string", defaultValue : "#", impl : "html" });

/*!
  Any valid html target
*/
qx.OO.addProperty({ name : "target", type : "string", defaultValue : "_blank", impl : "html" });






/*
---------------------------------------------------------------------------
  UTILITIES
---------------------------------------------------------------------------
*/

qx.ui.embed.LinkEmbed.LINK_START = "<a target='";
qx.ui.embed.LinkEmbed.HREF_START = "' href='";
qx.ui.embed.LinkEmbed.HREF_STOP = "'>";
qx.ui.embed.LinkEmbed.LINK_STOP = "</a>";

qx.Proto._syncHtml = function()
{
  var vHtml = [];

  vHtml.push(qx.ui.embed.LinkEmbed.LINK_START);
  vHtml.push(this.getTarget());
  vHtml.push(qx.ui.embed.LinkEmbed.HREF_START);
  vHtml.push(this.getUri());
  vHtml.push(qx.ui.embed.LinkEmbed.HREF_STOP);
  vHtml.push(this.getHtml());
  vHtml.push(qx.ui.embed.LinkEmbed.LINK_STOP);

  this.getElement().innerHTML = vHtml.join("");
}
