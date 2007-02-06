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

#module(ui_listview)

************************************************************************ */

qx.OO.defineClass("qx.ui.listview.ContentCellIconHtml", qx.ui.embed.IconHtmlEmbed,
function(vHtml, vIcon, vIconWidth, vIconHeight)
{
  qx.ui.embed.IconHtmlEmbed.call(this, vHtml, vIcon, vIconWidth, vIconHeight);

  this.setSelectable(false);
});

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "list-view-content-cell-icon-html" });

qx.ui.listview.ContentCellIconHtml.empty =
{
  icon : "",
  html : ""
}
