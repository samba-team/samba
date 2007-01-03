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

#module(ui_listview)

************************************************************************ */

qx.OO.defineClass("qx.ui.listview.ContentCellLink", qx.ui.embed.LinkEmbed,
function(vHtml)
{
  qx.ui.embed.LinkEmbed.call(this, vHtml);

  // selectable = false will break links in gecko based browsers
  this.setSelectable(true);
});

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "list-view-content-cell-link" });

qx.ui.listview.ContentCellLink.empty =
{
  html : "",
  uri : "#"
}
