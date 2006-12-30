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

#module(ui_tabview)

************************************************************************ */

qx.OO.defineClass("qx.ui.pageview.tabview.Bar", qx.ui.pageview.AbstractBar,
function()
{
  qx.ui.pageview.AbstractBar.call(this);

  this.setZIndex(2);
});

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "tab-view-bar" });
