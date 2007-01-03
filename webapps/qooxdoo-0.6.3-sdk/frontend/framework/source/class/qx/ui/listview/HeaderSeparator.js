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

qx.OO.defineClass("qx.ui.listview.HeaderSeparator", qx.ui.basic.Terminator,
function() {
  qx.ui.basic.Terminator.call(this);
});

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "list-view-header-separator" });
