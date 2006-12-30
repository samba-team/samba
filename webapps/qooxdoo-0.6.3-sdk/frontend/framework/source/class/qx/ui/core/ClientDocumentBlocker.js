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

#module(ui_core)

************************************************************************ */

/*!
  qx.ui.core.ClientDocumentBlocker blocks the inputs from the user.
  This will be used internally to allow better modal dialogs for example.
*/
qx.OO.defineClass("qx.ui.core.ClientDocumentBlocker", qx.ui.basic.Terminator,
function()
{
  qx.ui.basic.Terminator.call(this);

  this.setEdge(0);
  this.setZIndex(1e8);
  this.setDisplay(false);
});

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "blocker" });
