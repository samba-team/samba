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
