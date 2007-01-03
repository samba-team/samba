/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2006 by 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Volker Pauli

************************************************************************ */

/* ************************************************************************

#module(ui_splitpane)

************************************************************************ */

/**
 *
 * Creates a new instance of a vertical SplitPane.<br /><br />
 *
 * new qx.ui.splitpane.VerticalSplitPane()<br />
 * new qx.ui.splitpane.VerticalSplitPane(firstSize, secondSize)
 *
 * @param firstSize {string} The size of the top pane. Allowed values are any by {@see qx.ui.core.Widget} supported unit.
 * @param secondSize {string} The size of the bottom pane. Allowed values are any by {@see qx.ui.core.Widget} supported unit.
 */
qx.OO.defineClass("qx.ui.splitpane.VerticalSplitPane", qx.ui.splitpane.SplitPane,
function(firstSize, secondSize) {
  qx.ui.splitpane.SplitPane.call(this, "vertical", firstSize, secondSize);
});





/*
------------------------------------------------------------------------------------
  DISPOSER
------------------------------------------------------------------------------------
 */

/**
 * Garbage collection
 */
qx.Proto.dispose = function() {
  if (this.getDisposed()) {
    return true;
  }

  return qx.ui.splitpane.SplitPane.prototype.dispose.call(this);
}
