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
     * Volker Pauli

************************************************************************ */

/* ************************************************************************

#module(ui_splitpane)

************************************************************************ */

/**
 *
 * Creates a new instance of a horizontal SplitPane.<br /><br />
 *
 * new qx.ui.splitpane.HorizontalSplitPane()<br />
 * new qx.ui.splitpane.HorizontalSplitPane(firstSize, secondSize)
 *
 * @param firstSize {String} The size of the left pane. Allowed values are any by {@link qx.ui.core.Widget} supported unit.
 * @param secondSize {String} The size of the right pane. Allowed values are any by {@link qx.ui.core.Widget} supported unit.
 */
qx.OO.defineClass("qx.ui.splitpane.HorizontalSplitPane", qx.ui.splitpane.SplitPane,
function(firstSize, secondSize) {
  qx.ui.splitpane.SplitPane.call(this, "horizontal", firstSize, secondSize);
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
