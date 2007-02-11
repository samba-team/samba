/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2007 Derrell Lipman

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Derrell Lipman (derrell)

************************************************************************ */

/* ************************************************************************

#module(table)

************************************************************************ */

/**
 * All of the resizing information about a column.
 */
qx.OO.defineClass("qx.ui.table.ResizeBehaviorColumnData",
                  qx.ui.core.Widget,
function()
{
  qx.ui.core.Widget.call(this);

  // Assume equal flex width for all columns
  this.setWidth("1*");
});
