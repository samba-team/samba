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
 * An abstract resize behavior.  All resize behaviors should extend this
 * class.
 */
qx.OO.defineClass("qx.ui.table.AbstractResizeBehavior",
                  qx.core.Object,
function()
{
  qx.core.Object.call(this);

  this._resizeColumnData = [ ];
});



/**
 * Called when the ResizeTableColumnModel is initialized, and upon loading of
 * a new TableModel, to allow the Resize Behaviors to know how many columns
 * are in use.
 *
 * @param numColumns {Integer}
 *   The numbrer of columns in use.
 */
qx.Proto._setNumColumns = function(numColumns)
{
  throw new Error("_setNumColumns is abstract");
};


/**
 * Called when the table has first been rendered.
 *
 * @param tableColumnModel {qx.ui.table.ResizeTableColumnModel}
 *   The table column model in use.  Of particular interest is the property
 *   <i>_table</i> which is a reference to the table widget.  This allows
 *   access to any other features of the table, for use in calculating widths
 *   of columns.
 *
 * @param event
 *   The <i>onappear</i> event object.
 */
qx.Proto.onAppear = function(tableColumnModel, event)
{
  throw new Error("onAppear is abstract");
};


/**
 * Called when the window is resized.
 *
 * @param tableColumnModel {qx.ui.table.ResizeTableColumnModel}
 *   The table column model in use.  Of particular interest is the property
 *   <i>_table</i> which is a reference to the table widget.  This allows
 *   access to any other features of the table, for use in calculating widths
 *   of columns.
 *
 * @param event
 *   The <i>onwindowresize</i> event object.
 */
qx.Proto.onWindowResize = function(tableColumnModel, event)
{
  throw new Error("onWindowResize is abstract");
};


/**
 * Called when a column width is changed.
 *
 * @param tableColumnModel {qx.ui.table.ResizeTableColumnModel}
 *   The table column model in use.  Of particular interest is the property
 *   <i>_table</i> which is a reference to the table widget.  This allows
 *   access to any other features of the table, for use in calculating widths
 *   of columns.
 *
 * @param event
 *   The <i>widthChanged</i> event object.  This event has data, obtained via
 *   event.getData(), which is an object with three properties: the column
 *   which changed width (data.col), the old width (data.oldWidth) and the new
 *   width (data.newWidth).
 */
qx.Proto.onColumnWidthChanged = function(tableColumnModel, event)
{
  throw new Error("onColumnWidthChanged is abstract");
};


/**
 * Called when a column visibility is changed.
 *
 * @param tableColumnModel {qx.ui.table.ResizeTableColumnModel}
 *   The table column model in use.  Of particular interest is the property
 *   <i>_table</i> which is a reference to the table widget.  This allows
 *   access to any other features of the table, for use in calculating widths
 *   of columns.
 *
 * @param event
 *   The <i>visibilityChanged</i> event object.  This event has data, obtained
 *   via event.getData(), which is an object with two properties: the column
 *   which changed width (data.col) and the new visibility of the column
 *   (data.visible).
 */
qx.Proto.onVisibilityChanged = function(tableColumnModel, event)
{
  throw new Error("onVisibilityChanged is abstract");
};


/*
 * Determine the inner width available to columns in the table.
 *
 * @param tableColumnModel {qx.ui.table.ResizeTableColumnModel}
 *   The table column model in use.
 *
 */
qx.Proto._getAvailableWidth = function(tableColumnModel)
{
  // Get the inner width off the table
  var el = tableColumnModel._table.getElement();
  var width = qx.html.Dimension.getInnerWidth(el) - 2;

  // Get the last meta column scroller
  var scrollers = tableColumnModel._table._getPaneScrollerArr();
  var lastScroller = scrollers[scrollers.length - 1];

  // Update the scroll bar visibility so we can determine if the vertical bar
  // is displayed.  If it is, we'll need to reduce available space by its
  // width.
  tableColumnModel._table._updateScrollBarVisibility();

  // If the column visibility button is displayed or a verticalscroll bar is
  // being displayed, then reduce the available width by the width of those.
  if (tableColumnModel._table.getColumnVisibilityButtonVisible() ||
      (lastScroller._verScrollBar.getVisibility() &&
       lastScroller._verScrollBar.getWidth() == "auto"))
  {
    width -= 16;
  }

  return width;
};

