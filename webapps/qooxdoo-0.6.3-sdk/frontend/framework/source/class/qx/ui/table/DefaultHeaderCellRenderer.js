/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2006 by STZ-IDA, Germany, http://www.stz-ida.de

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Til Schneider (til132)

************************************************************************ */

/* ************************************************************************

#module(ui_table)

************************************************************************ */

/**
 * The default header cell renderer.
 */
qx.OO.defineClass("qx.ui.table.DefaultHeaderCellRenderer", qx.ui.table.HeaderCellRenderer,
function() {
  qx.ui.table.HeaderCellRenderer.call(this);
});


// overridden
qx.Proto.createHeaderCell = function(cellInfo) {
  var widget = new qx.ui.basic.Atom();
  widget.setAppearance("table-header-cell");

  this.updateHeaderCell(cellInfo, widget);

  return widget;
}


// overridden
qx.Proto.updateHeaderCell = function(cellInfo, cellWidget) {
  var DefaultHeaderCellRenderer = qx.ui.table.DefaultHeaderCellRenderer;

  cellWidget.setLabel(cellInfo.name);

  cellWidget.setIcon(cellInfo.sorted ? (cellInfo.sortedAscending ? "widget/table/ascending.png" : "widget/table/descending.png") : null);
  cellWidget.setState(DefaultHeaderCellRenderer.STATE_SORTED, cellInfo.sorted);
  cellWidget.setState(DefaultHeaderCellRenderer.STATE_SORTED_ASCENDING, cellInfo.sortedAscending);
}

/**
 * (string) The state which will be set for header cells of sorted columns.
 */
qx.Class.STATE_SORTED = "sorted";

/**
 * (string) The state which will be set when sorting is ascending.
 */
qx.Class.STATE_SORTED_ASCENDING = "sortedAscending";
