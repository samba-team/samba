/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2006 STZ-IDA, Germany, http://www.stz-ida.de

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Til Schneider (til132)

************************************************************************ */

/* ************************************************************************

#module(ui_table)

************************************************************************ */

/**
 * The table pane that shows a certain section from a table. This class handles
 * the display of the data part of a table and is therefore the base for virtual
 * scrolling.
 *
 * @param paneScroller {TablePaneScroller} the TablePaneScroller the header belongs to.
 */
qx.OO.defineClass("qx.ui.table.TablePane", qx.ui.basic.Terminator,
function(paneScroller) {
  qx.ui.basic.Terminator.call(this);

  this._paneScroller = paneScroller;

  // this.debug("USE_ARRAY_JOIN:" + qx.ui.table.TablePane.USE_ARRAY_JOIN + ", USE_TABLE:" + qx.ui.table.TablePane.USE_TABLE);

  this._lastColCount = 0;
  this._lastRowCount = 0;
});

/** The index of the first row to show. */
qx.OO.addProperty({ name:"firstVisibleRow", type:"number", defaultValue:0 });

/** The number of rows to show. */
qx.OO.addProperty({ name:"visibleRowCount", type:"number", defaultValue:0 });


// property modifier
qx.Proto._modifyFirstVisibleRow = function(propValue, propOldValue, propData) {
  this._updateContent();
  return true;
}


// property modifier
qx.Proto._modifyVisibleRowCount = function(propValue, propOldValue, propData) {
  this._updateContent();
  return true;
}


// overridden
qx.Proto._afterAppear = function() {
  qx.ui.basic.Terminator.prototype._afterAppear.call(this);

  if (this._updateWantedWhileInvisible) {
    // We are visible now and an update was wanted while we were invisible
    // -> Do the update now
    this._updateContent();
    this._updateWantedWhileInvisible = false;
  }
};


/**
 * Returns the TablePaneScroller this pane belongs to.
 *
 * @return {TablePaneScroller} the TablePaneScroller.
 */
qx.Proto.getPaneScroller = function() {
  return this._paneScroller;
};


/**
 * Returns the table this pane belongs to.
 *
 * @return {Table} the table.
 */
qx.Proto.getTable = function() {
  return this._paneScroller.getTable();
};


/**
 * Sets the currently focused cell.
 *
 * @param col {Integer} the model index of the focused cell's column.
 * @param row {Integer} the model index of the focused cell's row.
 * @param massUpdate {Boolean ? false} Whether other updates are planned as well.
 *        If true, no repaint will be done.
 */
qx.Proto.setFocusedCell = function(col, row, massUpdate) {
  if (col != this._focusedCol || row != this._focusedRow) {
    var oldCol = this._focusedCol;
    var oldRow = this._focusedRow;
    this._focusedCol = col;
    this._focusedRow = row;

    // Update the focused row background
    if (row != oldRow && !massUpdate) {
      // NOTE: Only the old and the new row need update
      this._updateContent(false, oldRow, true);
      this._updateContent(false, row, true);
    }
  }
}


/**
 * Event handler. Called when the selection has changed.
 *
 * @param evt {Map} the event.
 */
qx.Proto._onSelectionChanged = function(evt) {
  this._updateContent(false, null, true);
}


/**
 * Event handler. Called when the table gets or looses the focus.
 *
 * @param evt {Map} the event.
 */
qx.Proto._onFocusChanged = function(evt) {
  this._updateContent(false, null, true);
};


/**
 * Event handler. Called when the width of a column has changed.
 *
 * @param evt {Map} the event.
 */
qx.Proto._onColWidthChanged = function(evt) {
  this._updateContent(true);
}


/**
 * Event handler. Called the column order has changed.
 *
 * @param evt {Map} the event.
 */
qx.Proto._onColOrderChanged = function(evt) {
  this._updateContent(true);
}


/**
 * Event handler. Called when the pane model has changed.
 *
 * @param evt {Map} the event.
 */
qx.Proto._onPaneModelChanged = function(evt) {
  this._updateContent(true);
}


/**
 * Event handler. Called when the table model data has changed.
 *
 * @param evt {Map} the event.
 */
qx.Proto._onTableModelDataChanged = function(evt) {
  var data = evt.getData ? evt.getData() : null;

  var firstRow = this.getFirstVisibleRow();
  var rowCount = this.getVisibleRowCount();
  if (data == null || data.lastRow == -1
    || data.lastRow >= firstRow && data.firstRow < firstRow + rowCount)
  {
    // The change intersects this pane
    this._updateContent();
  }
}


/**
 * Event handler. Called when the table model meta data has changed.
 *
 * @param evt {Map} the event.
 */
qx.Proto._onTableModelMetaDataChanged = function(evt) {
  this._updateContent();
}


/**
 * Updates the content of the pane.
 *
 * @param completeUpdate {Boolean ? false} if true a complete update is performed.
 *    On a complete update all cell widgets are recreated.
 * @param onlyRow {Integer ? null} if set only the specified row will be updated.
 * @param onlySelectionOrFocusChanged {Boolean ? false} if true, cell values won't
 *        be updated. Only the row background will.
 */
qx.Proto._updateContent = function(completeUpdate, onlyRow,
  onlySelectionOrFocusChanged)
{
  if (! this.isSeeable()) {
    this._updateWantedWhileInvisible = true;
    return;
  }

  if (qx.ui.table.TablePane.USE_ARRAY_JOIN) {
    this._updateContent_array_join(completeUpdate, onlyRow, onlySelectionOrFocusChanged);
  } else {
    this._updateContent_orig(completeUpdate, onlyRow, onlySelectionOrFocusChanged);
  }
}


/**
 * Updates the content of the pane (implemented using array joins).
 *
 * @param completeUpdate {Boolean ? false} if true a complete update is performed.
 *    On a complete update all cell widgets are recreated.
 * @param onlyRow {Integer ? null} if set only the specified row will be updated.
 * @param onlySelectionOrFocusChanged {Boolean ? false} if true, cell values won't
 *        be updated. Only the row background will.
 */
qx.Proto._updateContent_array_join = function(completeUpdate, onlyRow,
  onlySelectionOrFocusChanged)
{
  var TablePane = qx.ui.table.TablePane;

  var table = this.getTable();

  var selectionModel = table.getSelectionModel();
  var tableModel = table.getTableModel();
  var columnModel = table.getTableColumnModel();
  var paneModel = this.getPaneScroller().getTablePaneModel();
  var rowRenderer = table.getDataRowRenderer();

  var colCount = paneModel.getColumnCount();
  var rowHeight = table.getRowHeight();

  var firstRow = this.getFirstVisibleRow();
  var rowCount = this.getVisibleRowCount();
  var modelRowCount = tableModel.getRowCount();
  if (firstRow + rowCount > modelRowCount) {
    rowCount = Math.max(0, modelRowCount - firstRow);
  }

  var cellInfo = { table:table };
  cellInfo.styleHeight = rowHeight;

  var htmlArr = [];
  var rowWidth = paneModel.getTotalWidth();

  if (TablePane.USE_TABLE) {
    // The table test
    htmlArr.push('<table cellspacing\="0" cellpadding\="0" style\="table-layout:fixed;font-family:');
    htmlArr.push(qx.ui.table.TablePane.CONTENT_ROW_FONT_FAMILY_TEST);
    htmlArr.push(';font-size:');
    htmlArr.push(qx.ui.table.TablePane.CONTENT_ROW_FONT_SIZE_TEST);
    htmlArr.push(';width:');
    htmlArr.push(rowWidth);
    htmlArr.push('px"><colgroup>');

    for (var x = 0; x < colCount; x++) {
      var col = paneModel.getColumnAtX(x);

      htmlArr.push('<col width="');
      htmlArr.push(columnModel.getColumnWidth(col));
      htmlArr.push('"/>');
    }

    htmlArr.push('</colgroup><tbody>');
  }

  tableModel.prefetchRows(firstRow, firstRow + rowCount - 1);
  for (var y = 0; y < rowCount; y++) {
    var row = firstRow + y;

    cellInfo.row = row;
    cellInfo.selected = selectionModel.isSelectedIndex(row);
    cellInfo.focusedRow = (this._focusedRow == row);
    cellInfo.rowData = tableModel.getRowData(row);

    // Update this row
    if (TablePane.USE_TABLE) {
      htmlArr.push('<tr style\="height:');
      htmlArr.push(rowHeight);
    } else {
      htmlArr.push('<div style\="position:absolute;left:0px;top:');
      htmlArr.push(y * rowHeight);
      htmlArr.push('px;width:');
      htmlArr.push(rowWidth);
      htmlArr.push('px;height:');
      htmlArr.push(rowHeight);
      htmlArr.push('px');
    }

    rowRenderer._createRowStyle_array_join(cellInfo, htmlArr);

    htmlArr.push('">');

    var left = 0;
    for (var x = 0; x < colCount; x++) {
      var col = paneModel.getColumnAtX(x);
      cellInfo.xPos = x;
      cellInfo.col = col;
      cellInfo.editable = tableModel.isColumnEditable(col);
      cellInfo.focusedCol = (this._focusedCol == col);
      cellInfo.value = tableModel.getValue(col, row);
      var cellWidth = columnModel.getColumnWidth(col);

      cellInfo.styleLeft = left;
      cellInfo.styleWidth = cellWidth;

      var cellRenderer = columnModel.getDataCellRenderer(col);
      cellRenderer.createDataCellHtml_array_join(cellInfo, htmlArr);

      left += cellWidth;
    }

    if (TablePane.USE_TABLE) {
      htmlArr.push('</tr>');
    } else {
      htmlArr.push('</div>');
    }
  }

  if (TablePane.USE_TABLE) {
    htmlArr.push('</tbody></table>');
  }

  var elem = this.getElement();
  // this.debug(">>>" + htmlArr.join("") + "<<<")
  elem.innerHTML = htmlArr.join("");

  this.setHeight(rowCount * rowHeight);

  this._lastColCount = colCount;
  this._lastRowCount = rowCount;
}


/**
 * Updates the content of the pane (old implementation).
 *
 * @param completeUpdate {Boolean ? false} if true a complete update is performed.
 *    On a complete update all cell widgets are recreated.
 * @param onlyRow {Integer ? null} if set only the specified row will be updated.
 * @param onlySelectionOrFocusChanged {Boolean ? false} if true, cell values won't
 *        be updated. Only the row background will.
 */
qx.Proto._updateContent_orig = function(completeUpdate, onlyRow,
  onlySelectionOrFocusChanged)
{
  var TablePane = qx.ui.table.TablePane;

  var table = this.getTable();

  var alwaysUpdateCells = table.getAlwaysUpdateCells();

  var selectionModel = table.getSelectionModel();
  var tableModel = table.getTableModel();
  var columnModel = table.getTableColumnModel();
  var paneModel = this.getPaneScroller().getTablePaneModel();
  var rowRenderer = table.getDataRowRenderer();

  var colCount = paneModel.getColumnCount();
  var rowHeight = table.getRowHeight();

  var firstRow = this.getFirstVisibleRow();
  var rowCount = this.getVisibleRowCount();
  var modelRowCount = tableModel.getRowCount();
  if (firstRow + rowCount > modelRowCount) {
    rowCount = Math.max(0, modelRowCount - firstRow);
  }

  // Remove the rows that are not needed any more
  if (completeUpdate || this._lastRowCount > rowCount) {
    var firstRowToRemove = completeUpdate ? 0 : rowCount;
    this._cleanUpRows(firstRowToRemove);
  }

  if (TablePane.USE_TABLE) {
    throw new Error("Combination of USE_TABLE==true and USE_ARRAY_JOIN==false is not yet implemented");
  }

  var elem = this.getElement();
  var childNodes = elem.childNodes;
  var cellInfo = { table:table };
  tableModel.prefetchRows(firstRow, firstRow + rowCount - 1);
  for (var y = 0; y < rowCount; y++) {
    var row = firstRow + y;
    if ((onlyRow != null) && (row != onlyRow)) {
      continue;
    }

    cellInfo.row = row;
    cellInfo.selected = selectionModel.isSelectedIndex(row);
    cellInfo.focusedRow = (this._focusedRow == row);
    cellInfo.rowData = tableModel.getRowData(row);

    // Update this row
    var rowElem;
    var recyleRowElem;
    if (y < childNodes.length) {
      rowElem = childNodes[y];
      recyleRowElem = true
    } else {
      var rowElem = document.createElement("div");

      //rowElem.style.position = "relative";
      rowElem.style.position = "absolute";
      rowElem.style.left = "0px";
      rowElem.style.top = (y * rowHeight) + "px";

      rowElem.style.height = rowHeight + "px";
      elem.appendChild(rowElem);
      recyleRowElem = false;
    }

    rowRenderer.updateDataRowElement(cellInfo, rowElem);

    if (alwaysUpdateCells || !recyleRowElem || !onlySelectionOrFocusChanged) {
      var html = "";
      var left = 0;
      for (var x = 0; x < colCount; x++) {
        var col = paneModel.getColumnAtX(x);
        cellInfo.xPos = x;
        cellInfo.col = col;
        cellInfo.editable = tableModel.isColumnEditable(col);
        cellInfo.focusedCol = (this._focusedCol == col);
        cellInfo.value = tableModel.getValue(col, row);
        var width = columnModel.getColumnWidth(col);
        cellInfo.style = 'position:absolute;left:' + left
          + 'px;top:0px;width:' + width
          + 'px; height:' + rowHeight + "px";

        var cellRenderer = columnModel.getDataCellRenderer(col);
        if (recyleRowElem) {
          var cellElem = rowElem.childNodes[x];
          cellRenderer.updateDataCellElement(cellInfo, cellElem);
        } else {
          html += cellRenderer.createDataCellHtml(cellInfo);
        }

        left += width;
      }
      if (! recyleRowElem) {
        rowElem.style.width = left + "px";
        rowElem.innerHTML = html;
      }
    }
  }

  this.setHeight(rowCount * rowHeight);

  this._lastColCount = colCount;
  this._lastRowCount = rowCount;
}


/**
 * Cleans up the row widgets.
 *
 * @param firstRowToRemove {Integer} the visible index of the first row to clean up.
 *    All following rows will be cleaned up, too.
 */
qx.Proto._cleanUpRows = function(firstRowToRemove) {
  var elem = this.getElement();
  if (elem) {
    var childNodes = this.getElement().childNodes;
    var paneModel = this.getPaneScroller().getTablePaneModel();
    var colCount = paneModel.getColumnCount();
    for (var y = childNodes.length - 1; y >= firstRowToRemove; y--) {
      elem.removeChild(childNodes[y]);
    }
  }
}


// overridden
qx.Proto.dispose = function() {
  if (this.getDisposed()) {
    return true;
  }

  this._cleanUpRows(0);

  return qx.ui.basic.Terminator.prototype.dispose.call(this);
}


qx.Class.USE_ARRAY_JOIN = false;
qx.Class.USE_TABLE = false;


qx.Class.CONTENT_ROW_FONT_FAMILY_TEST = "'Segoe UI', Corbel, Calibri, Tahoma, 'Lucida Sans Unicode', sans-serif";
qx.Class.CONTENT_ROW_FONT_SIZE_TEST = "11px";

