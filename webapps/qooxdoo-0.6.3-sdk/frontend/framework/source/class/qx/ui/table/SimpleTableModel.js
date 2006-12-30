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
 * A simple table model that provides an API for changing the model data.
 */
qx.OO.defineClass("qx.ui.table.SimpleTableModel", qx.ui.table.AbstractTableModel,
function() {
  qx.ui.table.AbstractTableModel.call(this);

  this._rowArr = [];
  this._sortColumnIndex = -1;
  this._sortAscending;

  this._editableColArr = null;
});


/**
 * <p>See overridden method for details.</p>
 *
 * @param rowIndex {int} the model index of the row.
 * @return {Array} Array containing a value for each column.
 */
qx.Proto.getRowData = function(rowIndex) {
  return this._rowArr[rowIndex];
};


/**
 * Returns the data of one row as map containing the column IDs as key and the
 * cell values as value.
 *
 * @param rowIndex {int} the model index of the row.
 * @return {Map} a Map containing the column values.
 */
qx.Proto.getRowDataAsMap = function(rowIndex) {
  var columnArr = this._rowArr[rowIndex];
  var map = {};
  for (var col = 0; col < this.getColumnCount(); col++) {
    map[this.getColumnId(col)] = columnArr[col];
  }
  return map;
};


/**
 * Sets all columns editable or not editable.
 *
 * @param editable {boolean} whether all columns are editable.
 */
qx.Proto.setEditable = function(editable) {
  this._editableColArr = [];
  for (var col = 0; col < this.getColumnCount(); col++) {
    this._editableColArr[col] = editable;
  }

  this.createDispatchEvent(qx.ui.table.TableModel.EVENT_TYPE_META_DATA_CHANGED);
}


/**
 * Sets whether a column is editable.
 *
 * @param columnIndex {int} the column of which to set the editable state.
 * @param editable {boolean} whether the column should be editable.
 */
qx.Proto.setColumnEditable = function(columnIndex, editable) {
  if (editable != this.isColumnEditable(columnIndex)) {
    if (this._editableColArr == null) {
      this._editableColArr = [];
    }
    this._editableColArr[columnIndex] = editable;

    this.createDispatchEvent(qx.ui.table.TableModel.EVENT_TYPE_META_DATA_CHANGED);
  }
}


// overridden
qx.Proto.isColumnEditable = function(columnIndex) {
  return this._editableColArr ? (this._editableColArr[columnIndex] == true) : false;
}


// overridden
qx.Proto.isColumnSortable = function(columnIndex) {
  return true;
}


// overridden
qx.Proto.sortByColumn = function(columnIndex, ascending) {
  // NOTE: We use different comperators for ascending and descending,
  //     because comperators should be really fast.
  var comperator;
  if (ascending) {
    comperator = function(row1, row2) {
      var obj1 = row1[columnIndex];
      var obj2 = row2[columnIndex];
      return (obj1 > obj2) ? 1 : ((obj1 == obj2) ? 0 : -1);
    }
  } else {
    comperator = function(row1, row2) {
      var obj1 = row1[columnIndex];
      var obj2 = row2[columnIndex];
      return (obj1 < obj2) ? 1 : ((obj1 == obj2) ? 0 : -1);
    }
  }

  this._rowArr.sort(comperator);

  this._sortColumnIndex = columnIndex;
  this._sortAscending = ascending;

  this.createDispatchEvent(qx.ui.table.TableModel.EVENT_TYPE_META_DATA_CHANGED);
}


/**
 * Clears the sorting.
 */
qx.Proto._clearSorting = function() {
  if (this._sortColumnIndex != -1) {
    this._sortColumnIndex = -1;
    this._sortAscending = true;

    this.createDispatchEvent(qx.ui.table.TableModel.EVENT_TYPE_META_DATA_CHANGED);
  }
}


// overridden
qx.Proto.getSortColumnIndex = function() {
  return this._sortColumnIndex;
}


// overridden
qx.Proto.isSortAscending = function() {
  return this._sortAscending;
}


// overridden
qx.Proto.getRowCount = function() {
  return this._rowArr.length;
}


// overridden
qx.Proto.getValue = function(columnIndex, rowIndex) {
  if (rowIndex < 0 || rowIndex >= this._rowArr.length) {
    throw new Error("this._rowArr out of bounds: " + rowIndex + " (0.." + this._rowArr.length + ")");
  }

  return this._rowArr[rowIndex][columnIndex];
}


// overridden
qx.Proto.setValue = function(columnIndex, rowIndex, value) {
  if (this._rowArr[rowIndex][columnIndex] != value) {
    this._rowArr[rowIndex][columnIndex] = value;

    // Inform the listeners
    if (this.hasEventListeners(qx.ui.table.TableModel.EVENT_TYPE_DATA_CHANGED)) {
      var data = { firstRow:rowIndex, lastRow:rowIndex,
                   firstColumn:columnIndex, lastColumn:columnIndex }
      this.dispatchEvent(new qx.event.type.DataEvent(qx.ui.table.TableModel.EVENT_TYPE_DATA_CHANGED, data), true);
    }

    if (columnIndex == this._sortColumnIndex) {
      this._clearSorting();
    }
  }
}


/**
 * Sets the whole data in a bulk.
 *
 * @param rowArr {var[][]} An array containing an array for each row. Each
 *        row-array contains the values in that row in the order of the columns
 *        in this model.
 */
qx.Proto.setData = function(rowArr) {
  this._rowArr = rowArr;

  // Inform the listeners
  if (this.hasEventListeners(qx.ui.table.TableModel.EVENT_TYPE_DATA_CHANGED)) {
    this.createDispatchEvent(qx.ui.table.TableModel.EVENT_TYPE_DATA_CHANGED);
  }

  this._clearSorting();
}


/**
 * Returns the data of this model.
 * <p>
 * Warning: Do not alter this array! If you want to change the data use
 * {@link #setData}, {@link #setDataAsMapArray} or {@link #setValue} instead.
 *
 * @return {var[][]} An array containing an array for each row. Each
 *         row-array contains the values in that row in the order of the columns
 *         in this model.
 */
qx.Proto.getData = function() {
  return this._rowArr;
};


/**
 * Sets the whole data in a bulk.
 *
 * @param mapArr {Map[]} An array containing a map for each row. Each
 *        row-map contains the column IDs as key and the cell values as value.
 */
qx.Proto.setDataAsMapArray = function(mapArr) {
  this.setData(this._mapArray2RowArr(mapArr));
};


/**
 * Adds some rows to the model.
 * <p>
 * Warning: The given array will be altered!
 *
 * @param rowArr {var[][]} An array containing an array for each row. Each
 *        row-array contains the values in that row in the order of the columns
 *        in this model.
 * @param startIndex {int ? null} The index where to insert the new rows. If null,
 *        the rows are appended to the end.
 */
qx.Proto.addRows = function(rowArr, startIndex) {
  if (startIndex == null) {
    startIndex = this._rowArr.length;
  }

  // Prepare the rowArr so it can be used for apply
  rowArr.splice(0, 0, startIndex, 0);

  // Insert the new rows
  Array.prototype.splice.apply(this._rowArr, rowArr);

  // Inform the listeners
  if (this.hasEventListeners(qx.ui.table.TableModel.EVENT_TYPE_DATA_CHANGED)) {
    var data = { firstRow:startIndex, lastRow:this._rowArr.length - 1, firstColumn:0, lastColumn:this.getColumnCount() - 1 };
    this.dispatchEvent(new qx.event.type.DataEvent(qx.ui.table.TableModel.EVENT_TYPE_DATA_CHANGED, data), true);
  }

  this._clearSorting();
};


/**
 * Adds some rows to the model.
 * <p>
 * Warning: The given array (mapArr) will be altered!
 *
 * @param mapArr {Map[]} An array containing a map for each row. Each
 *        row-map contains the column IDs as key and the cell values as value.
 * @param startIndex {int ? null} The index where to insert the new rows. If null,
 *        the rows are appended to the end.
 */
qx.Proto.addRowsAsMapArray = function(mapArr, startIndex) {
  this.addRows(this._mapArray2RowArr(mapArr), startIndex);
};


/**
 * Removes some rows from the model.
 *
 * @param startIndex {int} the index of the first row to remove.
 * @param howMany {int} the number of rows to remove.
 */
qx.Proto.removeRows = function(startIndex, howMany) {
  this._rowArr.splice(startIndex, howMany);

  // Inform the listeners
  if (this.hasEventListeners(qx.ui.table.TableModel.EVENT_TYPE_DATA_CHANGED)) {
    var data = { firstRow:startIndex, lastRow:this._rowArr.length - 1, firstColumn:0, lastColumn:this.getColumnCount() - 1 };
    this.dispatchEvent(new qx.event.type.DataEvent(qx.ui.table.TableModel.EVENT_TYPE_DATA_CHANGED, data), true);
  }

  this._clearSorting();
};


/**
 * Creates an array of maps to an array of arrays.
 *
 * @param mapArr {Map[]} An array containing a map for each row. Each
 *        row-map contains the column IDs as key and the cell values as value.
 * @return {var[][]} An array containing an array for each row. Each
 *         row-array contains the values in that row in the order of the columns
 *         in this model.
 */
qx.Proto._mapArray2RowArr = function(mapArr) {
  var rowCount = mapArr.length;
  var columnCount = this.getColumnCount();
  var dataArr = new Array(rowCount);
  var columnArr;
  var j;
  for (var i = 0; i < rowCount; ++i) {
    columnArr = new Array(columnCount);
    for (var j = 0; j < columnCount; ++j) {
      columnArr[j] = mapArr[i][this.getColumnId(j)];
    }
    dataArr[i] = columnArr;
  }

  return dataArr;
};
