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
 * An abstract table model that performs the column handling, so subclasses only
 * need to care for row handling.
 */
qx.OO.defineClass("qx.ui.table.AbstractTableModel", qx.ui.table.TableModel,
function() {
  qx.ui.table.TableModel.call(this);

  this._columnIdArr = [];
  this._columnNameArr = [];
  this._columnIndexMap = {};
});


// overridden
qx.Proto.getColumnCount = function() {
  return this._columnIdArr.length;
}


// overridden
qx.Proto.getColumnIndexById = function(columnId) {
  return this._columnIndexMap[columnId];
}


// overridden
qx.Proto.getColumnId = function(columnIndex) {
  return this._columnIdArr[columnIndex];
}


// overridden
qx.Proto.getColumnName = function(columnIndex) {
  return this._columnNameArr[columnIndex];
}


/**
 * Sets the column IDs. These IDs may be used internally to identify a column.
 * <p>
 * Note: This will clear previously set column names.
 * </p>
 *
 * @param columnIdArr {string[]} the IDs of the columns.
 * @see #setColumns
 */
qx.Proto.setColumnIds = function(columnIdArr) {
  this._columnIdArr = columnIdArr;

  // Create the reverse map
  this._columnIndexMap = {};
  for (var i = 0; i < columnIdArr.length; i++) {
    this._columnIndexMap[columnIdArr[i]] = i;
  }
  this._columnNameArr = new Array(columnIdArr.length);

  // Inform the listeners
  if (!this._internalChange) {
    this.createDispatchEvent(qx.ui.table.TableModel.EVENT_TYPE_META_DATA_CHANGED);
  }
}


/**
 * Sets the column names. These names will be shown to the user.
 * <p>
 * Note: The column IDs have to be defined before.
 * </p>
 *
 * @param columnNameArr {string[]} the names of the columns.
 * @see #setColumnIds
 */
qx.Proto.setColumnNamesByIndex = function(columnNameArr) {
  if (this._columnIdArr.length != columnNameArr.length) {
    throw new Error("this._columnIdArr and columnNameArr have different length: "
      + this._columnIdArr.length + " != " + columnNameArr.length);
  }
  this._columnNameArr = columnNameArr;

  // Inform the listeners
  this.createDispatchEvent(qx.ui.table.TableModel.EVENT_TYPE_META_DATA_CHANGED);
}


/**
 * Sets the column names. These names will be shown to the user.
 * <p>
 * Note: The column IDs have to be defined before.
 * </p>
 *
 * @param columnNameMap {Map} a map containing the column IDs as keys and the
 *        column name as values.
 * @see #setColumnIds
 */
qx.Proto.setColumnNamesById = function(columnNameMap) {
  this._columnNameArr = new Array(this._columnIdArr.length);
  for (var i = 0; i < this._columnIdArr.length; ++i) {
    this._columnNameArr[i] = columnNameMap[this._columnIdArr[i]];
  }
}


/**
 * Sets the columns.
 *
 * @param columnNameArr {string[]} The column names. These names will be shown to
 *        the user.
 * @param columnIdArr {string[] ? null} The column IDs. These IDs may be used
 *        internally to identify a column. If null, the column names are used as
 *        IDs.
 */
qx.Proto.setColumns = function(columnNameArr, columnIdArr) {
  if (columnIdArr == null) {
    columnIdArr = columnNameArr;
  }

  if (columnIdArr.length != columnNameArr.length) {
    throw new Error("columnIdArr and columnNameArr have different length: "
      + columnIdArr.length + " != " + columnNameArr.length);
  }

  this._internalChange = true;
  this.setColumnIds(columnIdArr);
  this._internalChange = false;
  this.setColumnNamesByIndex(columnNameArr);
}
