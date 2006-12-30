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
 * The model of a table pane. This model works as proxy to a
 * {@link TableColumnModel} and manages the visual order of the columns shown in
 * a {@link TablePane}.
 *
 * @param tableColumnModel {TableColumnModel} The TableColumnModel of which this
 *    model is the proxy.
 *
 * @event modelChanged {qx.event.type.Event} Fired when the model changed.
 */
qx.OO.defineClass("qx.ui.table.TablePaneModel", qx.core.Target,
function(tableColumnModel) {
  qx.core.Target.call(this);

  tableColumnModel.addEventListener("visibilityChangedPre", this._onColVisibilityChanged, this);

  this._tableColumnModel = tableColumnModel;
});


/** The visible x position of the first column this model should contain. */
qx.OO.addProperty({ name : "firstColumnX", type : "number", defaultValue : 0 });

/**
 * The maximum number of columns this model should contain. If -1 this model will
 * contain all remaining columns.
 */
qx.OO.addProperty({ name : "maxColumnCount", type : "number", defaultValue : -1 });


// property modifier
qx.Proto._modifyFirstColumnX = function(propValue, propOldValue, propData) {
  this._columnCount = null;
  this.createDispatchEvent(qx.ui.table.TablePaneModel.EVENT_TYPE_MODEL_CHANGED);
  return true;
}


// property modifier
qx.Proto._modifyMaxColumnCount = function(propValue, propOldValue, propData) {
  this._columnCount = null;
  this.createDispatchEvent(qx.ui.table.TablePaneModel.EVENT_TYPE_MODEL_CHANGED);
  return true;
}


/**
 * Event handler. Called when the visibility of a column has changed.
 *
 * @param evt {Map} the event.
 */
qx.Proto._onColVisibilityChanged = function(evt) {
  this._columnCount = null;

  // TODO: Check whether the column is in this model (This is a little bit
  //     tricky, because the column could _have been_ in this model, but is
  //     not in it after the change)
  this.createDispatchEvent(qx.ui.table.TablePaneModel.EVENT_TYPE_MODEL_CHANGED);
}


/**
 * Returns the number of columns in this model.
 *
 * @return {int} the number of columns in this model.
 */
qx.Proto.getColumnCount = function() {
  if (this._columnCount == null) {
    var firstX = this.getFirstColumnX();
    var maxColCount = this.getMaxColumnCount();
    var totalColCount = this._tableColumnModel.getVisibleColumnCount();

    if (maxColCount == -1 || (firstX + maxColCount) > totalColCount) {
      this._columnCount = totalColCount - firstX;
    } else {
      this._columnCount = maxColCount;
    }
  }
  return this._columnCount;
}


/**
 * Returns the model index of the column at the position <code>xPos</code>.
 *
 * @param xPos {int} the x postion in the table pane of the column.
 * @return {int} the model index of the column.
 */
qx.Proto.getColumnAtX = function(xPos) {
  var firstX = this.getFirstColumnX();
  return this._tableColumnModel.getVisibleColumnAtX(firstX + xPos);
}


/**
 * Returns the x position of the column <code>col</code>.
 *
 * @param col {int} the model index of the column.
 * @return {int} the x postion in the table pane of the column.
 */
qx.Proto.getX = function(col) {
  var firstX = this.getFirstColumnX();
  var maxColCount = this.getMaxColumnCount();

  var x = this._tableColumnModel.getVisibleX(col) - firstX;
  if (x >= 0 && (maxColCount == -1 || x < maxColCount)) {
    return x;
  } else {
    return -1;
  }
}


/**
 * Gets the position of the left side of a column (in pixels, relative to the
 * left side of the table pane).
 * <p>
 * This value corresponds to the sum of the widths of all columns left of the
 * column.
 *
 * @param col {int} the model index of the column.
 * @return the position of the left side of the column.
 */
qx.Proto.getColumnLeft = function(col) {
  var left = 0;
  var colCount = this.getColumnCount();
  for (var x = 0; x < colCount; x++) {
    var currCol = this.getColumnAtX(x);
    if (currCol == col) {
      return left;
    }

    left += this._tableColumnModel.getColumnWidth(currCol);
  }
  return -1;
}


/**
 * Returns the total width of all columns in the model.
 *
 * @return {int} the total width of all columns in the model.
 */
qx.Proto.getTotalWidth = function() {
  var totalWidth = 0;
  var colCount = this.getColumnCount();
  for (var x = 0; x < colCount; x++) {
    var col = this.getColumnAtX(x);
    totalWidth += this._tableColumnModel.getColumnWidth(col);
  }
  return totalWidth;
}


/** {string} The type of the event fired when the model changed. */
qx.Class.EVENT_TYPE_MODEL_CHANGED = "modelChanged";
