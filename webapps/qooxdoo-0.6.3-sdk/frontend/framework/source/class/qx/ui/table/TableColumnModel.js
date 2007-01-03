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

// These are needed because of their instantiation at bottom. I don't think this
// is a good idea. (wpbasti)
#require(qx.ui.table.DefaultHeaderCellRenderer)
#require(qx.ui.table.DefaultDataCellRenderer)
#require(qx.ui.table.TextFieldCellEditorFactory)

************************************************************************ */

/**
 * A model that contains all meta data about columns, such as width, renderers,
 * visibility and order.
 *
 * @event widthChanged {qx.event.type.DataEvent} Fired when the width of a
 *        column has changed. The data property of the event is a map having the
 *        following attributes:
 *        <ul>
 *        <li>col: The model index of the column the width of which has changed.</li>
 *        <li>newWidth: The new width of the column in pixels.</li>
 *        <li>oldWidth: The old width of the column in pixels.</li>
 *        </ul>
 * @event visibilityChangedPre {qx.event.type.DataEvent} Fired when the
 *        visibility of a column has changed. This event is equal to
 *        "visibilityChanged", but is fired right before.
 * @event visibilityChanged {qx.event.type.DataEvent} Fired when the
 *        visibility of a column has changed. The data property of the
 *        event is a map having the following attributes:
 *        <ul>
 *        <li>col: The model index of the column the visibility of which has changed.</li>
 *        <li>visible: Whether the column is now visible.</li>
 *        </ul>
 * @event orderChanged {qx.event.type.DataEvent} Fired when the column order
 *        has changed. The data property of the
 *        event is a map having the following attributes:
 *        <ul>
 *        <li>col: The model index of the column that was moved.</li>
 *        <li>fromOverXPos: The old overall x position of the column.</li>
 *        <li>toOverXPos: The new overall x position of the column.</li>
 *        </ul>
 *
 * @see com.ptvag.webcomponent.ui.table.TableModel
 */
qx.OO.defineClass("qx.ui.table.TableColumnModel", qx.core.Target,
function() {
  qx.core.Target.call(this);
});


/**
 * Initializes the column model.
 *
 * @param colCount {int} the number of columns the model should have.
 */
qx.Proto.init = function(colCount) {
  this._columnDataArr = [];

  var width = qx.ui.table.TableColumnModel.DEFAULT_WIDTH;
  var headerRenderer = qx.ui.table.TableColumnModel.DEFAULT_HEADER_RENDERER;
  var dataRenderer = qx.ui.table.TableColumnModel.DEFAULT_DATA_RENDERER;
  var editorFactory = qx.ui.table.TableColumnModel.DEFAULT_EDITOR_FACTORY;
  this._overallColumnArr = [];
  this._visibleColumnArr = [];
  for (var col = 0; col < colCount; col++) {
    this._columnDataArr[col] = { width:width, headerRenderer:headerRenderer,
      dataRenderer:dataRenderer, editorFactory:editorFactory }
    this._overallColumnArr[col] = col;
    this._visibleColumnArr[col] = col;
  }

  this._colToXPosMap = null;
}


/**
 * Sets the width of a column.
 *
 * @param col {int} the model index of the column.
 * @param width {int} the new width the column should get in pixels.
 */
qx.Proto.setColumnWidth = function(col, width) {
  var oldWidth = this._columnDataArr[col].width;
  if (oldWidth != width) {
    this._columnDataArr[col].width = width;
    if (this.hasEventListeners("widthChanged")) {
      var data = { col:col, newWidth:width, oldWidth:oldWidth }
      this.dispatchEvent(new qx.event.type.DataEvent("widthChanged", data), true);
    }
  }
}


/**
 * Returns the width of a column.
 *
 * @param col {int} the model index of the column.
 * @return {int} the width of the column in pixels.
 */
qx.Proto.getColumnWidth = function(col) {
  return this._columnDataArr[col].width;
}


/**
 * Sets the header renderer of a column.
 *
 * @param col {int} the model index of the column.
 * @param renderer {HeaderCellRenderer} the new header renderer the column
 *    should get.
 */
qx.Proto.setHeaderCellRenderer = function(col, renderer) {
  this._columnDataArr[col].headerRenderer = renderer;
}


/**
 * Returns the header renderer of a column.
 *
 * @param col {int} the model index of the column.
 * @return {HeaderCellRenderer} the header renderer of the column.
 */
qx.Proto.getHeaderCellRenderer = function(col) {
  return this._columnDataArr[col].headerRenderer;
}


/**
 * Sets the data renderer of a column.
 *
 * @param col {int} the model index of the column.
 * @param renderer {DataCellRenderer} the new data renderer the column should get.
 */
qx.Proto.setDataCellRenderer = function(col, renderer) {
  this._columnDataArr[col].dataRenderer = renderer;
}


/**
 * Returns the data renderer of a column.
 *
 * @param col {int} the model index of the column.
 * @return {DataCellRenderer} the data renderer of the column.
 */
qx.Proto.getDataCellRenderer = function(col) {
  return this._columnDataArr[col].dataRenderer;
}


/**
 * Sets the cell editor factory of a column.
 *
 * @param col {int} the model index of the column.
 * @param factory {CellEditorFactory} the new cell editor factory the column should get.
 */
qx.Proto.setCellEditorFactory = function(col, factory) {
  this._columnDataArr[col].editorFactory = factory;
}


/**
 * Returns the cell editor factory of a column.
 *
 * @param col {int} the model index of the column.
 * @return {CellEditorFactory} the cell editor factory of the column.
 */
qx.Proto.getCellEditorFactory = function(col) {
  return this._columnDataArr[col].editorFactory;
}


/**
 * Returns the map that translates model indexes to x positions.
 * <p>
 * The returned map contains for a model index (int) a map having two
 * properties: overX (the overall x position of the column, int) and
 * visX (the visible x position of the column, int). visX is missing for
 * hidden columns.
 *
 * @return the "column to x postion" map.
 */
qx.Proto._getColToXPosMap = function() {
  if (this._colToXPosMap == null) {
    this._colToXPosMap = {};
    for (var overX = 0; overX < this._overallColumnArr.length; overX++) {
      var col = this._overallColumnArr[overX];
      this._colToXPosMap[col] = { overX:overX }
    }
    for (var visX = 0; visX < this._visibleColumnArr.length; visX++) {
      var col = this._visibleColumnArr[visX];
      this._colToXPosMap[col].visX = visX;
    }
  }
  return this._colToXPosMap;
}


/**
 * Returns the number of visible columns.
 *
 * @return {int} the number of visible columns.
 */
qx.Proto.getVisibleColumnCount = function() {
  return this._visibleColumnArr.length;
}


/**
 * Returns the model index of a column at a certain visible x position.
 *
 * @param visXPos {int} the visible x position of the column.
 * @return {int} the model index of the column.
 */
qx.Proto.getVisibleColumnAtX = function(visXPos) {
  return this._visibleColumnArr[visXPos];
}


/**
 * Returns the visible x position of a column.
 *
 * @param col {int} the model index of the column.
 * @return {int} the visible x position of the column.
 */
qx.Proto.getVisibleX = function(col) {
  return this._getColToXPosMap()[col].visX;
}


/**
 * Returns the overall number of columns (including hidden columns).
 *
 * @return {int} the overall number of columns.
 */
qx.Proto.getOverallColumnCount = function() {
  return this._overallColumnArr.length;
}


/**
 * Returns the model index of a column at a certain overall x position.
 *
 * @param overXPos {int} the overall x position of the column.
 * @return {int} the model index of the column.
 */
qx.Proto.getOverallColumnAtX = function(overXPos) {
  return this._overallColumnArr[overXPos];
}


/**
 * Returns the overall x position of a column.
 *
 * @param col {int} the model index of the column.
 * @return {int} the overall x position of the column.
 */
qx.Proto.getOverallX = function(col) {
  return this._getColToXPosMap()[col].overX;
}


/**
 * Returns whether a certain column is visible.
 *
 * @param col {int} the model index of the column.
 * @return {boolean} whether the column is visible.
 */
qx.Proto.isColumnVisible = function(col) {
  return (this._getColToXPosMap()[col].visX != null);
}


/**
 * Sets whether a certain column is visible.
 *
 * @param col {int} the model index of the column.
 * @param visible {boolean} whether the column should be visible.
 */
qx.Proto.setColumnVisible = function(col, visible) {
  if (visible != this.isColumnVisible(col)) {
    if (visible) {
      var colToXPosMap = this._getColToXPosMap();

      var overX = colToXPosMap[col].overX;
      if (overX == null) {
        throw new Error("Showing column failed: " + col
          + ". The column is not added to this TablePaneModel.");
      }

      // get the visX of the next visible column after the column to show
      var nextVisX;
      for (var x = overX + 1; x < this._overallColumnArr.length; x++) {
        var currCol = this._overallColumnArr[x];
        var currVisX = colToXPosMap[currCol].visX;
        if (currVisX != null) {
          nextVisX = currVisX;
          break;
        }
      }

      // If there comes no visible column any more, then show the column
      // at the end
      if (nextVisX == null) {
        nextVisX = this._visibleColumnArr.length;
      }

      // Add the column to the visible columns
      this._visibleColumnArr.splice(nextVisX, 0, col);
    } else {
      var visX = this.getVisibleX(col);
      this._visibleColumnArr.splice(visX, 1);
    }

    // Invalidate the _colToXPosMap
    this._colToXPosMap = null;

    // Inform the listeners
    if (! this._internalChange) {
      if (this.hasEventListeners("visibilityChangedPre")) {
        var data = { col:col, visible:visible }
        this.dispatchEvent(new qx.event.type.DataEvent("visibilityChangedPre", data), true);
      }
      if (this.hasEventListeners("visibilityChanged")) {
        var data = { col:col, visible:visible }
        this.dispatchEvent(new qx.event.type.DataEvent("visibilityChanged", data), true);
      }
    }

    //this.debug("setColumnVisible col:"+col+",visible:"+visible+",this._overallColumnArr:"+this._overallColumnArr+",this._visibleColumnArr:"+this._visibleColumnArr);
  }
}


/**
 * Moves a column.
 *
 * @param fromOverXPos {int} the overall x postion of the column to move.
 * @param toOverXPos {int} the overall x postion of where the column should be
 *    moved to.
 */
qx.Proto.moveColumn = function(fromOverXPos, toOverXPos) {
  this._internalChange = true;

  var col = this._overallColumnArr[fromOverXPos];
  var visible = this.isColumnVisible(col);

  if (visible) {
    this.setColumnVisible(col, false);
  }

  this._overallColumnArr.splice(fromOverXPos, 1);
  this._overallColumnArr.splice(toOverXPos, 0, col);

  // Invalidate the _colToXPosMap
  this._colToXPosMap = null;

  if (visible) {
    this.setColumnVisible(col, true);
  }

  this._internalChange = false;

  // Inform the listeners
  if (this.hasEventListeners("orderChanged")) {
    var data = { col:col, fromOverXPos:fromOverXPos, toOverXPos:toOverXPos }
    this.dispatchEvent(new qx.event.type.DataEvent("orderChanged", data), true);
  }
}


/** {int} the default width of a column in pixels. */
qx.Class.DEFAULT_WIDTH = 100;

/** {DefaultDataCellRenderer} the default header cell renderer. */
qx.Class.DEFAULT_HEADER_RENDERER = new qx.ui.table.DefaultHeaderCellRenderer;

/** {DefaultDataCellRenderer} the default data cell renderer. */
qx.Class.DEFAULT_DATA_RENDERER = new qx.ui.table.DefaultDataCellRenderer;

/** {TextFieldCellEditorFactory} the default editor factory. */
qx.Class.DEFAULT_EDITOR_FACTORY = new qx.ui.table.TextFieldCellEditorFactory;
