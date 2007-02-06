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
#require(qx.ui.table.DefaultDataRowRenderer)
#embed(qx.widgettheme/table/selectColumnOrder.png)

************************************************************************ */

/**
 * A table.
 *
 * @param tableModel {qx.ui.table.TableModel, null} The table model to read the
 *        data from.
 */
qx.OO.defineClass("qx.ui.table.Table", qx.ui.layout.VerticalBoxLayout,
function(tableModel) {
  qx.ui.layout.VerticalBoxLayout.call(this);

  // Create the child widgets
  this._scrollerParent = new qx.ui.layout.HorizontalBoxLayout;
  this._scrollerParent.setDimension("100%", "1*");
  this._scrollerParent.setSpacing(1);

  this._statusBar = new qx.ui.basic.Label;
  this._statusBar.setAppearance("table-focus-statusbar");
  this._statusBar.setDimension("100%", "auto");

  this.add(this._scrollerParent, this._statusBar);

  this._columnVisibilityBt = new qx.ui.toolbar.Button(null, "widget/table/selectColumnOrder.png");
  this._columnVisibilityBt.addEventListener("execute", this._onColumnVisibilityBtExecuted, this);

  // Create the models
  this._selectionManager = this.getNewSelectionManager()(this);
  this.setSelectionModel(this.getNewSelectionModel()(this));
  this.setTableColumnModel(this.getNewTableColumnModel()(this));

  // If a table model was provided...
  if (tableModel != null) {
    // ... then save it.
    this.setTableModel(tableModel);
  }

  // create the main meta column
  this.setMetaColumnCounts([ -1 ]);

  // Make focusable
  this.setTabIndex(1);
  this.addEventListener("keydown", this._onkeydown);
  this.addEventListener("keypress", this._onkeypress);
  this.addEventListener("changeFocused", this._onFocusChanged);

  this._focusedCol = 0;
  this._focusedRow = 0;
});


/** The default row renderer to use when {@link #dataRowRenderer} is null. */
qx.Class.DEFAULT_DATA_ROW_RENDERER = new qx.ui.table.DefaultDataRowRenderer();


/** The selection model. */
qx.OO.addProperty({ name:"selectionModel", type:"object", instance : "qx.ui.table.SelectionModel" });

/** The table model. */
qx.OO.addProperty({ name:"tableModel", type:"object", instance : "qx.ui.table.TableModel" });

/** The table column model. */
qx.OO.addProperty({ name:"tableColumnModel", type:"object", instance : "qx.ui.table.TableColumnModel" });

/** The height of the table rows. */
qx.OO.addProperty({ name:"rowHeight", type:"number", defaultValue:15 });

/** Whether to show the status bar */
qx.OO.addProperty({ name:"statusBarVisible", type:"boolean", defaultValue:true });

/** Whether to show the column visibility button */
qx.OO.addProperty({ name:"columnVisibilityButtonVisible", type:"boolean", defaultValue:true });

/**
 * {int[]} The number of columns per meta column. If the last array entry is -1,
 * this meta column will get the remaining columns.
 */
qx.OO.addProperty({ name:"metaColumnCounts", type:"object" });

/**
 * Whether the focus should moved when the mouse is moved over a cell. If false
 * the focus is only moved on mouse clicks.
 */
qx.OO.addProperty({ name:"focusCellOnMouseMove", type:"boolean", defaultValue:false });

/**
 * Whether the table should keep the first visible row complete. If set to false,
 * the first row may be rendered partial, depending on the vertical scroll value.
 */
qx.OO.addProperty({ name:"keepFirstVisibleRowComplete", type:"boolean", defaultValue:true });

/**
 * Whether the table cells should be updated when only the selection or the
 * focus changed. This slows down the table update but allows to react on a
 * changed selection or a changed focus in a cell renderer.
 */
qx.OO.addProperty({ name:"alwaysUpdateCells", type:"boolean", defaultValue:false });

/** The height of the header cells. */
qx.OO.addProperty({ name:"headerCellHeight", type:"number", defaultValue:16, allowNull:false });

/** The renderer to use for styling the rows. */
qx.OO.addProperty({ name:"dataRowRenderer", type:"object", instance:"qx.ui.table.DataRowRenderer", defaultValue:qx.Class.DEFAULT_DATA_ROW_RENDERER, allowNull:false });

/**
 * A function to instantiate a selection manager.  this allows subclasses of
 * Table to subclass this internal class.  To take effect, this property must
 * be set before calling the Table constructor.
 */
qx.OO.addProperty(
  {
    name :
      "newSelectionManager",
    type :
      "function",
    setOnlyOnce :
      true,
    defaultValue:
      function(obj)
      {
        return new qx.ui.table.SelectionManager(obj);
      }
  });

/**
 * A function to instantiate a selection model.  this allows subclasses of
 * Table to subclass this internal class.  To take effect, this property must
 * be set before calling the Table constructor.
 */
qx.OO.addProperty(
  {
    name :
      "newSelectionModel",
    type :
      "function",
    setOnlyOnce :
      true,
    defaultValue:
      function(obj)
      {
        return new qx.ui.table.SelectionModel(obj);
      }
  });

/**
 * A function to instantiate a selection model.  this allows subclasses of
 * Table to subclass this internal class.  To take effect, this property must
 * be set before calling the Table constructor.
 */
qx.OO.addProperty(
  {
    name :
      "newTableColumnModel",
    type :
      "function",
    setOnlyOnce :
      true,
    defaultValue:
      function(obj)
      {
        return new qx.ui.table.TableColumnModel(obj);
      }
  });

/**
 * A function to instantiate a table pane.  this allows subclasses of Table to
 * subclass this internal class.  To take effect, this property must be set
 * before calling the Table constructor.
 */
qx.OO.addProperty(
  {
    name :
      "newTablePane",
    type :
      "function",
    setOnlyOnce :
      true,
    defaultValue:
      function(obj)
      {
        return new qx.ui.table.TablePane(obj);
      }
  });

/**
 * A function to instantiate a table pane.  this allows subclasses of Table to
 * subclass this internal class.  To take effect, this property must be set
 * before calling the Table constructor.
 */
qx.OO.addProperty(
  {
    name :
      "newTablePaneHeader",
    type :
      "function",
    setOnlyOnce :
      true,
    defaultValue:
      function(obj)
      {
        return new qx.ui.table.TablePaneHeader(obj);
      }
  });

/**
 * A function to instantiate a table pane scroller.  this allows subclasses of
 * Table to subclass this internal class.  To take effect, this property must
 * be set before calling the Table constructor.
 */
qx.OO.addProperty(
  {
    name :
      "newTablePaneScroller",
    type :
      "function",
    setOnlyOnce :
      true,
    defaultValue:
      function(obj)
      {
        return new qx.ui.table.TablePaneScroller(obj);
      }
  });

/**
 * A function to instantiate a table pane model.  this allows subclasses of
 * Table to subclass this internal class.  To take effect, this property must
 * be set before calling the Table constructor.
 */
qx.OO.addProperty(
  {
    name :
      "newTablePaneModel",
    type :
      "function",
    setOnlyOnce :
      true,
    defaultValue:
      function(columnModel)
      {
        return new qx.ui.table.TablePaneModel(columnModel);
      }
  });

// property modifier
qx.Proto._modifySelectionModel = function(propValue, propOldValue, propData) {
  this._selectionManager.setSelectionModel(propValue);

  if (propOldValue != null) {
    propOldValue.removeEventListener("changeSelection", this._onSelectionChanged, this);
  }
  propValue.addEventListener("changeSelection", this._onSelectionChanged, this);

  return true;
}


// property modifier
qx.Proto._modifyTableModel = function(propValue, propOldValue, propData) {
  this.getTableColumnModel().init(propValue.getColumnCount());

  if (propOldValue != null) {
    propOldValue.removeEventListener(qx.ui.table.TableModel.EVENT_TYPE_META_DATA_CHANGED, this._onTableModelMetaDataChanged, this);
    propOldValue.removeEventListener(qx.ui.table.TableModel.EVENT_TYPE_DATA_CHANGED, this._onTableModelDataChanged, this);
  }
  propValue.addEventListener(qx.ui.table.TableModel.EVENT_TYPE_META_DATA_CHANGED, this._onTableModelMetaDataChanged, this);
  propValue.addEventListener(qx.ui.table.TableModel.EVENT_TYPE_DATA_CHANGED, this._onTableModelDataChanged, this);

  // Update the status bar
  this._updateStatusBar();

  return true;
}


// property modifier
qx.Proto._modifyTableColumnModel = function(propValue, propOldValue, propData) {
  if (propOldValue != null) {
    propOldValue.removeEventListener("visibilityChanged", this._onColVisibilityChanged, this);
    propOldValue.removeEventListener("widthChanged", this._onColWidthChanged, this);
    propOldValue.removeEventListener("orderChanged", this._onColOrderChanged, this);
  }
  propValue.addEventListener("visibilityChanged", this._onColVisibilityChanged, this);
  propValue.addEventListener("widthChanged", this._onColWidthChanged, this);
  propValue.addEventListener("orderChanged", this._onColOrderChanged, this);

  return true;
};


// property modifier
qx.Proto._modifyStatusBarVisible = function(propValue, propOldValue, propData) {
  this._statusBar.setDisplay(propValue);

  if (propValue) {
    this._updateStatusBar();
  }
  return true;
};


// property modifier
qx.Proto._modifyColumnVisibilityButtonVisible = function(propValue, propOldValue, propData) {
  this._columnVisibilityBt.setDisplay(propValue);

  return true;
};


// property modifier
qx.Proto._modifyMetaColumnCounts = function(propValue, propOldValue, propData) {
  var metaColumnCounts = propValue;
  var scrollerArr = this._getPaneScrollerArr();

  // Remove the panes not needed any more
  this._cleanUpMetaColumns(metaColumnCounts.length);

  // Update the old panes
  var leftX = 0;
  for (var i = 0; i < scrollerArr.length; i++) {
    var paneScroller = scrollerArr[i];
    var paneModel = paneScroller.getTablePaneModel();
    paneModel.setFirstColumnX(leftX);
    paneModel.setMaxColumnCount(metaColumnCounts[i]);
    leftX += metaColumnCounts[i];
  }

  // Add the new panes
  if (metaColumnCounts.length > scrollerArr.length) {
    var selectionModel = this.getSelectionModel();
    var tableModel = this.getTableModel();
    var columnModel = this.getTableColumnModel();

    for (var i = scrollerArr.length; i < metaColumnCounts.length; i++) {
      var paneModel = this.getNewTablePaneModel()(columnModel);
      paneModel.setFirstColumnX(leftX);
      paneModel.setMaxColumnCount(metaColumnCounts[i]);
      leftX += metaColumnCounts[i];

      var paneScroller = this.getNewTablePaneScroller()(this);
      paneScroller.setTablePaneModel(paneModel);

      // Register event listener for vertical scrolling
      paneScroller.addEventListener("changeScrollY", this._onScrollY, this);

      this._scrollerParent.add(paneScroller);
    }
  }

  // Update all meta columns
  for (var i = 0; i < scrollerArr.length; i++) {
    var paneScroller = scrollerArr[i];
    var isLast = (i == (scrollerArr.length - 1));

    // Set the right header height
    paneScroller.getHeader().setHeight(this.getHeaderCellHeight());

    // Put the _columnVisibilityBt in the top right corner of the last meta column
    paneScroller.setTopRightWidget(isLast ? this._columnVisibilityBt : null);
  }

  this._updateScrollerWidths();
  this._updateScrollBarVisibility();

  return true;
}


// property modifier
qx.Proto._modifyFocusCellOnMouseMove = function(propValue, propOldValue, propData) {
  var scrollerArr = this._getPaneScrollerArr();
  for (var i = 0; i < scrollerArr.length; i++) {
    scrollerArr[i].setFocusCellOnMouseMove(propValue);
  }
  return true;
};


// property modifier
qx.Proto._modifyKeepFirstVisibleRowComplete = function(propValue, propOldValue, propData) {
  var scrollerArr = this._getPaneScrollerArr();
  for (var i = 0; i < scrollerArr.length; i++) {
    scrollerArr[i]._onKeepFirstVisibleRowCompleteChanged();
  }
  return true;
};


// property modifier
qx.Proto._modifyHeaderCellHeight = function(propValue, propOldValue, propData) {
  var scrollerArr = this._getPaneScrollerArr();
  for (var i = 0; i < scrollerArr.length; i++) {
    scrollerArr[i].getHeader().setHeight(propValue);
  }
  return true;
};

/**
 * Returns the selection manager.
 *
 * @return {SelectionManager} the selection manager.
 */
qx.Proto._getSelectionManager = function() {
  return this._selectionManager;
};


/**
 * Returns an array containing all TablePaneScrollers in this table.
 *
 * @return {TablePaneScroller[]} all TablePaneScrollers in this table.
 */
qx.Proto._getPaneScrollerArr = function() {
  return this._scrollerParent.getChildren();
}


/**
 * Returns a TablePaneScroller of this table.
 *
 * @param metaColumn {Integer} the meta column to get the TablePaneScroller for.
 * @return {TablePaneScroller} the TablePaneScroller.
 */
qx.Proto.getPaneScroller = function(metaColumn) {
  return this._getPaneScrollerArr()[metaColumn];
}


/**
 * Cleans up the meta columns.
 *
 * @param fromMetaColumn {Integer} the first meta column to clean up. All following
 *    meta columns will be cleaned up, too. All previous meta columns will
 *    stay unchanged. If 0 all meta columns will be cleaned up.
 */
qx.Proto._cleanUpMetaColumns = function(fromMetaColumn) {
  var scrollerArr = this._getPaneScrollerArr();
  if (scrollerArr != null) {
    for (var i = scrollerArr.length - 1; i >= fromMetaColumn; i--) {
      var paneScroller = scrollerArr[i];
      paneScroller.removeEventListener("changeScrollY", this._onScrollY, this);
      this._scrollerParent.remove(paneScroller);
      paneScroller.dispose();
    }
  }
}


/**
 * Event handler. Called when the selection has changed.
 *
 * @param evt {Map} the event.
 */
qx.Proto._onSelectionChanged = function(evt) {
  var scrollerArr = this._getPaneScrollerArr();
  for (var i = 0; i < scrollerArr.length; i++) {
    scrollerArr[i]._onSelectionChanged(evt);
  }

  this._updateStatusBar();
}


/**
 * Event handler. Called when the table model meta data has changed.
 *
 * @param evt {Map} the event.
 */
qx.Proto._onTableModelMetaDataChanged = function(evt) {
  var scrollerArr = this._getPaneScrollerArr();
  for (var i = 0; i < scrollerArr.length; i++) {
    scrollerArr[i]._onTableModelMetaDataChanged(evt);
  }

  this._updateStatusBar();
}


/**
 * Event handler. Called when the table model data has changed.
 *
 * @param evt {Map} the event.
 */
qx.Proto._onTableModelDataChanged = function(evt) {
  var scrollerArr = this._getPaneScrollerArr();
  for (var i = 0; i < scrollerArr.length; i++) {
    scrollerArr[i]._onTableModelDataChanged(evt);
  }

  var rowCount = this.getTableModel().getRowCount();
  if (rowCount != this._lastRowCount) {
    this._lastRowCount = rowCount;

    this._updateScrollBarVisibility();
    this._updateStatusBar();
  }
};


/**
 * Event handler. Called when a TablePaneScroller has been scrolled vertically.
 *
 * @param evt {Map} the event.
 */
qx.Proto._onScrollY = function(evt) {
  if (! this._internalChange) {
    this._internalChange = true;

    // Set the same scroll position to all meta columns
    var scrollerArr = this._getPaneScrollerArr();
    for (var i = 0; i < scrollerArr.length; i++) {
      scrollerArr[i].setScrollY(evt.getData());
    }

    this._internalChange = false;
  }
}


/**
 * Event handler. Called when a key was pressed.
 *
 * @param evt {Map} the event.
 */
qx.Proto._onkeydown = function(evt) {
  if (! this.getEnabled()) {
    return;
  }

  var identifier = evt.getKeyIdentifier();

  var consumed = false;
  var oldFocusedRow = this._focusedRow;
  if (this.isEditing()) {
    // Editing mode
    if (evt.getModifiers() == 0) {
      consumed = true;
      switch (identifier) {
        case "Enter":
          this.stopEditing();
          var oldFocusedRow = this._focusedRow;
          this.moveFocusedCell(0, 1);
          if (this._focusedRow != oldFocusedRow) {
            this.startEditing();
          }
          break;
        case "Escape":
          this.cancelEditing();
          this.focus();
          break;
        default:
          consumed = false;
          break;
      }
    }
  } else {
    // No editing mode

    // Handle keys that are independant from the modifiers
    consumed = true;
    switch (identifier) {
      case "Home":
        this.setFocusedCell(this._focusedCol, 0, true);
        break;
      case "End":
        var rowCount = this.getTableModel().getRowCount();
        this.setFocusedCell(this._focusedCol, rowCount - 1, true);
        break;
      default:
        consumed = false;
        break;
    }

    // Handle keys that depend on modifiers
    if (evt.getModifiers() == 0) {
      consumed = true;
      switch (identifier) {
        case "F2":
        case "Enter":
          this.startEditing();
          break;
        default:
          consumed = false;
          break;
      }
    } else if (evt.isCtrlPressed()) {
      consumed = true;
      switch (identifier) {
        case "A": // Ctrl + A
          var rowCount = this.getTableModel().getRowCount();
          if (rowCount > 0) {
            this.getSelectionModel().setSelectionInterval(0, rowCount - 1);
          }
          break;
        default:
          consumed = false;
          break;
      }
    }
  }

  if (oldFocusedRow != this._focusedRow) {
    // The focus moved -> Let the selection manager handle this event
    this._selectionManager.handleMoveKeyDown(this._focusedRow, evt);
  }

  if (consumed) {
    evt.preventDefault();
    evt.stopPropagation();
  }
};


qx.Proto._onkeypress = function(evt)
{
  if (! this.getEnabled()) {
    return;
  }

  if (this.isEditing()) { return }
  // No editing mode
  var oldFocusedRow = this._focusedRow;
  var consumed = true;

  // Handle keys that are independant from the modifiers
  var identifier = evt.getKeyIdentifier();
  switch (identifier) {
    case "Space":
      this._selectionManager.handleSelectKeyDown(this._focusedRow, evt);
      break;

    case "Left":
      this.moveFocusedCell(-1, 0);
      break;

    case "Right":
      this.moveFocusedCell(1, 0);
      break;

    case "Up":
      this.moveFocusedCell(0, -1);
      break;

    case "Down":
      this.moveFocusedCell(0, 1);
      break;

    case "PageUp":
    case "PageDown":
      var scroller = this.getPaneScroller(0);
      var pane = scroller.getTablePane();
      var rowCount = pane.getVisibleRowCount() - 1;
      var rowHeight = this.getRowHeight();
      var direction = (identifier == "PageUp") ? -1 : 1;
      scroller.setScrollY(scroller.getScrollY() + direction * rowCount * rowHeight);
      this.moveFocusedCell(0, direction * rowCount);
      break;

    default:
      consumed = false;
  }
  if (oldFocusedRow != this._focusedRow) {
    // The focus moved -> Let the selection manager handle this event
    this._selectionManager.handleMoveKeyDown(this._focusedRow, evt);
  }

  if (consumed) {
    evt.preventDefault();
    evt.stopPropagation();
  }
};


/**
 * Event handler. Called when the table gets the focus.
 */
qx.Proto._onFocusChanged = function(evt) {
  var scrollerArr = this._getPaneScrollerArr();
  for (var i = 0; i < scrollerArr.length; i++) {
    scrollerArr[i]._onFocusChanged(evt);
  }
};


/**
 * Event handler. Called when the visibility of a column has changed.
 *
 * @param evt {Map} the event.
 */
qx.Proto._onColVisibilityChanged = function(evt) {
  var scrollerArr = this._getPaneScrollerArr();
  for (var i = 0; i < scrollerArr.length; i++) {
    scrollerArr[i]._onColVisibilityChanged(evt);
  }

  this._updateScrollerWidths();
  this._updateScrollBarVisibility();
}


/**
 * Event handler. Called when the width of a column has changed.
 *
 * @param evt {Map} the event.
 */
qx.Proto._onColWidthChanged = function(evt) {
  var scrollerArr = this._getPaneScrollerArr();
  for (var i = 0; i < scrollerArr.length; i++) {
    scrollerArr[i]._onColWidthChanged(evt);
  }

  this._updateScrollerWidths();
  this._updateScrollBarVisibility();
}


/**
 * Event handler. Called when the column order has changed.
 *
 * @param evt {Map} the event.
 */
qx.Proto._onColOrderChanged = function(evt) {
  var scrollerArr = this._getPaneScrollerArr();
  for (var i = 0; i < scrollerArr.length; i++) {
    scrollerArr[i]._onColOrderChanged(evt);
  }

  // A column may have been moved between meta columns
  this._updateScrollerWidths();
  this._updateScrollBarVisibility();
}


/**
 * Gets the TablePaneScroller at a certain x position in the page. If there is
 * no TablePaneScroller at this postion, null is returned.
 *
 * @param pageX {Integer} the position in the page to check (in pixels).
 * @return {TablePaneScroller} the TablePaneScroller or null.
 *
 * @see TablePaneScrollerPool
 */
qx.Proto.getTablePaneScrollerAtPageX = function(pageX) {
  var metaCol = this._getMetaColumnAtPageX(pageX);
  return (metaCol != -1) ? this.getPaneScroller(metaCol) : null;
}


/**
 * Sets the currently focused cell.
 *
 * @param col {Integer} the model index of the focused cell's column.
 * @param row {Integer} the model index of the focused cell's row.
 * @param scrollVisible {Boolean ? false} whether to scroll the new focused cell
 *        visible.
 *
 * @see TablePaneScrollerPool
 */
qx.Proto.setFocusedCell = function(col, row, scrollVisible) {
  if (!this.isEditing() && (col != this._focusedCol || row != this._focusedRow)) {
    this._focusedCol = col;
    this._focusedRow = row;

    var scrollerArr = this._getPaneScrollerArr();
    for (var i = 0; i < scrollerArr.length; i++) {
      scrollerArr[i].setFocusedCell(col, row);
    }

    if (scrollVisible) {
      this.scrollCellVisible(col, row);
    }
  }
}


/**
 * Returns the column of the currently focused cell.
 *
 * @return {Integer} the model index of the focused cell's column.
 */
qx.Proto.getFocusedColumn = function() {
  return this._focusedCol;
};


/**
 * Returns the row of the currently focused cell.
 *
 * @return {Integer} the model index of the focused cell's column.
 */
qx.Proto.getFocusedRow = function() {
  return this._focusedRow;
};


/**
 * Moves the focus.
 *
 * @param deltaX {Integer} The delta by which the focus should be moved on the x axis.
 * @param deltaY {Integer} The delta by which the focus should be moved on the y axis.
 */
qx.Proto.moveFocusedCell = function(deltaX, deltaY) {
  var col = this._focusedCol;
  var row = this._focusedRow;

  if (deltaX != 0) {
    var columnModel = this.getTableColumnModel();
    var x = columnModel.getVisibleX(col);
    var colCount = columnModel.getVisibleColumnCount();
    x = qx.lang.Number.limit(x + deltaX, 0, colCount - 1);
    col = columnModel.getVisibleColumnAtX(x);
  }

  if (deltaY != 0) {
    var tableModel = this.getTableModel();
    row = qx.lang.Number.limit(row + deltaY, 0, tableModel.getRowCount() - 1);
  }

  this.setFocusedCell(col, row, true);
}


/**
 * Scrolls a cell visible.
 *
 * @param col {Integer} the model index of the column the cell belongs to.
 * @param row {Integer} the model index of the row the cell belongs to.
 */
qx.Proto.scrollCellVisible = function(col, row) {
  var columnModel = this.getTableColumnModel();
  var x = columnModel.getVisibleX(col);

  var metaColumn = this._getMetaColumnAtColumnX(x);
  if (metaColumn != -1) {
    this.getPaneScroller(metaColumn).scrollCellVisible(col, row);
  }
}


/**
 * Returns whether currently a cell is editing.
 *
 * @return whether currently a cell is editing.
 */
qx.Proto.isEditing = function() {
  if (this._focusedCol != null) {
    var x = this.getTableColumnModel().getVisibleX(this._focusedCol);
    var metaColumn = this._getMetaColumnAtColumnX(x);
    return this.getPaneScroller(metaColumn).isEditing();
  }
}


/**
 * Starts editing the currently focused cell. Does nothing if already editing
 * or if the column is not editable.
 *
 * @return {Boolean} whether editing was started
 */
qx.Proto.startEditing = function() {
  if (this._focusedCol != null) {
    var x = this.getTableColumnModel().getVisibleX(this._focusedCol);
    var metaColumn = this._getMetaColumnAtColumnX(x);
    return this.getPaneScroller(metaColumn).startEditing();
  }
  return false;
}


/**
 * Stops editing and writes the editor's value to the model.
 */
qx.Proto.stopEditing = function() {
  if (this._focusedCol != null) {
    var x = this.getTableColumnModel().getVisibleX(this._focusedCol);
    var metaColumn = this._getMetaColumnAtColumnX(x);
    this.getPaneScroller(metaColumn).stopEditing();
  }
}


/**
 * Stops editing without writing the editor's value to the model.
 */
qx.Proto.cancelEditing = function() {
  if (this._focusedCol != null) {
    var x = this.getTableColumnModel().getVisibleX(this._focusedCol);
    var metaColumn = this._getMetaColumnAtColumnX(x);
    this.getPaneScroller(metaColumn).cancelEditing();
  }
}


/**
 * Gets the meta column at a certain x position in the page. If there is no
 * meta column at this postion, -1 is returned.
 *
 * @param pageX {Integer} the position in the page to check (in pixels).
 * @return {Integer} the index of the meta column or -1.
 */
qx.Proto._getMetaColumnAtPageX = function(pageX) {
  var scrollerArr = this._getPaneScrollerArr();
  for (var i = 0; i < scrollerArr.length; i++) {
    var elem = scrollerArr[i].getElement();
    if (pageX >= qx.html.Location.getPageBoxLeft(elem)
      && pageX <= qx.html.Location.getPageBoxRight(elem))
    {
      return i;
    }
  }

  return -1;
}


/**
 * Returns the meta column a column is shown in. If the column is not shown at
 * all, -1 is returned.
 *
 * @param visXPos {Integer} the visible x position of the column.
 * @return {Integer} the meta column the column is shown in.
 */
qx.Proto._getMetaColumnAtColumnX = function(visXPos) {
  var metaColumnCounts = this.getMetaColumnCounts();
  var rightXPos = 0;
  for (var i = 0; i < metaColumnCounts.length; i++) {
    var counts = metaColumnCounts[i];
    rightXPos += counts;

    if (counts == -1 || visXPos < rightXPos) {
      return i;
    }
  }

  return -1;
}


/**
 * Updates the text shown in the status bar.
 */
qx.Proto._updateStatusBar = function() {
  if (this.getStatusBarVisible()) {
    var selectedRowCount = this.getSelectionModel().getSelectedCount();
    var rowCount = this.getTableModel().getRowCount();

    var text;
    if (selectedRowCount == 0) {
      text = rowCount + ((rowCount == 1) ? " row" : " rows");
    } else {
      text = selectedRowCount + " of " + rowCount
        + ((rowCount == 1) ? " row" : " rows") + " selected";
    }
    this._statusBar.setHtml(text);
  }
}


/**
 * Updates the widths of all scrollers.
 */
qx.Proto._updateScrollerWidths = function() {
/*  no longer needed, per Til, and removing it does not appear to add problems.
 *  qx.ui.core.Widget.flushGlobalQueues();
 */

  // Give all scrollers except for the last one the wanted width
  // (The last one has a flex with)
  var scrollerArr = this._getPaneScrollerArr();
  for (var i = 0; i < scrollerArr.length; i++) {
    var isLast = (i == (scrollerArr.length - 1));
    var width = isLast ? "1*" : scrollerArr[i].getTablePaneModel().getTotalWidth();
    scrollerArr[i].setWidth(width);
  }
}


/**
 * Updates the visibility of the scrollbars in the meta columns.
 */
qx.Proto._updateScrollBarVisibility = function() {
  if (this.isSeeable()) {
    var horBar = qx.ui.table.TablePaneScroller.HORIZONTAL_SCROLLBAR;
    var verBar = qx.ui.table.TablePaneScroller.VERTICAL_SCROLLBAR;
    var scrollerArr = this._getPaneScrollerArr();

    // Check which scroll bars are needed
    var horNeeded = false;
    var verNeeded = false;
    for (var i = 0; i < scrollerArr.length; i++) {
      var isLast = (i == (scrollerArr.length - 1));

      // Only show the last vertical scrollbar
      var bars = scrollerArr[i].getNeededScrollBars(horNeeded, !isLast);

      if (bars & horBar) {
        horNeeded = true;
      }
      if (isLast && (bars & verBar)) {
        verNeeded = true;
      }
    }

    // Set the needed scrollbars
    for (var i = 0; i < scrollerArr.length; i++) {
      var isLast = (i == (scrollerArr.length - 1));

      // Only show the last vertical scrollbar
      scrollerArr[i].setHorizontalScrollBarVisible(horNeeded);
      scrollerArr[i].setVerticalScrollBarVisible(isLast && verNeeded);
    }
  }
}


/**
 * Event handler. Called when the column visibiliy button was executed.
 */
qx.Proto._onColumnVisibilityBtExecuted = function() {
  if ((this._columnVisibilityMenuCloseTime == null)
    || (new Date().getTime() > this._columnVisibilityMenuCloseTime + 200))
  {
    this._toggleColumnVisibilityMenu();
  }
}


/**
 * Toggels the visibility of the menu used to change the visibility of columns.
 */
qx.Proto._toggleColumnVisibilityMenu = function() {
  if (this._columnVisibilityMenu == null || !this._columnVisibilityMenu.isSeeable()) {
    if (! this.getEnabled()) {
      return;
    }

    // Show the menu

    // Create the new menu
    var menu = new qx.ui.menu.Menu;

    menu.addEventListener("disappear", function(evt) {
      this._columnVisibilityMenuCloseTime = new Date().getTime();
    }, this);

    var tableModel = this.getTableModel();
    var columnModel = this.getTableColumnModel();
    for (var x = 0; x < columnModel.getOverallColumnCount(); x++) {
      var col = columnModel.getOverallColumnAtX(x);
      var visible = columnModel.isColumnVisible(col);
      var cmd = { col:col }
      var bt = new qx.ui.menu.CheckBox(tableModel.getColumnName(col), null, visible);

      var handler = this._createColumnVisibilityCheckBoxHandler(col);
      bt._handler = handler;
      bt.addEventListener("execute", handler, this);

      menu.add(bt);
    }

    menu.setParent(this.getTopLevelWidget());

    this._columnVisibilityMenu = menu;

    // Show the menu
    var btElem = this._columnVisibilityBt.getElement();
    menu.setRestrictToPageOnOpen(false);
    menu.setTop(qx.html.Location.getClientBoxBottom(btElem));
    menu.setLeft(-1000);

    // NOTE: We have to show the menu in a timeout, otherwise it won't be shown
    //       at all.
    window.setTimeout(function() {
      menu.show();
      qx.ui.core.Widget.flushGlobalQueues();

      menu.setLeft(qx.html.Location.getClientBoxRight(btElem) - menu.getOffsetWidth());
      qx.ui.core.Widget.flushGlobalQueues();
    }, 0);
  } else {
    // hide the menu
    menu.hide();
    this._cleanupColumnVisibilityMenu();
  }
}


/**
 * Cleans up the column visibility menu.
 */
qx.Proto._cleanupColumnVisibilityMenu = function() {
  if (this._columnVisibilityMenu != null && ! this._columnVisibilityMenu.getDisposed()) {
    this._columnVisibilityMenu.dispose();
    this._columnVisibilityMenu = null;
  }
}


/**
 * Creates a handler for a check box of the column visibility menu.
 *
 * @param col {Integer} the model index of column to create the handler for.
 */
qx.Proto._createColumnVisibilityCheckBoxHandler = function(col) {
  return function(evt) {
    var columnModel = this.getTableColumnModel();
    columnModel.setColumnVisible(col, !columnModel.isColumnVisible(col));
  }
}


/**
 * Sets the width of a column.
 *
 * @param col {Integer} the model index of column.
 * @param width {Integer} the new width in pixels.
 */
qx.Proto.setColumnWidth = function(col, width) {
  this.getTableColumnModel().setColumnWidth(col, width);
}


// overridden
qx.Proto._changeInnerWidth = function(newValue, oldValue) {
  var self = this;
  window.setTimeout(function() {
    self._updateScrollBarVisibility();
    qx.ui.core.Widget.flushGlobalQueues();
  }, 0);

  return qx.ui.layout.VerticalBoxLayout.prototype._changeInnerWidth.call(this, newValue, oldValue);
}


// overridden
qx.Proto._changeInnerHeight = function(newValue, oldValue) {
  var self = this;
  window.setTimeout(function() {
    self._updateScrollBarVisibility();
    qx.ui.core.Widget.flushGlobalQueues();
  }, 0);

  return qx.ui.layout.VerticalBoxLayout.prototype._changeInnerHeight.call(this, newValue, oldValue);
}


// overridden
qx.Proto._afterAppear = function() {
  qx.ui.layout.VerticalBoxLayout.prototype._afterAppear.call(this);

  this._updateScrollBarVisibility();
}


// overridden
qx.Proto.dispose = function() {
  if (this.getDisposed()) {
    return true;
  }

  if (this._tableModel) {
    this._tableModel.removeEventListener(qx.ui.table.TableModel.EVENT_TYPE_META_DATA_CHANGED, this._onTableModelMetaDataChanged, this);
  }

  this._columnVisibilityBt.removeEventListener("execute", this._onColumnVisibilityBtExecuted, this);
  this._columnVisibilityBt.dispose();

  this._cleanupColumnVisibilityMenu();

  this._cleanUpMetaColumns(0);

  var selectionModel = this.getSelectionModel();
  if (selectionModel != null) {
    selectionModel.removeEventListener("changeSelection", this._onSelectionChanged, this);
  }

  var tableModel = this.getTableModel();
  if (tableModel != null) {
    tableModel.removeEventListener(qx.ui.table.TableModel.EVENT_TYPE_META_DATA_CHANGED, this._onTableModelMetaDataChanged, this);
    tableModel.removeEventListener(qx.ui.table.TableModel.EVENT_TYPE_DATA_CHANGED, this._onTableModelDataChanged, this);
  }

  var tableColumnModel = this.getTableColumnModel();
  if (tableColumnModel) {
    tableColumnModel.removeEventListener("visibilityChanged", this._onColVisibilityChanged, this);
    tableColumnModel.removeEventListener("widthChanged", this._onColWidthChanged, this);
    tableColumnModel.removeEventListener("orderChanged", this._onColOrderChanged, this);
  }

  this.removeEventListener("keydown", this._onkeydown);
  this.removeEventListener("keypress", this._onkeypress);

  return qx.ui.layout.VerticalBoxLayout.prototype.dispose.call(this);
}
