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
 * The default resize behavior.  Until a resize model is loaded, the default
 * behavior is to:
 * <ol>
 *   <li>
 *     Upon the table initially appearing, and upon any window resize, divide
 *     the table space equally between the visible columns.
 *   </li>
 *   <li>
 *     When a column is increased in width, all columns to its right are
 *     pushed to the right with no change to their widths.  This may push some
 *     columns off the right edge of the table, causing a horizontal scroll
 *     bar to appear.
 *   </li>
 *   <li>
 *     When a column is decreased in width, if the total width of all columns
 *     is <i>greater than</i> the table width, no additional column wiidth
 *     changes are made.
 *   </li>
 *   <li>
 *     When a column is decreased in width, if the total width of all columns
 *     is <i>less than</i> the width of the table, the visible column
 *     immediately to the right of the column which decreased in width has its
 *     width increased to fill the remaining space.
 *   </li>
 * </ol>
 *
 * A resize model may be loaded to provide more guidance on how to adjust
 * column width upon each of the events: initial appear, window resize, and
 * column resize. *** TO BE FILLED IN ***
 */
qx.OO.defineClass("qx.ui.table.DefaultResizeBehavior",
                  qx.ui.table.AbstractResizeBehavior,
function()
{
  qx.ui.table.AbstractResizeBehavior.call(this);
});


/*
 * A function to instantiate a resize behavior column data object.
 */
qx.OO.addProperty(
  {
    name :
      "newResizeBehaviorColumnData",
    type :
      "function",
    setOnlyOnce :
      true,
    defaultValue:
      function(obj)
      {
        return new qx.ui.table.ResizeBehaviorColumnData();
      }
  });


/**
 * Set the width of a column.
 *
 * @param col {Integer}
 *   The column whose width is to be set
 *
 * @param width {Integer, String}
 *   The width of the specified column.  The width may be specified as integer
 *   number of pixels (e.g. 100), a string representing percentage of the
 *   inner width of the Table (e.g. "25%"), or a string representing a flex
 *   width (e.g. "1*").
 */
qx.Proto.setWidth = function(col, width)
{
  // Ensure the column is within range
  if (col >= this._resizeColumnData.length)
  {
    throw new Error("Column number out of range");
  }

  // Set the new width
  this._resizeColumnData[col].setWidth(width);
};


/**
 * Set the minimum width of a column.
 *
 * @param col {Integer}
 *   The column whose minimum width is to be set
 *
 * @param width {Integer}
 *   The minimum width of the specified column.
 */
qx.Proto.setMinWidth = function(col, width)
{
  // Ensure the column is within range
  if (col >= this._resizeColumnData.length)
  {
    throw new Error("Column number out of range");
  }

  // Set the new width
  this._resizeColumnData[col].setMinWidth(width);
};


/**
 * Set the maximum width of a column.
 *
 * @param col {Integer}
 *   The column whose maximum width is to be set
 *
 * @param width {Integer}
 *   The maximum width of the specified column.
 */
qx.Proto.setMaxWidth = function(col, width)
{
  // Ensure the column is within range
  if (col >= this._resizeColumnData.length)
  {
    throw new Error("Column number out of range");
  }

  // Set the new width
  this._resizeColumnData[col].setMaxWidth(width);
};


/**
 * Set any or all of the width, minimum width, and maximum width of a column
 * in a single call.
 *
 * @param map {Map}
 *   A map containing any or all of the property names "width", "minWidth",
 *   and "maxWidth".  The property values are as described for
 *   {@link #setWidth}, {@link #setMinWidth} and {@link #setMaxWidth}
 *   respectively.
 */
qx.Proto.set = function(col, map)
{
  for (var prop in map)
  {
    switch(prop)
    {
    case "width":
      this.setWidth(col, map[prop]);
      break;

    case "minWidth":
      this.setMinWidth(col, map[prop]);
      break;

    case "maxWidth":
      this.setMaxWidth(col, map[prop]);
      break;

    default:
      throw new Error("Unknown property: " + prop);
    }
  }
};


// overloaded
qx.Proto.onAppear = function(tableColumnModel, event)
{
  // Get the initial available width so we know whether a resize caused an
  // increase or decrease in the available space.
  this._width = this._getAvailableWidth(tableColumnModel);

  // Calculate column widths
  this._computeColumnsFlexWidth(tableColumnModel, event);
};


// overloaded
qx.Proto.onWindowResize = function(tableColumnModel, event)
{
  // Calculate column widths
  this._computeColumnsFlexWidth(tableColumnModel, event);
};


// overloaded
qx.Proto.onColumnWidthChanged = function(tableColumnModel, event)
{
  // Extend the next column to fill blank space
  this._extendNextColumn(tableColumnModel, event);
};


// overloaded
qx.Proto.onVisibilityChanged = function(tableColumnModel, event)
{
  // Extend the last column to fill blank space
  this._extendLastColumn(tableColumnModel, event);
};


// overloaded
qx.Proto._setNumColumns = function(numColumns)
{
  // Are there now fewer (or the same number of) columns than there were
  // previously?
  if (numColumns <= this._resizeColumnData.length)
  {
    // Yup.  Delete the extras.
    this._resizeColumnData.splice(numColumns);
    return;
  }

  // There are more columns than there were previously.  Allocate more.
  for (var i = this._resizeColumnData.length; i < numColumns; i++)
  {
    this._resizeColumnData[i] = this.getNewResizeBehaviorColumnData()();
    this._resizeColumnData[i]._columnNumber = i;
  }
};


/**
 * Computes the width of all flexible children (based loosely on the method of
 * the same name in HorizontalBoxLayoutImpl).
 *
 * @param tableColumnModel {qx.ui.table.ResizeTableColumnModel}
 *   The table column model in use.
 *
 * @param event
 *   The event object.
 */
qx.Proto._computeColumnsFlexWidth = function(tableColumnModel, event)
{
  // Semi-permanent configuration settings
  var debug = true;

  if (debug)
  {
    this.debug("computeColumnsFlexWidth");
  }

  var visibleColumns = tableColumnModel._visibleColumnArr;
  var visibleColumnsLength = visibleColumns.length;
  var columnData;
  var flexibleColumns = [ ];
  var widthUsed = 0;
  var i;

  // Determine the available width
  var width = this._getAvailableWidth(tableColumnModel);


  // *************************************************************
  // 1. Compute the sum of all static sized columns and find
  //    all flexible columns.
  // *************************************************************
  for (i = 0; i < visibleColumnsLength; i++)
  {
    // Get the current column's column data
    columnData = this._resizeColumnData[visibleColumns[i]];

    // Is this column width type "auto"?
    if (columnData._computedWidthTypeAuto)
    {
      // Yup.  Convert it to a Flex "1*"
      columnData._computedWidthTypeAuto = false;
      columnData._computedWidthTypeFlex = true;
      columnData._computedWidthParsed = 1;
    }

    // Is this column a flex width?
    if (columnData._computedWidthTypeFlex)
    {
      // Yup.  Save it for future processing.
      flexibleColumns.push(columnData);
    }
    else if (columnData._computedWidthTypePercent)
    {
      // We can calculate the width of a Percent type right now.  Convert it
      // to a Flex type that's already calculated (no further calculation
      // required).
      columnData._computedWidthPercentValue =
        Math.round(width * (columnData._computedWidthParsed / 100));
      widthUsed += columnData._computedWidthPercentValue;
    }
    else
    {
      // We have a fixed width.  Track width already allocated.
      widthUsed += columnData.getWidth();
    }
  }

  if (debug)
  {
    this.debug("Width: " + widthUsed + "/" + width);
    this.debug("Flexible Count: " + flexibleColumns.length);
  }


  // *************************************************************
  // 2. Compute the sum of all flexible column widths
  // *************************************************************
  var widthRemaining = width - widthUsed;
  var flexibleColumnsLength = flexibleColumns.length;
  var prioritySum = 0;

  for (i = 0; i < flexibleColumnsLength; i++)
  {
    prioritySum += flexibleColumns[i]._computedWidthParsed;
  }


  // *************************************************************
  // 3. Calculating the size of each 'part'.
  // *************************************************************
  var partWidth = widthRemaining / prioritySum;

  // *************************************************************
  // 4. Adjust flexible columns, taking min/max values into account
  // *************************************************************
  
  bSomethingChanged = true;
  for (flexibleColumnsLength = flexibleColumns.length;
       bSomethingChanged && flexibleColumnsLength > 0;
       flexibleColumnsLength = flexibleColumns.length)
  {
    // Assume nothing will change
    bSomethingChanged = false;

    for (i = flexibleColumnsLength - 1; i >= 0; i--)
    {
      columnData = flexibleColumns[i];

      computedFlexibleWidth =
        columnData._computedWidthFlexValue =
        columnData._computedWidthParsed * partWidth;

      // If the part is not within its specified min/max range, adjust it.
      var min = columnData.getMinWidthValue();
      var max = columnData.getMaxWidthValue();
      if (min && computedFlexibleWidth < min)
      {
        columnData._computedWidthFlexValue = Math.round(min);
        widthUsed += columnData._computedWidthFlexValue;
        qx.lang.Array.removeAt(flexibleColumns, i);
        bSomethingChanged = true;

        // Don't round fixed-width columns (in step 5)
        columnData = null;
      }
      else if (max && computedFlexibleWidth > max)
      {
        columnData._computedWidthFlexValue = Math.round(max);
        widthUsed += columnData._computedWidthFlexValue;
        qx.lang.Array.removeAt(flexibleColumns, i);
        bSomethingChanged = true;

        // Don't round fixed-width columns (in step 5)
        columnData = null;
      }
    }
  }

  // If any flexible columns remain, then allocate the remaining space to them
  if (flexibleColumns.length > 0)
  {
    // Recalculate the priority sum of the remaining flexible columns
    prioritySum = 0;
    for (i = 0; i < flexibleColumnsLength; i++)
    {
      prioritySum += flexibleColumns[i]._computedWidthParsed;
    }

    // Recalculate the width remaining and part width
    widthRemaining = width - widthUsed;
    partWidth = widthRemaining / prioritySum;

    // If there's no width remaining...
    if (widthRemaining <= 0)
    {
      // ... then use minimum width * priority for all remaining columns
      for (i = 0; i < flexibleColumnsLength; i++)
      {
        columnData = flexibleColumns[i];

        computedFlexibleWidth =
          columnData._computedWidthFlexValue =
          (qx.ui.table.DefaultResizeBehavior.MIN_WIDTH *
           flexibleColumns[i]._computedWidthParsed);
        columnData._computedWidthFlexValue = Math.round(computedFlexibleWidth);
        widthUsed += columnData._computedWidthFlexValue;
      }
    }
    else
    {
      // Assign widths of remaining flexible columns
      for (i = 0; i < flexibleColumnsLength; i++)
      {
        columnData = flexibleColumns[i];

        computedFlexibleWidth =
        columnData._computedWidthFlexValue =
        columnData._computedWidthParsed * partWidth;

        // If the computed width is less than our hard-coded minimum...
        if (computedFlexibleWidth <
            qx.ui.table.DefaultResizeBehavior.MIN_WIDTH)
        {
          // ... then use the hard-coded minimum
          computedFlexibleWidth = qx.ui.table.DefaultResizeBehavior.MIN_WIDTH;
        }

        columnData._computedWidthFlexValue = Math.round(computedFlexibleWidth);
        widthUsed += columnData._computedWidthFlexValue;
      }
    }
  }

  // *************************************************************
  // 5. Fix rounding errors
  // *************************************************************
  if (columnData != null && widthRemaining > 0)
  {
    columnData._computedWidthFlexValue += width - widthUsed;
  }

  // *************************************************************
  // 6. Set the column widths to what we have calculated
  // *************************************************************
  for (i = 0; i < visibleColumnsLength; i++)
  {
    var colWidth;

    // Get the current column's column data
    columnData = this._resizeColumnData[visibleColumns[i]];

    // Is this column a flex width?
    if (columnData._computedWidthTypeFlex)
    {
      // Yup.  Set the width to the calculated width value based on flex
      colWidth = columnData._computedWidthFlexValue;
    }
    else if (columnData._computedWidthTypePercent)
    {
      // Set the width to the calculated width value based on percent
      colWidth = columnData._computedWidthPercentValue;
    }
    else
    {
      colWidth = columnData.getWidth();
    }

    // Now that we've calculated the width, set it.
    tableColumnModel.setColumnWidth(visibleColumns[i], colWidth);

    if (debug)
    {
      this.debug("col " + columnData._columnNumber + ": width=" + colWidth);
    }
  }
};


/**
 * Extend the visible column to right of the column which just changed width,
 * to fill any available space within the inner width of the table.  This
 * means that if the sum of the widths of all columns exceeds the inner width
 * of the table, no change is made.  If, on the other hand, the sum of the
 * widths of all columns is less than the inner width of the table, the
 * visible column to the right of the column which just changed width is
 * extended to take up the width available within the inner width of the
 * table.
 *
 * @param tableColumnModel {qx.ui.table.ResizeTableColumnModel}
 *   The table column model in use.
 *
 * @param event
 *   The event object.
 */
qx.Proto._extendNextColumn = function(tableColumnModel, event)
{
  // Event data properties: col, oldWidth, newWidth
  var data = event.getData();

  var visibleColumns = tableColumnModel._visibleColumnArr;

  // Determine the available width
  var width = this._getAvailableWidth(tableColumnModel);

  // Determine the number of visible columns
  var numColumns = visibleColumns.length;

  // Did this column become longer than it was?
  if (data.newWidth > data.oldWidth)
  {
    // Yup.  Don't resize anything else.  The other columns will just get
    // pushed off and require scrollbars be added (if not already there).
    return;
  }

  // This column became shorter.  See if we no longer take up the full space
  // that's available to us.
  var i;
  var nextCol;
  var widthUsed = 0;
  for (i = 0; i < numColumns; i++)
  {
    widthUsed +=
      tableColumnModel.getColumnWidth(visibleColumns[i]);
  }

  // If the used width is less than the available width...
  if (widthUsed < width)
  {
    // ... then determine the next visible column
    for (i = 0; i < visibleColumns.length; i++)
    {
      if (visibleColumns[i] == data.col)
      {
        nextCol = visibleColumns[i + 1];
        break;
      }
    }

    if (nextCol)
    {
      // Make the next column take up the available space.
      var oldWidth = tableColumnModel.getColumnWidth(nextCol);
      var newWidth = (width - (widthUsed -
                               tableColumnModel.getColumnWidth(nextCol)));
      tableColumnModel.setColumnWidth(nextCol, newWidth);
    }
  }
};


/**
 * If a column was just made invisible, extend the last column to fill any
 * available space within the inner width of the table.  This means that if
 * the sum of the widths of all columns exceeds the inner width of the table,
 * no change is made.  If, on the other hand, the sum of the widths of all
 * columns is less than the inner width of the table, the last column is
 * extended to take up the width available within the inner width of the
 * table.
 *
 * @param tableColumnModel {qx.ui.table.ResizeTableColumnModel}
 *   The table column model in use.
 *
 * @param event
 *   The event object.
 */
qx.Proto._extendLastColumn = function(tableColumnModel, event)
{
  // Event data properties: col, visible
  var data = event.getData();

  // If the column just became visible, don't make any width changes
  if (data.visible)
  {
    return;
  }

  // Get the array of visible columns
  var visibleColumns = tableColumnModel._visibleColumnArr;

  // Determine the available width
  var width = this._getAvailableWidth(tableColumnModel);

  // Determine the number of visible columns
  var numColumns = visibleColumns.length;

  // See if we no longer take up the full space that's available to us.
  var i;
  var lastCol;
  var widthUsed = 0;
  for (i = 0; i < numColumns; i++)
  {
    widthUsed +=
      tableColumnModel.getColumnWidth(visibleColumns[i]);
  }

  // If the used width is less than the available width...
  if (widthUsed < width)
  {
    // ... then get the last visible column
    lastCol = visibleColumns[visibleColumns.length - 1];

    // Make the last column take up the available space.
    var oldWidth = tableColumnModel.getColumnWidth(lastCol);
    var newWidth = (width - (widthUsed -
                             tableColumnModel.getColumnWidth(lastCol)));
    tableColumnModel.setColumnWidth(lastCol, newWidth);
  }
};



qx.Class.MIN_WIDTH = 10;
