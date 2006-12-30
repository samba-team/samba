/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2006 by 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)

************************************************************************ */

/* ************************************************************************

#module(ui_layout)

************************************************************************ */

qx.OO.defineClass("qx.ui.layout.GridLayout", qx.ui.core.Parent,
function()
{
  qx.ui.core.Parent.call(this);

  this._columnData = [];
  this._rowData = [];

  this._spans = [];
});




/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

/*!
  The spacing between childrens. Could be any positive integer value.
*/
qx.OO.addProperty({ name : "horizontalSpacing", type : "number", defaultValue : 0, addToQueueRuntime : true, impl : "layout" });

/*!
  The spacing between childrens. Could be any positive integer value.
*/
qx.OO.addProperty({ name : "verticalSpacing", type : "number", defaultValue : 0, addToQueueRuntime : true, impl : "layout" });

/*!
  The horizontal align of the children. Allowed values are: "left", "center" and "right"
*/
qx.OO.addProperty({ name : "horizontalChildrenAlign", type : "string", defaultValue : "left", possibleValues : [ "left", "center", "right" ], addToQueueRuntime : true });

/*!
  The vertical align of the children. Allowed values are: "top", "middle" and "bottom"
*/
qx.OO.addProperty({ name : "verticalChildrenAlign", type : "string", defaultValue : "top", possibleValues : [ "top", "middle", "bottom" ], addToQueueRuntime : true });

/*!
  Cell padding top of all cells, if not locally defined
*/
qx.OO.addProperty({ name : "cellPaddingTop", type : "number" });

/*!
  Cell padding right of all cells, if not locally defined
*/
qx.OO.addProperty({ name : "cellPaddingRight", type : "number" });

/*!
  Cell padding bottom of all cells, if not locally defined
*/
qx.OO.addProperty({ name : "cellPaddingBottom", type : "number" });

/*!
  Cell padding left of all cells, if not locally defined
*/
qx.OO.addProperty({ name : "cellPaddingLeft", type : "number" });






/*
---------------------------------------------------------------------------
  INIT LAYOUT IMPL
---------------------------------------------------------------------------
*/

/*!
  This creates an new instance of the layout impl this widget uses
*/
qx.Proto._createLayoutImpl = function() {
  return new qx.renderer.layout.GridLayoutImpl(this);
}







/*
---------------------------------------------------------------------------
  CORE FUNCTIONS
---------------------------------------------------------------------------
*/

qx.Proto.add = function(vChild, vCol, vRow)
{
  vChild._col = vCol;
  vChild._row = vRow;

  if (this.isFillCell(vCol, vRow)) {
    throw new Error("Could not insert child " + vChild + " into a fill cell: " + vCol + "x" + vRow);
  }

  qx.ui.core.Parent.prototype.add.call(this, vChild);
}







/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyLayout = function(propValue, propOldValue, propData)
{
  // invalidate inner preferred dimensions
  this._invalidatePreferredInnerDimensions();

  return true;
}





/*
---------------------------------------------------------------------------
  GRID SETUP
---------------------------------------------------------------------------
*/

qx.Proto._syncDataFields = function(vData, vOldLength, vNewLength)
{
  if (vNewLength > vOldLength)
  {
    for (var i=vOldLength; i<vNewLength; i++) {
      vData[i] = {};
    }
  }
  else if (vOldLength > vNewLength)
  {
    vData.splice(vNewLength, vOldLength - vNewLength);
  }
}






/*
---------------------------------------------------------------------------
  GRID SETUP: COLUMNS
---------------------------------------------------------------------------
*/

qx.Proto._columnCount = 0;

qx.Proto.setColumnCount = function(vCount)
{
  this._columnCount = vCount;
  this._syncColumnDataFields();
}

qx.Proto.getColumnCount = function() {
  return this._columnCount;
}

qx.Proto.addColumn = function()
{
  this._columnCount++;
  this._syncColumnDataFields();
}

qx.Proto.removeColumn = function()
{
  if (this._columnCount > 0)
  {
    this._columnCount--;
    this._syncColumnDataFields();
  }
}

qx.Proto._syncColumnDataFields = function()
{
  var vData = this._columnData;
  var vOldLength = vData.length;
  var vNewLength = this._columnCount;

  this._syncDataFields(vData, vOldLength, vNewLength);
}





/*
---------------------------------------------------------------------------
  GRID SETUP: ROWS
---------------------------------------------------------------------------
*/

qx.Proto._rowCount = 0;

qx.Proto.setRowCount = function(vCount)
{
  this._rowCount = vCount;
  this._syncRowDataFields();
}

qx.Proto.getRowCount = function() {
  return this._rowCount;
}

qx.Proto.addRow = function()
{
  this._rowCount++;
  this._syncRowDataFields();
}

qx.Proto.removeRow = function()
{
  if (this._rowCount > 0)
  {
    this._rowCount--;
    this._syncRowDataFields();
  }
}

qx.Proto._syncRowDataFields = function()
{
  var vData = this._rowData;
  var vOldLength = vData.length;
  var vNewLength = this._rowCount;

  this._syncDataFields(vData, vOldLength, vNewLength);
}







/*
---------------------------------------------------------------------------
  DATA HANDLING: COLUMNS
---------------------------------------------------------------------------
*/

qx.Proto._getColumnProperty = function(vColumnIndex, vProperty)
{
  try
  {
    return this._columnData[vColumnIndex][vProperty] || null;
  }
  catch(ex)
  {
    this.error("Error while getting column property (" + vColumnIndex + "|" + vProperty + ")", ex);
    return null;
  }
}

qx.Proto._setupColumnProperty = function(vColumnIndex, vProperty, vValue)
{
  this._columnData[vColumnIndex][vProperty] = vValue;
  this._invalidateColumnLayout();
}

qx.Proto._removeColumnProperty = function(vColumnIndex, vProperty, vValue)
{
  delete this._columnData[vColumnIndex][vProperty];
  this._invalidateColumnLayout();
}

qx.Proto._invalidateColumnLayout = function()
{
  if (!this._initialLayoutDone || !this._isDisplayable) {
    return;
  }

  this.forEachVisibleChild(function() {
    this.addToQueue("width");
  });
}






/*
---------------------------------------------------------------------------
  DATA HANDLING: ROWS
---------------------------------------------------------------------------
*/

qx.Proto._getRowProperty = function(vRowIndex, vProperty)
{
  try
  {
    return this._rowData[vRowIndex][vProperty] || null;
  }
  catch(ex)
  {
    this.error("Error while getting row property (" + vRowIndex + "|" + vProperty + ")", ex);
    return null;
  }
}

qx.Proto._setupRowProperty = function(vRowIndex, vProperty, vValue)
{
  this._rowData[vRowIndex][vProperty] = vValue;
  this._invalidateRowLayout();
}

qx.Proto._removeRowProperty = function(vRowIndex, vProperty, vValue)
{
  delete this._rowData[vRowIndex][vProperty];
  this._invalidateRowLayout();
}

qx.Proto._invalidateRowLayout = function()
{
  if (!this._initialLayoutDone || !this._isDisplayable) {
    return;
  }

  this.forEachVisibleChild(function() {
    this.addToQueue("height");
  });
}






/*
---------------------------------------------------------------------------
  UTILITIES: CELL DIMENSIONS
---------------------------------------------------------------------------
*/

// SETTER

qx.Proto.setColumnWidth = function(vIndex, vValue)
{
  this._setupColumnProperty(vIndex, "widthValue", vValue);

  var vType = qx.ui.core.Parent.prototype._evalUnitsPixelPercentAutoFlex(vValue);

  this._setupColumnProperty(vIndex, "widthType", vType);

  var vParsed, vComputed;

  switch(vType)
  {
    case qx.ui.core.Widget.TYPE_PIXEL:
      vParsed = vComputed = Math.round(vValue);
      break;

    case qx.ui.core.Widget.TYPE_PERCENT:
    case qx.ui.core.Widget.TYPE_FLEX:
      vParsed = parseFloat(vValue);
      vComputed = null;
      break;

    case qx.ui.core.Widget.TYPE_AUTO:
      vParsed = vComputed = null;
      break;

    default:
      vParsed = vComputed = null;
  }

  this._setupColumnProperty(vIndex, "widthParsed", vParsed);
  this._setupColumnProperty(vIndex, "widthComputed", vComputed);
}

qx.Proto.setRowHeight = function(vIndex, vValue)
{
  this._setupRowProperty(vIndex, "heightValue", vValue);

  var vType = qx.ui.core.Widget.prototype._evalUnitsPixelPercentAutoFlex(vValue);
  this._setupRowProperty(vIndex, "heightType", vType);

  var vParsed, vComputed;

  switch(vType)
  {
    case qx.ui.core.Widget.TYPE_PIXEL:
      vParsed = vComputed = Math.round(vValue);
      break;

    case qx.ui.core.Widget.TYPE_PERCENT:
    case qx.ui.core.Widget.TYPE_FLEX:
      vParsed = parseFloat(vValue);
      vComputed = null;
      break;

    case qx.ui.core.Widget.TYPE_AUTO:
      vParsed = vComputed = null;
      break;

    default:
      vParsed = vComputed = null;
  }

  this._setupRowProperty(vIndex, "heightParsed", vParsed);
  this._setupRowProperty(vIndex, "heightComputed", vComputed);
}



// GETTER: BOX

qx.Proto.getColumnBoxWidth = function(vIndex)
{
  var vComputed = this._getColumnProperty(vIndex, "widthComputed");

  if (vComputed != null) {
    return vComputed;
  }

  var vType = this._getColumnProperty(vIndex, "widthType");
  var vParsed = this._getColumnProperty(vIndex, "widthParsed");
  var vComputed = null;

  switch(vType)
  {
    case qx.ui.core.Widget.TYPE_PIXEL:
      vComputed = Math.max(0, vParsed);
      break;

    case qx.ui.core.Widget.TYPE_PERCENT:
      vComputed = this.getInnerWidth() * Math.max(0, vParsed) * 0.01;
      break;

    case qx.ui.core.Widget.TYPE_AUTO:
      // TODO
      vComputed = null;
      break;

    case qx.ui.core.Widget.TYPE_FLEX:
      // TODO
      vComputed = null;
      break;
  }

  this._setupColumnProperty(vIndex, "widthComputed", vComputed);
  return vComputed;
}

qx.Proto.getRowBoxHeight = function(vIndex)
{
  var vComputed = this._getRowProperty(vIndex, "heightComputed");

  if (vComputed != null) {
    return vComputed;
  }

  var vType = this._getRowProperty(vIndex, "heightType");
  var vParsed = this._getRowProperty(vIndex, "heightParsed");
  var vComputed = null;

  switch(vType)
  {
    case qx.ui.core.Widget.TYPE_PIXEL:
      vComputed = Math.max(0, vParsed);
      break;

    case qx.ui.core.Widget.TYPE_PERCENT:
      vComputed = this.getInnerHeight() * Math.max(0, vParsed) * 0.01;
      break;

    case qx.ui.core.Widget.TYPE_AUTO:
      // TODO
      vComputed = null;
      break;

    case qx.ui.core.Widget.TYPE_FLEX:
      // TODO
      vComputed = null;
      break;
  }

  this._setupRowProperty(vIndex, "heightComputed", vComputed);
  return vComputed;
}


// GETTER: PADDING

qx.Proto.getComputedCellPaddingLeft = function(vCol, vRow) {
  return this.getColumnPaddingLeft(vCol) || this.getRowPaddingLeft(vRow) || this.getCellPaddingLeft() || 0;
}

qx.Proto.getComputedCellPaddingRight = function(vCol, vRow) {
  return this.getColumnPaddingRight(vCol) || this.getRowPaddingRight(vRow) || this.getCellPaddingRight() || 0;
}

qx.Proto.getComputedCellPaddingTop = function(vCol, vRow) {
  return this.getRowPaddingTop(vRow) || this.getColumnPaddingTop(vCol) || this.getCellPaddingTop() || 0;
}

qx.Proto.getComputedCellPaddingBottom = function(vCol, vRow) {
  return this.getRowPaddingBottom(vRow) || this.getColumnPaddingBottom(vCol) || this.getCellPaddingBottom() || 0;
}


// GETTER: INNER

qx.Proto.getColumnInnerWidth = function(vCol, vRow) {
  return this.getColumnBoxWidth(vCol) - this.getComputedCellPaddingLeft(vCol, vRow) - this.getComputedCellPaddingRight(vCol, vRow);
}

qx.Proto.getRowInnerHeight = function(vCol, vRow) {
  return this.getRowBoxHeight(vRow) - this.getComputedCellPaddingTop(vCol, vRow) - this.getComputedCellPaddingBottom(vCol, vRow);
}








/*
---------------------------------------------------------------------------
  UTILITIES: CELL ALIGNMENT
---------------------------------------------------------------------------
*/

// SETTER

qx.Proto.setColumnHorizontalAlignment = function(vIndex, vValue) {
  this._setupColumnProperty(vIndex, "horizontalAlignment", vValue);
}

qx.Proto.setColumnVerticalAlignment = function(vIndex, vValue) {
  this._setupColumnProperty(vIndex, "verticalAlignment", vValue);
}

qx.Proto.setRowHorizontalAlignment = function(vIndex, vValue) {
  this._setupRowProperty(vIndex, "horizontalAlignment", vValue);
}

qx.Proto.setRowVerticalAlignment = function(vIndex, vValue) {
  this._setupRowProperty(vIndex, "verticalAlignment", vValue);
}



// GETTER

qx.Proto.getColumnHorizontalAlignment = function(vIndex) {
  return this._getColumnProperty(vIndex, "horizontalAlignment");
}

qx.Proto.getColumnVerticalAlignment = function(vIndex) {
  return this._getColumnProperty(vIndex, "verticalAlignment");
}

qx.Proto.getRowHorizontalAlignment = function(vIndex) {
  return this._getRowProperty(vIndex, "horizontalAlignment");
}

qx.Proto.getRowVerticalAlignment = function(vIndex) {
  return this._getRowProperty(vIndex, "verticalAlignment");
}






/*
---------------------------------------------------------------------------
  UTILITIES: CELL PADDING
---------------------------------------------------------------------------
*/

// SETTER

qx.Proto.setColumnPaddingTop = function(vIndex, vValue) {
  this._setupColumnProperty(vIndex, "paddingTop", vValue);
}

qx.Proto.setColumnPaddingRight = function(vIndex, vValue) {
  this._setupColumnProperty(vIndex, "paddingRight", vValue);
}

qx.Proto.setColumnPaddingBottom = function(vIndex, vValue) {
  this._setupColumnProperty(vIndex, "paddingBottom", vValue);
}

qx.Proto.setColumnPaddingLeft = function(vIndex, vValue) {
  this._setupColumnProperty(vIndex, "paddingLeft", vValue);
}

qx.Proto.setRowPaddingTop = function(vIndex, vValue) {
  this._setupRowProperty(vIndex, "paddingTop", vValue);
}

qx.Proto.setRowPaddingRight = function(vIndex, vValue) {
  this._setupRowProperty(vIndex, "paddingRight", vValue);
}

qx.Proto.setRowPaddingBottom = function(vIndex, vValue) {
  this._setupRowProperty(vIndex, "paddingBottom", vValue);
}

qx.Proto.setRowPaddingLeft = function(vIndex, vValue) {
  this._setupRowProperty(vIndex, "paddingLeft", vValue);
}



// GETTER

qx.Proto.getColumnPaddingTop = function(vIndex) {
  return this._getColumnProperty(vIndex, "paddingTop");
}

qx.Proto.getColumnPaddingRight = function(vIndex) {
  return this._getColumnProperty(vIndex, "paddingRight");
}

qx.Proto.getColumnPaddingBottom = function(vIndex) {
  return this._getColumnProperty(vIndex, "paddingBottom");
}

qx.Proto.getColumnPaddingLeft = function(vIndex) {
  return this._getColumnProperty(vIndex, "paddingLeft");
}

qx.Proto.getRowPaddingTop = function(vIndex) {
  return this._getRowProperty(vIndex, "paddingTop");
}

qx.Proto.getRowPaddingRight = function(vIndex) {
  return this._getRowProperty(vIndex, "paddingRight");
}

qx.Proto.getRowPaddingBottom = function(vIndex) {
  return this._getRowProperty(vIndex, "paddingBottom");
}

qx.Proto.getRowPaddingLeft = function(vIndex) {
  return this._getRowProperty(vIndex, "paddingLeft");
}






/*
---------------------------------------------------------------------------
  DIMENSION CACHE
---------------------------------------------------------------------------
*/

qx.Proto._changeInnerWidth = function(vNew, vOld)
{
  for (var i=0, l=this.getColumnCount(); i<l; i++) {
    if (this._getColumnProperty(i, "widthType") == qx.ui.core.Widget.TYPE_PERCENT) {
      this._setupColumnProperty(i, "widthComputed", null);
    }
  }

  qx.ui.core.Parent.prototype._changeInnerWidth.call(this, vNew, vOld);
}

qx.Proto._changeInnerHeight = function(vNew, vOld)
{
  for (var i=0, l=this.getRowCount(); i<l; i++) {
    if (this._getRowProperty(i, "heightType") == qx.ui.core.Widget.TYPE_PERCENT) {
      this._setupRowProperty(i, "heightComputed", null);
    }
  }

  qx.ui.core.Parent.prototype._changeInnerHeight.call(this, vNew, vOld);
}






/*
---------------------------------------------------------------------------
  DIMENSION CACHE
---------------------------------------------------------------------------
*/

qx.Proto.getInnerWidthForChild = function(vChild) {
  return this._getColumnProperty(vChild._col, "widthComputed");
}

qx.Proto.getInnerHeightForChild = function(vChild) {
  return this._getRowProperty(vChild._row, "heightComputed");
}





/*
---------------------------------------------------------------------------
  SPAN CELLS
---------------------------------------------------------------------------
*/

qx.Proto.mergeCells = function(vStartCol, vStartRow, vColLength, vRowLength)
{
  var vSpans = this._spans;
  var vLength = vSpans.length;

  // Find end cols/rows
  var vEndCol = vStartCol + vColLength - 1;
  var vEndRow = vStartRow + vRowLength - 1;

  if (this._collidesWithSpans(vStartCol, vStartRow, vEndCol, vEndRow))
  {
    this.debug("Span collision detected!");

    // Send out warning
    return false;
  }

  // Finally store new span entry
  vSpans.push({ startCol : vStartCol, startRow : vStartRow, endCol : vEndCol, endRow : vEndRow, colLength : vColLength, rowLength : vRowLength });

  // Send out ok
  return true;
}

qx.Proto.hasSpans = function() {
  return this._spans.length > 0;
}

qx.Proto.getSpanEntry = function(vCol, vRow)
{
  for (var i=0, s=this._spans, l=s.length, c; i<l; i++)
  {
    c = s[i];

    if (vCol >= c.startCol && vCol <= c.endCol && vRow >= c.startRow && vRow <= c.endRow) {
      return c;
    }
  }

  return null;
}

qx.Proto.isSpanStart = function(vCol, vRow)
{
  for (var i=0, s=this._spans, l=s.length, c; i<l; i++)
  {
    c = s[i];

    if (c.startCol == vCol && c.startRow == vRow) {
      return true;
    }
  }

  return false;
}

qx.Proto.isSpanCell = function(vCol, vRow)
{
  for (var i=0, s=this._spans, l=s.length, c; i<l; i++)
  {
    c = s[i];

    if (vCol >= c.startCol && vCol <= c.endCol && vRow >= c.startRow && vRow <= c.endRow) {
      return true;
    }
  }

  return false;
}

qx.Proto.isFillCell = function(vCol, vRow)
{
  for (var i=0, s=this._spans, l=s.length, c; i<l; i++)
  {
    c = s[i];

    if (vCol >= c.startCol && vCol <= c.endCol && vRow >= c.startRow && vRow <= c.endRow && (vCol > c.startCol || vRow > c.startRow)) {
      return true;
    }
  }

  return false;
}

qx.Proto._collidesWithSpans = function(vStartCol, vStartRow, vEndCol, vEndRow)
{
  for (var i=0, s=this._spans, l=s.length, c; i<l; i++)
  {
    c = s[i];

    if (vEndCol >= c.startCol && vStartCol <= c.endCol && vEndRow >= c.startRow && vStartRow <= c.endRow ) {
      return true;
    }
  }

  return false;
}







/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }


  delete this._columnData;
  delete this._rowData;

  delete this._spans;

  return qx.ui.core.Parent.prototype.dispose.call(this);
}
