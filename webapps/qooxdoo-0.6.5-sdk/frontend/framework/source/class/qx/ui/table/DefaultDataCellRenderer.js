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

// This is needed because of the instantiation at the end of this file.
// I don't think this is a good idea. (wpbasti)
#require(qx.util.format.NumberFormat)

************************************************************************ */

/**
 * The default data cell renderer.
 */
qx.OO.defineClass("qx.ui.table.DefaultDataCellRenderer", qx.ui.table.AbstractDataCellRenderer,
function() {
  qx.ui.table.AbstractDataCellRenderer.call(this);
});


/**
 * Whether the alignment should automatically be set according to the cell value.
 * If true numbers will be right-aligned.
 */
qx.OO.addProperty({ name:"useAutoAlign", type:"boolean", defaultValue:true, allowNull:false });


// overridden
qx.Proto._getCellStyle = function(cellInfo) {
  var style = qx.ui.table.AbstractDataCellRenderer.prototype._getCellStyle(cellInfo);

  var stylesToApply = this._getStyleFlags(cellInfo);
  if (stylesToApply & qx.ui.table.DefaultDataCellRenderer.STYLEFLAG_ALIGN_RIGHT){
    style += ";text-align:right";
  }
  if (stylesToApply & qx.ui.table.DefaultDataCellRenderer.STYLEFLAG_BOLD){
    style += ";font-weight:bold";
  }
  if (stylesToApply & qx.ui.table.DefaultDataCellRenderer.STYLEFLAG_ITALIC){
    style += ";font-style:italic";
  }

  return style;
}

/**
 * Determines the styles to apply to the cell
 *
 * @param cellInfo {Object} cellInfo of the cell
 * @return the sum of any of the STYLEFLAGS defined below
 */
qx.Proto._getStyleFlags = function(cellInfo) {
  if (this.getUseAutoAlign()) {
    if (typeof cellInfo.value == "number") {
      return qx.ui.table.DefaultDataCellRenderer.STYLEFLAG_ALIGN_RIGHT;
    }
  }
}


// overridden
qx.Proto._getContentHtml = function(cellInfo) {
  return qx.html.String.escape(this._formatValue(cellInfo));
}


// overridden
qx.Proto.updateDataCellElement = function(cellInfo, cellElement) {
  var clazz = qx.ui.table.DefaultDataCellRenderer;
  var style = cellElement.style;

  var stylesToApply = this._getStyleFlags(cellInfo);
  if (stylesToApply & clazz.STYLEFLAG_ALIGN_RIGHT){
    style.textAlign = "right";
  } else {
    style.textAlign = "";
  }

  if (stylesToApply & clazz.STYLEFLAG_BOLD){
    style.fontWeight = "bold";
  } else {
    style.fontWeight = "";
  }

  if (stylesToApply & clazz.STYLEFLAG_ITALIC){
    style.fontStyle = "ital";
  } else {
    style.fontStyle = "";
  }

  var textNode = cellElement.firstChild;
  if (textNode != null) {
    textNode.nodeValue = this._formatValue(cellInfo);
  } else {
    cellElement.innerHTML = qx.html.String.escape(this._formatValue(cellInfo));
  }
}


/**
 * Formats a value.
 *
 * @param cellInfo {Map} A map containing the information about the cell to
 *        create. This map has the same structure as in
 *        {@link DataCellRenderer#createDataCell}.
 * @return {String} the formatted value.
 */
qx.Proto._formatValue = function(cellInfo) {
  var value = cellInfo.value;
  if (value == null) {
    return "";
  } else if (typeof value == "number") {
    return qx.ui.table.DefaultDataCellRenderer._numberFormat.format(value);
  } else if (value instanceof Date) {
    return qx.util.format.DateFormat.getDateInstance().format(value);
  } else {
    return value;
  }
}


qx.Proto._createCellStyle_array_join = function(cellInfo, htmlArr) {
  qx.ui.table.AbstractDataCellRenderer.prototype._createCellStyle_array_join(cellInfo, htmlArr);

  var stylesToApply = this._getStyleFlags(cellInfo);
  if (stylesToApply & qx.ui.table.DefaultDataCellRenderer.STYLEFLAG_ALIGN_RIGHT){
    htmlArr.push(";text-align:right");
  }
  if (stylesToApply & qx.ui.table.DefaultDataCellRenderer.STYLEFLAG_BOLD){
    htmlArr.push(";font-weight:bold");
  }
  if (stylesToApply & qx.ui.table.DefaultDataCellRenderer.STYLEFLAG_ITALIC){
    htmlArr.push(";font-style:italic");
  }
}


qx.Proto._createContentHtml_array_join = function(cellInfo, htmlArr) {
  htmlArr.push(qx.html.String.escape(this._formatValue(cellInfo)));
}


qx.Class._numberFormat = new qx.util.format.NumberFormat();
qx.Class._numberFormat.setMaximumFractionDigits(2);

qx.Class.STYLEFLAG_ALIGN_RIGHT = 1;
qx.Class.STYLEFLAG_BOLD = 2;
qx.Class.STYLEFLAG_ITALIC = 4;



