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
 * An abstract data cell renderer that does the basic coloring
 * (borders, selected look, ...).
 */
qx.OO.defineClass("qx.ui.table.AbstractDataCellRenderer", qx.ui.table.DataCellRenderer,
function() {
  qx.ui.table.DataCellRenderer.call(this);
});


// overridden
qx.Proto.createDataCellHtml = function(cellInfo) {
  var AbstractDataCellRenderer = qx.ui.table.AbstractDataCellRenderer;
  return AbstractDataCellRenderer.MAIN_DIV_START + this._getCellStyle(cellInfo)
    + AbstractDataCellRenderer.MAIN_DIV_START_END
    + this._getContentHtml(cellInfo) + AbstractDataCellRenderer.MAIN_DIV_END;
}


// overridden
qx.Proto.updateDataCellElement = function(cellInfo, cellElement) {
  cellElement.innerHTML = this._getContentHtml(cellInfo);
}


/**
 * Returns the CSS styles that should be applied to the main div of this cell.
 *
 * @param cellInfo {Map} The information about the cell.
 *        See {@link #createDataCellHtml}.
 * @return the CSS styles of the main div.
 */
qx.Proto._getCellStyle = function(cellInfo) {
  return cellInfo.style + qx.ui.table.AbstractDataCellRenderer.MAIN_DIV_STYLE;
}


/**
 * Returns the HTML that should be used inside the main div of this cell.
 *
 * @param cellInfo {Map} The information about the cell.
 *        See {@link #createDataCellHtml}.
 * @return {string} the inner HTML of the main div.
 */
qx.Proto._getContentHtml = function(cellInfo) {
  return cellInfo.value;
}


qx.Proto.createDataCellHtml_array_join = function(cellInfo, htmlArr) {
  var AbstractDataCellRenderer = qx.ui.table.AbstractDataCellRenderer;

  if (qx.ui.table.TablePane.USE_TABLE) {
    htmlArr.push(AbstractDataCellRenderer.TABLE_TD);
    htmlArr.push(cellInfo.styleHeight);
    htmlArr.push("px");
  } else {
    htmlArr.push(AbstractDataCellRenderer.ARRAY_JOIN_MAIN_DIV_LEFT);
    htmlArr.push(cellInfo.styleLeft);
    htmlArr.push(AbstractDataCellRenderer.ARRAY_JOIN_MAIN_DIV_WIDTH);
    htmlArr.push(cellInfo.styleWidth);
    htmlArr.push(AbstractDataCellRenderer.ARRAY_JOIN_MAIN_DIV_HEIGHT);
    htmlArr.push(cellInfo.styleHeight);
    htmlArr.push("px");
  }

  this._createCellStyle_array_join(cellInfo, htmlArr);

  htmlArr.push(AbstractDataCellRenderer.ARRAY_JOIN_MAIN_DIV_START_END);

  this._createContentHtml_array_join(cellInfo, htmlArr);

  if (qx.ui.table.TablePane.USE_TABLE) {
    htmlArr.push(AbstractDataCellRenderer.TABLE_TD_END);
  } else {
    htmlArr.push(AbstractDataCellRenderer.ARRAY_JOIN_MAIN_DIV_END);
  }
}


qx.Proto._createCellStyle_array_join = function(cellInfo, htmlArr) {
  htmlArr.push(qx.ui.table.AbstractDataCellRenderer.MAIN_DIV_STYLE);
}


qx.Proto._createContentHtml_array_join = function(cellInfo, htmlArr) {
  htmlArr.push(cellInfo.value);
}


qx.Class.MAIN_DIV_START = '<div style="';
qx.Class.MAIN_DIV_START_END = '">';
qx.Class.MAIN_DIV_END = '</div>';
qx.Class.MAIN_DIV_STYLE = ';overflow:hidden;white-space:nowrap;border-right:1px solid #eeeeee;border-bottom:1px solid #eeeeee;padding-left:2px;padding-right:2px;cursor:default'
  + (qx.sys.Client.getInstance().isMshtml() ? '' : ';-moz-user-select:none;');

qx.Class.ARRAY_JOIN_MAIN_DIV_LEFT = '<div style="position:absolute;left:';
qx.Class.ARRAY_JOIN_MAIN_DIV_WIDTH = 'px;top:0px;width:';
qx.Class.ARRAY_JOIN_MAIN_DIV_HEIGHT = 'px;height:';
qx.Class.ARRAY_JOIN_MAIN_DIV_START_END = '">';
qx.Class.ARRAY_JOIN_MAIN_DIV_END = '</div>';

qx.Class.TABLE_TD = '<td style="height:';
qx.Class.TABLE_TD_END = '</td>';