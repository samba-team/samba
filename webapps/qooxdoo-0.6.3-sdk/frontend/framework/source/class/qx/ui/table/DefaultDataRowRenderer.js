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
 * The default data row renderer.
 */
qx.OO.defineClass("qx.ui.table.DefaultDataRowRenderer", qx.ui.table.DataRowRenderer,
function() {
  qx.ui.table.DataRowRenderer.call(this);
});


/** Whether the focused row should be highlighted. */
qx.OO.addProperty({ name:"highlightFocusRow", type:"boolean", allowNull:false, defaultValue:true});

/**
 * Whether the focused row and the selection should be grayed out when the table
 * hasn't the focus.
 */
qx.OO.addProperty({ name:"visualizeFocusedState", type:"boolean", allowNull:false, defaultValue:true});


// overridden
qx.Proto.updateDataRowElement = function(rowInfo, rowElem) {
  var clazz = qx.ui.table.DefaultDataRowRenderer;

  if (rowInfo.focusedRow && this.getHighlightFocusRow()) {
    if (rowInfo.table.getFocused() || !this.getVisualizeFocusedState()) {
      rowElem.style.backgroundColor = rowInfo.selected ? clazz.BGCOL_FOCUSED_SELECTED : clazz.BGCOL_FOCUSED;
    } else {
      rowElem.style.backgroundColor = rowInfo.selected ? clazz.BGCOL_FOCUSED_SELECTED_BLUR : clazz.BGCOL_FOCUSED_BLUR;
    }
  } else {
    if (rowInfo.selected) {
      if (rowInfo.table.getFocused() || !this.getVisualizeFocusedState()) {
        rowElem.style.backgroundColor = clazz.BGCOL_SELECTED;
      } else {
        rowElem.style.backgroundColor = clazz.BGCOL_SELECTED_BLUR;
      }
    } else {
      rowElem.style.backgroundColor = (rowInfo.row % 2 == 0) ? clazz.BGCOL_EVEN : clazz.BGCOL_ODD;
    }
  }
  rowElem.style.color = rowInfo.selected ? clazz.COL_SELECTED : clazz.COL_NORMAL;
}


qx.Proto._createRowStyle_array_join = function(rowInfo, htmlArr) {
  var clazz = qx.ui.table.DefaultDataRowRenderer;

  htmlArr.push(clazz.ARRAY_JOIN_BG_COLOR);
  if (rowInfo.focusedRow && this.getHighlightFocusRow()) {
    if (rowInfo.table.getFocused() || !this.getVisualizeFocusedState()) {
      htmlArr.push(rowInfo.selected ? clazz.BGCOL_FOCUSED_SELECTED : clazz.BGCOL_FOCUSED);
    } else {
      htmlArr.push(rowInfo.selected ? clazz.BGCOL_FOCUSED_SELECTED_BLUR : clazz.BGCOL_FOCUSED_BLUR);
    }
  } else {
    if (rowInfo.selected) {
      if (rowInfo.table.getFocused() || !this.getVisualizeFocusedState()) {
        htmlArr.push(clazz.BGCOL_SELECTED);
      } else {
        htmlArr.push(clazz.BGCOL_SELECTED_BLUR);
      }
    } else {
      htmlArr.push((rowInfo.row % 2 == 0) ? clazz.BGCOL_EVEN : clazz.BGCOL_ODD);
    }
  }
  htmlArr.push(clazz.ARRAY_JOIN_COLOR);
  htmlArr.push(rowInfo.selected ? clazz.COL_SELECTED : clazz.COL);
}


qx.Class.BGCOL_FOCUSED_SELECTED = "#5a8ad3";
qx.Class.BGCOL_FOCUSED_SELECTED_BLUR = "#b3bac6";
qx.Class.BGCOL_FOCUSED = "#ddeeff";
qx.Class.BGCOL_FOCUSED_BLUR = "#dae0e7";
qx.Class.BGCOL_SELECTED = "#335ea8";
qx.Class.BGCOL_SELECTED_BLUR = "#989ea8";
qx.Class.BGCOL_EVEN = "#faf8f3";
qx.Class.BGCOL_ODD = "white";
qx.Class.COL_SELECTED = "white";
qx.Class.COL_NORMAL = "black";

qx.Class.ARRAY_JOIN_BG_COLOR = ";background-color:";
qx.Class.ARRAY_JOIN_COLOR = ';color:';
