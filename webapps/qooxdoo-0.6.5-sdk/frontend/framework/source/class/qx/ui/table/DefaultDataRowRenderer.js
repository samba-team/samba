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

************************************************************************ */

/**
 * The default data row renderer.
 */
qx.OO.defineClass("qx.ui.table.DefaultDataRowRenderer", qx.ui.table.DataRowRenderer,
function() {
  qx.ui.table.DataRowRenderer.call(this);

  var Ddrr = qx.ui.table.DefaultDataRowRenderer;

  // Initialize to the default colors.
  this._colors =
    {
      bgcolFocusedSelected     : Ddrr.BGCOL_FOCUSED_SELECTED,
      bgcolFocusedSelectedBlur : Ddrr.BGCOL_FOCUSED_SELECTED_BLUR,
      bgcolFocused             : Ddrr.BGCOL_FOCUSED,
      bgcolFocusedBlur         : Ddrr.BGCOL_FOCUSED_BLUR,
      bgcolSelected            : Ddrr.BGCOL_SELECTED,
      bgcolSelectedBlur        : Ddrr.BGCOL_SELECTED_BLUR,
      bgcolEven                : Ddrr.BGCOL_EVEN,
      bgcolOdd                 : Ddrr.BGCOL_ODD,
      colSelected              : Ddrr.COL_SELECTED,
      colNormal                : Ddrr.COL_NORMAL
    };

});


/** Whether the focused row should be highlighted. */
qx.OO.addProperty({ name:"highlightFocusRow", type:"boolean", allowNull:false, defaultValue:true});

/**
 * Whether the focused row and the selection should be grayed out when the
 * table hasn't the focus.
 */
qx.OO.addProperty({ name:"visualizeFocusedState", type:"boolean", allowNull:false, defaultValue:true});

/** The font family used for the data row */
qx.OO.addProperty({ name:"fontFamily", type:"string", allowNull:false, defaultValue:"'Segoe UI', Corbel, Calibri, Tahoma, 'Lucida Sans Unicode', sans-serif" });

/** The font size used for the data row */
qx.OO.addProperty({ name:"fontSize", type:"string", allowNull:false, defaultValue:"11px" });


// overridden
qx.Proto.updateDataRowElement = function(rowInfo, rowElem) {
  rowElem.style.fontFamily = this.getFontFamily();
  rowElem.style.fontSize   = this.getFontSize();

  if (rowInfo.focusedRow && this.getHighlightFocusRow()) {
    if (rowInfo.table.getFocused() || !this.getVisualizeFocusedState()) {
      rowElem.style.backgroundColor = rowInfo.selected ? this._colors.bgcolFocusedSelected : this._colors.bgcolFocused;
    } else {
      rowElem.style.backgroundColor = rowInfo.selected ? this._colors.bgcolFocusedSelectedBlur : this._colors.bgcolFocusedBlur;
    }
  } else {
    if (rowInfo.selected) {
      if (rowInfo.table.getFocused() || !this.getVisualizeFocusedState()) {
        rowElem.style.backgroundColor = this._colors.bgcolSelected;
      } else {
        rowElem.style.backgroundColor = this._colors.bgcolSelectedBlur;
      }
    } else {
      rowElem.style.backgroundColor = (rowInfo.row % 2 == 0) ? this._colors.bgcolEven : this._colors.bgcolOdd;
    }
  }
  rowElem.style.color = rowInfo.selected ? this._colors.colSelected : this._colors.colNormal;
};


// Array join test
qx.Proto._createRowStyle_array_join = function(rowInfo, htmlArr) {
  htmlArr.push(";font-family:");
  htmlArr.push(this.getFontFamily());
  htmlArr.push(";font-size:");
  htmlArr.push(this.getFontSize());

  htmlArr.push(";background-color:");
  if (rowInfo.focusedRow && this.getHighlightFocusRow()) {
    if (rowInfo.table.getFocused() || !this.getVisualizeFocusedState()) {
      htmlArr.push(rowInfo.selected ? this._colors.bgcolFocusedSelected : this._colors.bgcolFocused);
    } else {
      htmlArr.push(rowInfo.selected ? this._colors.bgcolFocusedSelectedBlur : this._colors.bgcolFocusedBlur);
    }
  } else {
    if (rowInfo.selected) {
      if (rowInfo.table.getFocused() || !this.getVisualizeFocusedState()) {
        htmlArr.push(this._colors.bgcolSelected);
      } else {
        htmlArr.push(this._colors.bgcolSelectedBlur);
      }
    } else {
      htmlArr.push((rowInfo.row % 2 == 0) ? this._colors.bgcolEven : this._colors.bgcolOdd);
    }
  }
  htmlArr.push(';color:');
  htmlArr.push(rowInfo.selected ? this._colors.colSelected : this._colors.colNormal);
};


/**
 * Allow setting the table row colors.
 *
 * @param colors {Map}
 *    The value of each property in the map is a string containing either a
 *    number (e.g. "#518ad3") or color name ("white") representing the color
 *    for that type of display.  The map may contain any or all of the
 *    following properties:
 *    <ul>
 *      <li>bgcolFocusedSelected</li>
 *      <li>bgcolFocusedSelectedBlur</li>
 *      <li>bgcolFocused</li>
 *      <li>bgcolFocusedBlur</li>
 *      <li>bgcolSelected</li>
 *      <li>bgcolSelectedBlur</li>
 *      <li>bgcolEven</li>
 *      <li>bgcolOdd</li>
 *      <li>colSelected</li>
 *      <li>colNormal</li>
 *    </ul>
 */
qx.Proto.setRowColors = function(colors)
{
  for (var color in colors)
  {
    this._colors[color] = colors[color];
  }
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
