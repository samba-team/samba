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
 * A cell renderer for header cells.
 */
qx.OO.defineClass("qx.ui.table.HeaderCellRenderer", qx.core.Object,
function() {
  qx.core.Object.call(this);
});


/**
 * Creates a header cell.
 * <p>
 * The cellInfo map contains the following properties:
 * <ul>
 * <li>col (int): the model index of the column.</li>
 * <li>xPos (int): the x position of the column in the table pane.</li>
 * <li>name (string): the name of the column.</li>
 * <li>editable (boolean): whether the column is editable.</li>
 * <li>sorted (boolean): whether the column is sorted.</li>
 * <li>sortedAscending (boolean): whether sorting is ascending.</li>
 * </ul>
 *
 * @param cellInfo {Map} A map containing the information about the cell to
 *    create.
 * @return {qx.ui.core.Widget} the widget that renders the header cell.
 */
qx.Proto.createHeaderCell = function(cellInfo) {
  throw new Error("createHeaderCell is abstract");
}


/**
 * Updates a header cell.
 *
 * @param cellInfo {Map} A map containing the information about the cell to
 *    create. This map has the same structure as in {@link #createHeaderCell}.
 * @param cellWidget {qx.ui.core.Widget} the widget that renders the header cell. This is
 *    the same widget formally created by {@link #createHeaderCell}.
 */
qx.Proto.updateHeaderCell = function(cellInfo, cellWidget) {
  throw new Error("updateHeaderCell is abstract");
}


/** The preferred height of cells created by this header renderer. */
qx.OO.addProperty({ name:"prefferedCellHeight", type:"number", defaultValue:16, allowNull:false });
