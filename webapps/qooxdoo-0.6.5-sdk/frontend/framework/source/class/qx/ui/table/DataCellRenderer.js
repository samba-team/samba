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
 * A cell renderer for data cells.
 */
qx.OO.defineClass("qx.ui.table.DataCellRenderer", qx.core.Object,
function() {
  qx.core.Object.call(this);
});


/**
 * Creates the HTML for a data cell.
 * <p>
 * The cellInfo map contains the following properties:
 * <ul>
 * <li>value (var): the cell's value.</li>
 * <li>rowData (var): contains the row data for the row, the cell belongs to.
 *   The kind of this object depends on the table model, see
 *   {@link TableModel#getRowData()}</li>
 * <li>row (int): the model index of the row the cell belongs to.</li>
 * <li>col (int): the model index of the column the cell belongs to.</li>
 * <li>table (qx.ui.table.Table): the table the cell belongs to.</li>
 * <li>xPos (int): the x position of the cell in the table pane.</li>
 * <li>selected (boolean): whether the cell is selected.</li>
 * <li>focusedCol (boolean): whether the cell is in the same column as the
 *   focused cell.</li>
 * <li>focusedRow (boolean): whether the cell is in the same row as the
 *   focused cell.</li>
 * <li>editable (boolean): whether the cell is editable.</li>
 * <li>style (string): The CSS styles that should be applied to the outer HTML
 *   element.</li>
 * </ul>
 *
 * @param cellInfo {Map} A map containing the information about the cell to
 *    create.
 * @return {String} the HTML of the data cell.
 */
qx.Proto.createDataCellHtml = function(cellInfo) {
  throw new Error("createDataCellHtml is abstract");
}


/**
 * Updates the content of the pane.
 *
 * @param completeUpdate {Boolean ? false} if true a complete update is performed.
 *    On a complete update all cell widgets are recreated.
 * @param onlyRow {Integer ? null} if set only the specified row will be updated.
 * @param onlySelectionOrFocusChanged {Boolean ? false} if true, cell values won't
 *        be updated. Only the row background will.
 */
qx.Proto.updateDataCellElement = function(cellInfo, cellElement) {
  throw new Error("updateDataCellElement is abstract");
}


/**
 * Updates the content of the pane using array joins.
 *
 * @param completeUpdate {Boolean ? false} if true a complete update is performed.
 *    On a complete update all cell widgets are recreated.
 * @param onlyRow {Integer ? null} if set only the specified row will be updated.
 * @param onlySelectionOrFocusChanged {Boolean ? false} if true, cell values won't
 *        be updated. Only the row background will.
 */
qx.Proto.createDataCellHtml_array_join = function(cellInfo, htmlArr) {
  throw new Error("createDataCellHtml_array_join is abstract");
}
