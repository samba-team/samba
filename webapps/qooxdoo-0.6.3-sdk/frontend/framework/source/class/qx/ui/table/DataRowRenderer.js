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
 * A cell renderer for data rows.
 */
qx.OO.defineClass("qx.ui.table.DataRowRenderer", qx.core.Object,
function() {
  qx.core.Object.call(this);
});


/**
 * Updates a data row.
 * <p>
 * The rowInfo map contains the following properties:
 * <ul>
 * <li>rowData (var): contains the row data for the row.
 *   The kind of this object depends on the table model, see
 *   {@link TableModel#getRowData()}</li>
 * <li>row (int): the model index of the row.</li>
 * <li>selected (boolean): whether a cell in this row is selected.</li>
 * <li>focusedRow (boolean): whether the focused cell is in this row.</li>
 * <li>table (qx.ui.table.Table): the table the row belongs to.</li>
 * </ul>
 *
 * @param rowInfo {Map} A map containing the information about the row to
 *    update. This map has the same structure as in {@link #createDataCell}.
 * @param cellElement {element} the DOM element that renders the data rot. This
 *    is the same element formally created by the HTML from {@link #createDataCell}.
 */
qx.Proto.updateDataRowElement = function(rowInfo, rowElement) {
  throw new Error("updateDataRowElement is abstract");
}
