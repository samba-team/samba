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
 * A cell editor factory creating text fields.
 */
qx.OO.defineClass("qx.ui.table.TextFieldCellEditorFactory", qx.ui.table.CellEditorFactory,
function() {
  qx.ui.table.CellEditorFactory.call(this);
});


// overridden
qx.Proto.createCellEditor = function(cellInfo) {
  var cellEditor = new qx.ui.form.TextField;
  cellEditor.setAppearance("table-editor-textfield");
  cellEditor.originalValue = cellInfo.value;
  cellEditor.setValue("" + cellInfo.value);

  cellEditor.addEventListener("appear", function() {
    this.selectAll();
  });

  return cellEditor;
}


// overridden
qx.Proto.getCellEditorValue = function(cellEditor) {
  // Workaround: qx.ui.form.TextField.getValue() delivers the old value, so we use the
  //             value property of the DOM element directly
  var value = cellEditor.getElement().value;

  if (typeof cellEditor.originalValue == "number") {
    value = parseFloat(value);
  }
  return value;
}
